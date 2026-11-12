"""Tests for checks/dnl/webconfig.py: line-tracked parsing, XDT transforms,
and anonymous-access evaluation over a config chain."""
from pathlib import Path

import pytest

from checks.dnl.webconfig import (
    LINE, ORIGIN, anonymous_denied, apply_transform, config_chain, effective,
    load_configs, parse_xml_with_lines,
)

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy" / "config_variants"


@pytest.fixture(scope="module")
def cfgs():
    return load_configs(FX)


def cfg(cfgs, rel):
    return next(c for c in cfgs if c.rel == rel)


def test_lines_and_bom(cfgs):
    site = cfg(cfgs, "Site/Web.config")
    comp = site.root.find("system.web/compilation")
    assert comp.get(LINE) == "4" and comp.get(ORIGIN) == "Site/Web.config"
    bom = cfg(cfgs, "Bom/Web.config")
    assert bom.error is None and bom.root.find("appSettings/add").get(LINE) == "4"


def test_malformed_is_reported_not_raised(cfgs):
    assert cfg(cfgs, "Broken/Web.config").root is None and cfg(cfgs, "Broken/Web.config").error


def test_views_flag_and_transform_pairing(cfgs):
    assert cfg(cfgs, "Views/Web.config").is_views and not cfg(cfgs, "Site/Web.config").is_views
    assert set(cfg(cfgs, "Site/Web.config").transforms) == {"Release", "Debug"}
    assert not [c for c in cfgs if c.rel.lower().endswith("release.config")]


def test_release_transform_removes_debug(cfgs):
    eff = dict(effective(cfg(cfgs, "Site/Web.config")))
    assert eff["base"].find("system.web/compilation").get("debug") == "true"
    assert eff["Release"].find("system.web/compilation").get("debug") is None


def test_match_locator_set_attributes(cfgs):
    eff = dict(effective(cfg(cfgs, "Site/Web.config")))
    add = [a for a in eff["Release"].iter("add") if a.get("name") == "Main"][0]
    assert "Server=prod" in add.get("connectionString") and add.get(ORIGIN) == "Site/Web.Release.config"
    audit = [a for a in eff["Release"].iter("add") if a.get("name") == "Audit"][0]
    assert "Server=dev" in audit.get("connectionString")
    # base is untouched by the deep copy
    base_add = [a for a in eff["base"].iter("add") if a.get("name") == "Main"][0]
    assert "Password" in base_add.get("connectionString")


def test_insert_if_missing_strips_xdt(cfgs):
    eff = dict(effective(cfg(cfgs, "Site/Web.config")))
    ce = eff["Debug"].find("system.web/customErrors")
    assert ce.get("mode") == "Off" and ce.get(ORIGIN) == "Site/Web.Debug.config"
    assert not any("XML-Document-Transform" in k for k in ce.attrib)


def test_replace_insert_remove():
    base = parse_xml_with_lines('<configuration><a><x name="1" v="a"/><x name="2" v="b"/></a></configuration>', "b")
    ns = 'xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform"'
    t = parse_xml_with_lines(
        f'<configuration {ns}><a>'
        '<x name="1" v="z" xdt:Transform="Replace" xdt:Locator="Match(name)"/>'
        '<x name="2" xdt:Transform="Remove" xdt:Locator="Match(name)"/>'
        '<x name="3" xdt:Transform="Insert"/>'
        '</a></configuration>', "t")
    out = apply_transform(base, t)
    xs = out.findall("a/x")
    assert [(x.get("name"), x.get("v")) for x in xs] == [("1", "z"), ("3", None)]
    assert all(x.get(ORIGIN) == "t" for x in xs)
    assert not any("XML-Document-Transform" in k for x in xs for k in x.attrib)


def test_unsupported_locator_is_noted():
    base = parse_xml_with_lines('<configuration><a><x v="1"/></a></configuration>', "b")
    ns = 'xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform"'
    t = parse_xml_with_lines(
        f'<configuration {ns}><a><x v="2" xdt:Transform="SetAttributes" xdt:Locator="XPath(//x)"/></a></configuration>', "t")
    out = apply_transform(base, t)
    assert out.find("a/x").get("v") == "2"
    assert "approximated" in out.get("{dnl}notes")


def test_anonymous_denied_location_and_nested(cfgs):
    chain = config_chain(cfgs, FX / "Site", FX / "Site" / "Admin")
    assert anonymous_denied(chain, "/Admin/Users.aspx")[0] is True
    assert anonymous_denied(chain[:1], "/Public/Home.aspx")[0] is False
    assert anonymous_denied(chain[:1], "/Reports/x.aspx")[0] is True   # <location path="Reports"><deny users="?"/>


def test_role_only_rules_do_not_match_anonymous():
    root = parse_xml_with_lines('<configuration><system.web><authorization><allow roles="A"/><deny users="bob"/></authorization></system.web></configuration>', "w")
    assert anonymous_denied([root], "/x") == (False, None)


def test_allow_star_before_deny_means_public():
    root = parse_xml_with_lines('<configuration><system.web><authorization><allow users="*"/><deny users="?"/></authorization></system.web></configuration>', "w")
    assert anonymous_denied([root], "/x")[0] is False


def test_malformed_raises_value_error():
    with pytest.raises(ValueError):
        parse_xml_with_lines("<a><b></a>", "x")


def test_nested_location_is_rebased(cfgs):
    chain = config_chain(cfgs, FX / "Site", FX / "Site" / "Admin")
    # Admin/Web.config <location path="Reports"> allows *: only /Admin/Reports
    rule = anonymous_denied(chain, "/Admin/Reports/x.aspx")
    assert rule[0] is False and rule[1].tag == "allow"
    # top-level Reports deny still applies to /Reports, unaffected by Admin's
    assert anonymous_denied(chain, "/Reports/x.aspx")[0] is True
    # a config does not apply to URLs outside its directory
    assert anonymous_denied(chain, "/Public/a.aspx")[0] is False


def test_verbs_rule_does_not_decide():
    root = parse_xml_with_lines('<configuration><system.web><authorization><deny verbs="POST" users="*"/></authorization></system.web></configuration>', "w")
    assert anonymous_denied([root], "/x") == (False, None)


def test_default_namespace_stripped():
    root = parse_xml_with_lines('<configuration xmlns="http://schemas.microsoft.com/.NetConfiguration/v2.0"><system.web><authorization><deny users="?"/></authorization></system.web></configuration>', "w")
    assert root.find("system.web/authorization") is not None
    assert anonymous_denied([root], "/x")[0] is True


def test_unknown_verb_noted_and_effective_cached(cfgs):
    base = parse_xml_with_lines('<configuration><a/></configuration>', "b")
    t = parse_xml_with_lines('<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform"><a xdt:Transform="Merge"/></configuration>', "t")
    assert "Merge unsupported" in apply_transform(base, t).get("{dnl}notes")
    c = cfg(cfgs, "Site/Web.config")
    assert effective(c)[1][1] is effective(c)[1][1]


def test_malformed_transform_recorded(tmp_path):
    (tmp_path / "Web.config").write_text("<configuration/>")
    (tmp_path / "Web.Release.config").write_text("<configuration><a></configuration>")
    c = load_configs(tmp_path)[0]
    assert c.transforms == {} and c.transform_errors
