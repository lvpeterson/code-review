"""Tests for checks/dnl/rules_config.py: web.config rules with transform-aware severity."""
from pathlib import Path

import pytest

from checks.dnl.rules_config import check_configs
from checks.dnl.webconfig import load_configs

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy" / "config_variants"


@pytest.fixture(scope="module")
def cfgs():
    return load_configs(FX)


@pytest.fixture(scope="module")
def findings(cfgs):
    return check_configs(cfgs, set(), set())[0]


def hits(findings, cid, handler=None):
    return [f for f in findings if f.check_id == cid
            and (handler is None or (f.route and f.route.handler_name == handler))]


def one(findings, cid, handler=None):
    h = hits(findings, cid, handler)
    assert len(h) == 1, [(f.file, f.line, f.severity) for f in h]
    return h[0]


def test_debug_removed_in_release_is_info(findings):
    f = one(findings, "DNL-CFG-001")
    assert f.severity == "info" and "Removed by the Web.Release.config" in f.description


def test_connection_string_password(findings):
    # Main's password is overridden by the Release transform (R4) but is still committed in
    # the base config, so it keeps its severity and says so; Reporting is untransformed.
    # The $(DbPassword) one never fires.
    hs = hits(findings, "DNL-SEC-001")
    assert sorted(f.severity for f in hs) == ["high", "high"]
    main = next(f for f in hs if f.line == 13)
    assert "Overridden by the Web.Release.config transform(s), but the value is still committed" in main.description
    f = next(f for f in hs if f.line == 15)
    assert f.file == "Site/Web.config" and "Overridden" not in f.description
    assert not any(f.line == 16 for f in hs)


def test_introduced_by_transform(findings):
    f = one(findings, "DNL-CFG-002")
    assert f.file == "Site/Web.Debug.config" and "Introduced by Web.Debug.config" in f.description


def test_views_config_ignored(findings):
    assert not [f for f in findings if "Views" in f.file]


def test_elmah_handler_low_when_location_denies(findings):
    assert one(findings, "DNL-INV-001").severity == "low"


def test_api_surface_tag(cfgs):
    fs, _ = check_configs(cfgs, api_surface_dirs={FX / "Site"}, has_aspx_dirs=set())
    f = next(f for f in hits(fs, "DNL-SEC-001") if f.severity == "high")
    assert f.owasp["api2023"].startswith("API2:2023")


def test_malformed_note(cfgs):
    _, notes = check_configs(cfgs, set(), set())
    assert any("Broken/Web.config: could not parse" in n for n in notes)


def test_validate_request_needs_aspx_dir(cfgs):
    base = check_configs(cfgs, set(), set())[0]
    assert [f.line for f in hits(base, "DNL-XSS-002") if f.file == "Rules/Web.config"] == [15]
    fs, _ = check_configs(cfgs, set(), {FX / "Rules"})
    lines = sorted(f.line for f in hits(fs, "DNL-XSS-002"))
    assert lines == [15, 16]


def test_severity_variants(findings):
    assert one([f for f in findings if f.file == "Rules/Web.config"], "DNL-CFG-003").severity == "high"
    sev = {f.severity for f in hits(findings, "DNL-SESS-005")}
    assert sev == {"high", "medium"}


def test_placeholders_and_safe_values(findings):
    assert [f.line for f in hits(findings, "DNL-SEC-002")] == [4]
    h = hits(findings, "DNL-CFG-006")
    f = next(f for f in h if f.file == "Rules/Web.config")
    assert "Strict-Transport-Security" in f.description and "X-Frame-Options" not in f.description


def test_transform_notes_surfaced(tmp_path):
    (tmp_path / "Web.config").write_text("<configuration><system.web><compilation debug='true'/></system.web></configuration>")
    (tmp_path / "Web.Debug.config").write_text("<configuration><a></configuration>")
    (tmp_path / "Web.Staging.config").write_text(
        '<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform">'
        '<system.web xdt:Transform="Merge"/></configuration>')
    fs, notes = check_configs(load_configs(tmp_path), set(), set())
    assert "Web.config: transform skipped (Web.Debug.config: mismatched tag: line 1, column 20)" in notes
    assert any("Merge unsupported" in n for n in notes)
    f = one(fs, "DNL-CFG-001")
    assert f.severity == "medium"   # no transform removes it


def test_debug_only_removal_stays_at_severity(tmp_path):
    (tmp_path / "Web.config").write_text("<configuration><system.web><compilation debug='true'/></system.web></configuration>")
    (tmp_path / "Web.Debug.config").write_text(
        '<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform"><system.web>'
        '<compilation xdt:Transform="RemoveAttributes(debug)"/></system.web></configuration>')
    fs, _ = check_configs(load_configs(tmp_path), set(), set())
    assert one(fs, "DNL-CFG-001").severity == "medium"


def test_each_rule_fires_once(findings):
    ids = {f.check_id for f in findings}
    assert ids >= {"DNL-CFG-001", "DNL-CFG-002", "DNL-CFG-003", "DNL-CFG-004", "DNL-CFG-005", "DNL-CFG-006",
                   "DNL-CFG-007", "DNL-XSS-002", "DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-003", "DNL-SESS-004",
                   "DNL-SESS-005", "DNL-INT-001", "DNL-INT-002", "DNL-SEC-001", "DNL-SEC-002", "DNL-INV-001", "DNL-RES-001"}


# -- R15: app-root-only rules -------------------------------------------------

_ROOT_ONLY = {"DNL-CFG-005", "DNL-CFG-006", "DNL-SESS-002"}


def test_subfolder_auth_only_config_gets_no_root_rules(findings):
    # Fallback (no project dirs): Site/Admin sits under Site, so it is not an app root.
    assert not [f for f in findings if f.check_id in _ROOT_ONLY and f.file == "Site/Admin/Web.config"]
    assert {f.check_id for f in findings if f.file == "Site/Web.config"} >= _ROOT_ONLY


def test_root_rules_follow_project_dirs(cfgs):
    fs, _ = check_configs(cfgs, set(), set(), project_dirs={FX / "Site"})
    got = {f.file for f in fs if f.check_id in _ROOT_ONLY}
    # Site is the project root; Rules/Admin/Bom are outside every project and
    # shallowest in their own tree, so they still count; Site/Admin never does.
    assert "Site/Web.config" in got and "Site/Admin/Web.config" not in got


def test_root_rules_not_on_nested_dir_of_project(tmp_path):
    (tmp_path / "Sub").mkdir()
    (tmp_path / "Web.config").write_text("<configuration><system.web/></configuration>")
    (tmp_path / "Sub" / "Web.config").write_text("<configuration><system.web><authorization>"
                                                 "<deny users='?'/></authorization></system.web></configuration>")
    fs, _ = check_configs(load_configs(tmp_path), set(), set(), project_dirs={tmp_path})
    assert {f.file for f in fs if f.check_id in _ROOT_ONLY} == {"Web.config"}


# -- R16: secret-looking keys that are really settings --------------------------

def test_sec_002_skips_setting_like_keys(tmp_path):
    (tmp_path / "Web.config").write_text(
        "<configuration><appSettings>"
        "<add key='PasswordResetUrl' value='https://example.test/reset' />"
        "<add key='PasswordRegex' value='^.{8,}$' />"
        "<add key='TokenExpirationMinutes' value='3000' />"
        "<add key='PasswordMinimumLength' value='12345' />"
        "<add key='ApiKey' value='sk_live_abcdef' />"
        "</appSettings></configuration>")
    fs, _ = check_configs(load_configs(tmp_path), set(), set())
    assert [f.description for f in fs if f.check_id == "DNL-SEC-002"] == [
        'appSettings key "ApiKey" holds a hard-coded secret value.']


# -- final review fixes -------------------------------------------------------

def test_committed_secret_overridden_by_transform_keeps_severity(tmp_path):
    (tmp_path / "Web.config").write_text(
        "<configuration><appSettings><add key='ApiKey' value='sk_live_abcdef'/></appSettings>"
        "<connectionStrings><add name='Db' connectionString='Server=s;User Id=u;Password=Hunter2x'/>"
        "</connectionStrings></configuration>")
    (tmp_path / "Web.Release.config").write_text(
        '<configuration xmlns:xdt="http://schemas.microsoft.com/XML-Document-Transform">'
        '<appSettings><add key="ApiKey" xdt:Transform="Remove" xdt:Locator="Match(key)"/></appSettings>'
        '<connectionStrings><add name="Db" connectionString="Server=s;Integrated Security=SSPI" '
        'xdt:Transform="SetAttributes" xdt:Locator="Match(name)"/></connectionStrings></configuration>')
    fs, _ = check_configs(load_configs(tmp_path), set(), set())
    for cid, sev in (("DNL-SEC-001", "high"), ("DNL-SEC-002", "medium")):
        f = one(fs, cid)
        assert f.severity == sev
        assert f.description.endswith(
            " Overridden by the Web.Release.config transform(s), but the value is still committed in the base Web.config.")


def test_connection_string_placeholder_is_one_token_only(tmp_path):
    cs = [("Braced", "Server=s;Password={Secr3t;x};"), ("Token", "Server=s;Password={DbPassword}"),
          ("Plain", "Server=s;Password=changeme"), ("Octopus", "Server=s;Password=#{Db.Password}")]
    items = "\n".join(f'<add name="{n}" connectionString="{c}"/>' for n, c in cs)
    (tmp_path / "Web.config").write_text(f"<configuration><connectionStrings>{items}</connectionStrings></configuration>")
    fs, _ = check_configs(load_configs(tmp_path), set(), set())
    assert sorted(f.description for f in hits(fs, "DNL-SEC-001")) == [
        'Connection string "Braced" embeds a database password.',
        'Connection string "Plain" embeds a database password.']


def test_sec_002_setting_key_words_not_substrings(tmp_path):
    (tmp_path / "Web.config").write_text(
        "<configuration><appSettings>"
        "<add key='InformationApiKey' value='sk_live_abcdef' />"
        "<add key='PasswordResetUrl' value='https://example.test/reset' />"
        "<add key='Password_Format' value='Hashed' />"
        "<add key='PasswordRegex' value='^.{8,}$' />"
        "</appSettings></configuration>")
    fs, _ = check_configs(load_configs(tmp_path), set(), set())
    assert [f.description for f in hits(fs, "DNL-SEC-002")] == [
        'appSettings key "InformationApiKey" holds a hard-coded secret value.']
