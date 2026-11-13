"""Integrity markup rules (DNL-INT-003/004) and session / auth code rules (DNL-SESS-006..008)."""
from pathlib import Path

import pytest

from checks.dnl import project, routes, rules_integrity, rules_session
from core.registry import get_analyzer
import languages.dotnet_legacy.analyzers  # noqa: F401  (registration)

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "taint_app", False)


@pytest.fixture(scope="module")
def refs(model):
    return routes.discover_mvc_webapi(model) + routes.discover_webforms(model) + routes.discover_wcf(model)


def text_at(model, f):
    return (model.root / f.file).read_text().splitlines()[f.line - 1]


def pick(findings, rule, file_endswith=None):
    out = [f for f in findings if f.check_id == rule]
    return [f for f in out if f.file.endswith(file_endswith)] if file_endswith else out


# -- INT-003 --------------------------------------------------------------------

def test_sri_layout_flags_only_external_without_integrity(model, refs):
    got = pick(rules_integrity.check(model, refs), "DNL-INT-003", "_Layout.cshtml")
    lines = sorted(text_at(model, f).strip() for f in got)
    assert lines == ['<SCRIPT SRC=http://cdn.example.net/unquoted.js></SCRIPT>',
                     '<link rel="stylesheet" href="//fonts.example.net/css?family=Sans">',
                     '<script src="https://cdn.example.net/lib.js"></script>']
    # one finding per (file, line); relative, integrity, commented-out and rel=icon tags never fire
    assert len({(f.file, f.line) for f in got}) == len(got)
    assert all(f.severity == "medium" and f.route is None for f in got)


def test_sri_master_and_page(model, refs):
    allf = rules_integrity.check(model, refs)
    (m,) = pick(allf, "DNL-INT-003", "Site.master")
    assert "cdn.example.net/site.css" in text_at(model, m) and m.route is None
    (p,) = pick(allf, "DNL-INT-003", "MacOn.aspx")
    assert p.route is not None and p.route.meta["kind"] == "webforms" and p.route.path.endswith("/MacOn.aspx")


def test_sri_same_line_tags_once(tmp_path):
    (tmp_path / "A.csproj").write_text('<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.7.2'
                                       '</TargetFrameworkVersion></PropertyGroup></Project>')
    (tmp_path / "x.html").write_text('<script src="https://a.example/1.js"></script><script src="https://b.example/2.js">'
                                     '</script>\n<!--[if lt IE 9]><script src="https://c.example/3.js"></script><![endif]-->\n'
                                     '<link rel="Stylesheet" href=\'https://d.example/s.css\' integrity="">\n')
    model = project.ProjectModel(tmp_path, [project.Project("A", tmp_path / "A.csproj", "cs", tmp_path)], {})
    got = rules_integrity.check(model)
    assert [f.line for f in got if f.check_id == "DNL-INT-003"] == [1, 2, 3]  # empty integrity counts as missing


# -- INT-004 --------------------------------------------------------------------

def test_viewstate_mac_directives(model, refs):
    allf = rules_integrity.check(model, refs)
    (mac,) = pick(allf, "DNL-INT-004", "MacOff.aspx")
    assert mac.severity == "high" and mac.route is not None and mac.line == 1
    (enc,) = pick(allf, "DNL-INT-004", "EncNever.aspx")
    assert enc.severity == "low" and enc.line == 2  # attribute on the second directive line
    (ctl,) = pick(allf, "DNL-INT-004", "Ctl.ascx")
    assert ctl.severity == "high" and ctl.route is None
    assert not pick(allf, "DNL-INT-004", "MacOn.aspx") and not pick(allf, "DNL-INT-004", "Site.master")


# -- SESS-006 / 007 / 008 -------------------------------------------------------

@pytest.fixture(scope="module")
def sess(model, refs):
    return [f for f in rules_session.check(model, refs) if f.file.endswith("AccountController.cs")]


def where(f):
    return f.description.rsplit("(in ", 1)[1].rstrip(").")


def test_sess_006_logout(sess):
    got = {where(f): f for f in pick(sess, "DNL-SESS-006")}
    assert set(got) == {"AccountController.LogOff"}  # Abandon / Clear (via helper) are safe
    f = got["AccountController.LogOff"]
    assert f.severity == "low" and f.confidence == "REVIEW" and f.route is not None


def test_sess_007_login(sess):
    got = {where(f) for f in pick(sess, "DNL-SESS-007")}
    assert got == {"AccountController.Login"}  # Abandon and clearing the session cookie renew the session


def test_sess_008_plaintext_compare(model, sess):
    got = pick(sess, "DNL-SESS-008")
    lines = sorted(text_at(model, f).strip() for f in got)
    assert lines == ['if (string.Equals(user.Password, model.Password)) return View();',
                     'if (user.Password == model.Password)']
    assert all(f.severity == "medium" and f.confidence == "REVIEW" for f in got)
    login = next(f for f in got if "==" in text_at(model, f))
    assert login.route is not None and where(login) == "AccountController.Login"


def test_route_less_findings_land_in_exactly_one_analyzer(model):
    seen = {}
    for fw in ("mvc", "webapi", "webforms", "wcf", "config"):
        for f in get_analyzer("dotnet_legacy", fw)(FX / "taint_app").analyze().findings:
            if f.check_id in ("DNL-INT-003", "DNL-INT-004") and f.route is None:
                seen.setdefault((f.check_id, f.file, f.line), []).append(fw)
    assert seen and all(len(v) == 1 for v in seen.values())
    assert seen[("DNL-INT-003", "TaintCs/Views/Shared/_Layout.cshtml", 10)] == ["mvc"]
    assert seen[("DNL-INT-003", "TaintWeb/Site.master", 5)] == ["webforms"]
    assert seen[("DNL-INT-004", "TaintWeb/Ctl.ascx", 1)] == ["webforms"]


# -- SESS-006/007 suppression scope ---------------------------------------------

def _mini(tmp_path, source):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Compile Include="A.cs" /></ItemGroup></Project>')
    (tmp_path / "A.cs").write_text(source)
    project._CACHE.clear()
    return project.prepare(tmp_path, False)


_AUTH = ('using System.Web; using System.Web.Security; namespace N {'
         ' public class Other { public void Cleanup() { HttpContext.Current.Session.Abandon(); }'
         ' public void Enter() { HttpContext.Current.Session.Abandon(); } }'
         ' public class AccountController { void Cleanup() { }'
         ' public void LogOff() { FormsAuthentication.SignOut(); Cleanup(); }'
         ' void Enter() { }'
         ' public void Login() { FormsAuthentication.SetAuthCookie("u", false); Enter(); } } }')


def test_unrelated_same_named_method_does_not_suppress(tmp_path, roslyn_helper):
    got = {(f.check_id, where(f)) for f in rules_session.check(_mini(tmp_path, _AUTH))}
    assert got == {("DNL-SESS-006", "AccountController.LogOff"), ("DNL-SESS-007", "AccountController.Login")}


def test_own_and_inherited_helpers_still_suppress(tmp_path, roslyn_helper):
    src = ('using System.Web; using System.Web.Security; namespace N {'
           ' public class BaseC { protected void End() { HttpContext.Current.Session.Abandon(); } }'
           ' public class AccountController : BaseC { void Local() { HttpContext.Current.Session.Clear(); }'
           ' public void LogOff() { FormsAuthentication.SignOut(); this.Local(); }'
           ' public void LogOut2() { FormsAuthentication.SignOut(); End(); }'
           ' public void Login() { FormsAuthentication.SetAuthCookie("u", false); base.End(); } } }')
    assert rules_session.check(_mini(tmp_path, src)) == []


def test_unrelated_caller_does_not_suppress(tmp_path, roslyn_helper):
    src = ('using System.Web; using System.Web.Security; namespace N {'
           ' public class Other { void T(AccountController c) { c.LogOff(); HttpContext.Current.Session.Abandon(); } }'
           ' public class AccountController { public void LogOff() { FormsAuthentication.SignOut(); } } }')
    # `c.LogOff()` resolves to AccountController.LogOff, so Other.T is a real caller that abandons: handled.
    assert rules_session.check(_mini(tmp_path, src)) == []
    src2 = ('using System.Web; using System.Web.Security; namespace N {'
            ' public class Other { public void T() { LogOff(); HttpContext.Current.Session.Abandon(); } void LogOff() { } }'
            ' public class AccountController { public void LogOff() { FormsAuthentication.SignOut(); } } }')
    got = rules_session.check(_mini(tmp_path, src2))
    assert [(f.check_id, where(f)) for f in got] == [("DNL-SESS-006", "AccountController.LogOff")]


def test_password_policy_comparisons_are_not_secrets(tmp_path, roslyn_helper):
    src = ('namespace N { public class U { public int PasswordFormat; public int PasswordLength; public int MinRequiredPasswordLength;'
           ' public string Password; public string Other; public int Fmt;'
           ' public bool M(U u) { return u.PasswordFormat == u.Fmt || u.PasswordLength != u.Fmt'
           ' || u.MinRequiredPasswordLength == u.Fmt || u.Password == u.Other; } } }')
    got = [f for f in rules_session.check(_mini(tmp_path, src)) if f.check_id == "DNL-SESS-008"]
    assert len(got) == 1 and "'Password'" in got[0].description


# -- WebForms code-behind findings carry the page route -------------------------

def test_webforms_code_behind_findings_carry_the_page_route(tmp_path, roslyn_helper):
    from checks.dnl import rules_crypto, rules_deser_xml  # noqa: PLC0415
    (tmp_path / "W.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003"><ItemGroup>'
        '<Reference Include="System.Web" /><Compile Include="P.aspx.cs" /><Content Include="P.aspx" /></ItemGroup></Project>')
    (tmp_path / "P.aspx").write_text('<%@ Page Language="C#" CodeBehind="P.aspx.cs" Inherits="N.P" %>')
    (tmp_path / "P.aspx.cs").write_text(
        'using System.Security.Cryptography; using System.Web.Security; using System.Xml; namespace N {'
        ' public class P : System.Web.UI.Page {'
        ' object hasher = MD5.Create();'
        ' protected void Page_Load(object s, System.EventArgs e) { var r = new XmlTextReader("a.xml"); r.Read(); }'
        ' protected void Btn_Click(object s, System.EventArgs e) { FormsAuthentication.SetAuthCookie("u", false); } } }')
    project._CACHE.clear()
    model = project.prepare(tmp_path, False)
    refs = routes.discover_webforms(model)
    assert refs and refs[0].method is None
    for rule, mod in (("DNL-CRY-001", rules_crypto), ("DNL-XXE-001", rules_deser_xml), ("DNL-SESS-007", rules_session)):
        got = pick(mod.check(model, refs), rule)
        assert got, rule
        assert all(f.route is not None and f.route.meta["kind"] == "webforms" for f in got), rule
    # the field initializer (outside any method) is attributed too
    (cry,) = pick(rules_crypto.check(model, refs), "DNL-CRY-001")
    assert cry.route.path.endswith("/P.aspx")
