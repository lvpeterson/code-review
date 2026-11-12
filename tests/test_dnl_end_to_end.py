"""dotnet_legacy analyzers wired through the CLI, plus README rule coverage."""
import json
import re
import sys
from pathlib import Path

import pytest

import main
from checks.dnl import helper, project
from core.owasp_web import RULES
from core.registry import get_analyzer
import languages.dotnet_legacy.analyzers  # noqa: F401  (registration)

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"
README = Path(__file__).resolve().parent.parent / "languages" / "dotnet_legacy" / "README.md"


@pytest.fixture(autouse=True)
def _fresh_cache():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


# -- brief tests ------------------------------------------------------------

def test_end_to_end_cli(tmp_path, monkeypatch, roslyn_helper):
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "mvc5_app"), "--json", str(out), "--html", str(tmp_path / "r.html")])
    assert main.main() == 0
    data = json.loads(out.read_text())
    fw = {r["framework"] for r in data if r["language"] == "dotnet_legacy"}
    assert fw == {"mvc", "webapi", "config"}
    ids = {f["check_id"] for r in data for f in r["findings"]}
    assert {"DNL-AUTHZ-001", "DNL-AUTHZ-003", "DNL-CFG-001"} <= ids
    assert all(f["owasp"] for r in data if r["language"] == "dotnet_legacy" for f in r["findings"])
    assert 'id="tab-panel-owasp"' in (tmp_path / "r.html").read_text()


def test_degraded_cli(tmp_path, monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    project._CACHE.clear()
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "mvc5_app"), "--allow-degraded", "--html", str(tmp_path / "r.html")])
    assert main.main() == 0 and "degraded-banner" in (tmp_path / "r.html").read_text()


# -- analyzer behaviour -------------------------------------------------------

def _run(fw: str, target: Path):
    return get_analyzer("dotnet_legacy", fw)(target).analyze()


def test_mvc_and_webapi_split_routes_and_authz_003(roslyn_helper):
    project.prepare(FX / "mvc5_app", False)
    mvc, api = _run("mvc", FX / "mvc5_app"), _run("webapi", FX / "mvc5_app")
    assert mvc.routes and all(r.meta["kind"] == "mvc" for r in mvc.routes)
    assert api.routes and all(r.meta["kind"] == "webapi" for r in api.routes)
    # Each finding belongs to a route of its own analyzer (or is AUTHZ-003, route-less).
    for res in (mvc, api):
        ids = {id(r) for r in res.routes}
        assert all(f.route is None or id(f.route) in ids for f in res.findings)
    a3 = [f for res in (mvc, api) for f in res.findings if f.check_id == "DNL-AUTHZ-003"]
    # AlwaysAllowAttribute lives in MvcApp (references System.Web.Mvc) -> reported once, by mvc.
    assert len(a3) == 1 and a3[0] in mvc.findings
    assert mvc.degraded is None and api.degraded is None


def test_routes_computed_once_per_model(roslyn_helper, monkeypatch):
    from checks.dnl import routes as dnl_routes
    import languages.dotnet_legacy.analyzers as an
    calls = []
    real = dnl_routes.discover_mvc_webapi
    monkeypatch.setattr(an.routes, "discover_mvc_webapi", lambda m: calls.append(1) or real(m))
    project.prepare(FX / "mvc5_app", False)
    _run("mvc", FX / "mvc5_app")
    _run("webapi", FX / "mvc5_app")
    assert len(calls) == 1


def test_webforms_analyzer(roslyn_helper):
    project.prepare(FX / "webforms_vb", False)
    res = _run("webforms", FX / "webforms_vb")
    assert {r.path for r in res.routes} == {"/Default.aspx", "/Secure/Edit.aspx", "/Members/List.aspx"}
    assert any(f.check_id == "DNL-AUTHZ-001" for f in res.findings)


def test_config_analyzer_api_and_aspx_dirs(roslyn_helper):
    project.prepare(FX / "webapi_global", False)
    res = _run("config", FX / "webapi_global")
    assert res.findings, "webapi_global Web.config should yield config findings"
    # ApiApp references System.Web.Http -> its config findings carry the API tag.
    assert all("api2023" in f.owasp for f in res.findings)


def test_degraded_analyzers(monkeypatch):
    monkeypatch.setattr(helper, "find_helper", lambda *a: None)
    monkeypatch.setattr(helper, "sdk_available", lambda: False)
    project.prepare(FX / "mvc5_app", True)
    mvc, cfg = _run("mvc", FX / "mvc5_app"), _run("config", FX / "mvc5_app")
    assert mvc.routes == [] and mvc.findings == [] and mvc.degraded == helper.DEGRADED_REASON
    assert cfg.degraded == helper.DEGRADED_REASON
    assert any(f.check_id == "DNL-CFG-001" for f in cfg.findings)


def test_model_notes_surface(roslyn_helper):
    model = project.prepare(FX / "mvc5_app", False)
    model.notes.append("synthetic note")
    assert "synthetic note" in _run("config", FX / "mvc5_app").notes


# -- README -------------------------------------------------------------------

def test_readme_lists_every_rule_with_tags():
    text = README.read_text(encoding="utf-8")
    assert chr(0x2014) not in text  # no em-dashes
    for rid, (c25, c21, api, _mode) in RULES.items():
        row = next((ln for ln in text.splitlines() if ln.startswith(f"| {rid} ")), None)
        assert row is not None, f"{rid} missing from README rule table"
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert re.fullmatch(r"(high|medium|low|info)(/(high|medium|low|info))*", cells[1]), row
        assert f"{c25}:2025" in row and f"{c21}:2021" in row, row
        assert (f"{api}:2023" in row) if api else ("API" not in cells[-1]), row


# -- final review fixes -------------------------------------------------------

def test_model_notes_emitted_once(roslyn_helper):
    model = project.prepare(FX / "mvc5_app", False)
    model.notes.append("synthetic note")
    results = [_run(fw, FX / "mvc5_app") for fw in ("mvc", "webapi", "webforms", "config")]
    assert sum("synthetic note" in r.notes for r in results) == 1


def _authz3_model():
    from checks.dnl import ir
    from checks.dnl.project import Project, ProjectModel
    from core.models import Finding
    t = ir.TypeIR("AllowAll", "N", "class", ["public"], ["AuthorizeAttribute"], [], [], [], [], 1, 9, "a/f.cs")
    proj = Project("P", Path("a/P.csproj"), "cs", Path("a"), references={"system.web.mvc"}, compile_files=[Path("a/f.cs")])
    model = ProjectModel(Path("a"), [proj], {"a/f.cs": ir.FileIR("a/f.cs", "cs", "P", 0, [t])}, None, [])
    model.project_of = lambda rel: proj
    return model, Finding(check_id="DNL-AUTHZ-003", severity="high", title="t", description="d", file="a/f.cs", line=1)


def test_owner_kind_falls_back_to_an_enumerated_analyzer(monkeypatch):
    import languages.dotnet_legacy.analyzers as an
    model, f = _authz3_model()
    monkeypatch.setattr(an.detector, "detect_frameworks", lambda root: ["mvc", "config"])
    assert an._owner_kind(model, f) == "mvc"
    model.cache.clear()
    monkeypatch.setattr(an.detector, "detect_frameworks", lambda root: ["webapi", "webforms", "config"])
    assert an._owner_kind(model, f) == "webapi"
    model.cache.clear()
    monkeypatch.setattr(an.detector, "detect_frameworks", lambda root: ["config"])
    assert an._owner_kind(model, f) == "config"


def test_project_less_site_end_to_end(tmp_path, roslyn_helper):
    site = tmp_path / "Site"
    site.mkdir()
    (site / "Web.config").write_text(
        '<configuration><system.web><pages validateRequest="false"/></system.web></configuration>')
    (site / "Default.aspx").write_text('<%@ Page Language="VB" %>\n')
    project.prepare(site, False)
    wf, cfg = _run("webforms", site), _run("config", site)
    assert [r.path for r in wf.routes] == ["/Default.aspx"]
    assert any(f.check_id == "DNL-AUTHZ-001" for f in wf.findings)
    assert any(f.check_id == "DNL-XSS-002" for f in cfg.findings)


def test_end_to_end_taint_app(tmp_path, monkeypatch, roslyn_helper):
    out = tmp_path / "r.json"
    monkeypatch.setattr(sys, "argv", ["main.py", str(FX / "taint_app"), "--json", str(out)])
    assert main.main() == 0
    inj = [f for r in json.loads(out.read_text()) for f in r["findings"] if f["check_id"] == "DNL-INJ-001"]
    assert inj and all(f["owasp"]["2025"].startswith("A05:2025") for f in inj)


def test_taint_solver_performance_guard(roslyn_helper):
    """Bounded work rather than wall time: the fixpoint must settle within the round cap."""
    from checks.dnl import taint_solver
    model = project.prepare(FX / "taint_app", False)
    taint_solver.solve(model)
    state = model.cache["taint"]
    assert state["converged"] is True
    # Observed 11 rounds; the cap is 24, so there is margin and converged carries the check.
    assert state["rounds"] <= 24
