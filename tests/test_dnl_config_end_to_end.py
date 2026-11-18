"""ASP.NET Core configuration rules end to end: the synthetic `config_app` fixture trips every new
rule id, helper and degraded runs agree, the registry/README/source agree on the ids, dotnet_legacy
output is unchanged, and Development-only weak settings stay silent."""
import re
from pathlib import Path

import pytest

import enumerator
from checks.dnl import helper, project
from core.owasp_web import RULES

ROOT = Path(__file__).resolve().parent.parent
FX = Path(__file__).parent / "fixtures"
APP = FX / "aspnetcore" / "config_app"
README = ROOT / "languages" / "dotnet_legacy" / "README.md"

# Every id this plan adds (the plan's "Rule ids" table).
NEW_IDS = (
    "DNL-CFG-008", "DNL-CFG-009", "DNL-CFG-010", "DNL-CFG-011", "DNL-CFG-012", "DNL-CFG-013",
    "DNL-CFG-014", "DNL-CFG-015", "DNL-SESS-009", "DNL-SESS-010", "DNL-SESS-011", "DNL-SEC-004",
    "DNL-SEC-005", "DNL-SEC-006", "DNL-SEC-007", "DNL-CSRF-002", "DNL-RES-004", "DNL-RES-005",
    "DNL-INV-003", "DNL-INV-004", "DNL-CRY-009",
)
# Reused from the legacy rules (same check, ASP.NET Core flavour); the fixture trips these too.
REUSED_IDS = ("DNL-CFG-007", "DNL-SESS-001", "DNL-SESS-002", "DNL-SESS-003", "DNL-CSRF-001",
              "DNL-SEC-001", "DNL-SEC-002", "DNL-RES-001", "DNL-ERR-002")
# Reported on a route (by a route analyzer), not in the route-less config result.
ROUTE_BOUND = {"DNL-CFG-015", "DNL-CSRF-002", "DNL-RES-005", "DNL-INV-004", "DNL-RES-004", "DNL-CSRF-001"}


@pytest.fixture(autouse=True)
def _fresh_cache():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _dotnet(**kw):
    return [r for r in enumerator.enumerate_target(APP, **kw) if r.language == "dotnet"]


def _keys(results, wanted=None) -> set[tuple]:
    return {(f.check_id, f.file, f.line) for r in results for f in r.findings
            if wanted is None or wanted(f.check_id)}


# -- every group reports -----------------------------------------------------------------------

def test_fixture_reports_every_group(roslyn_helper):
    results = _dotnet()
    config = [f for r in results if r.framework == "config" for f in r.findings]
    route_less = {f.check_id for f in config if f.route is None}
    for cid in NEW_IDS + REUSED_IDS:
        if cid not in ROUTE_BOUND:
            assert cid in route_less, f"{cid} missing from the dotnet/config result"
    assert not [f for f in config if f.check_id in ROUTE_BOUND], "route-bound findings belong to route analyzers"

    bound = [(r.framework, f) for r in results if r.framework != "config"
             for f in r.findings if f.route is not None]

    def at(cid, path_part):
        hits = [f for _, f in bound if f.check_id == cid and path_part in f.route.path]
        assert hits, f"{cid} not reported on a route containing {path_part!r}"
        return hits[0]

    assert at("DNL-CFG-015", "/Account/Reset").route.meta["kind"] == "controller"
    assert at("DNL-CSRF-002", "/Account/Delete").route.meta["kind"] == "controller"
    assert at("DNL-RES-005", "/api/v1/items").route.handler_name.endswith("List")
    assert at("DNL-INV-004", "/api/v1/items")           # the older version, not /api/v2
    assert not [f for _, f in bound if f.check_id == "DNL-INV-004" and "/v2/" in f.route.path]
    assert at("DNL-RES-004", "/Account/Login")
    assert at("DNL-CSRF-001", "/Account/UpdateProfile")
    # Two pipelines: the second has no exception handler at all.
    assert {f.file for f in config if f.check_id == "DNL-CFG-009"} == {"Edge/Program.cs"}
    assert {f.file for f in config if f.check_id == "DNL-ERR-002"} == {"Web/Program.cs"}
    assert all(r.degraded is None for r in results)


# -- degraded parity ---------------------------------------------------------------------------

_PARITY = re.compile(r"DNL-(CFG-\d+|SESS-009|SESS-010|SESS-011|SEC-00[4-7]|CSRF-002|RES-00[45]|INV-00[34]|CRY-009)")


def _parity(cid: str) -> bool:
    return _PARITY.fullmatch(cid) is not None


def test_degraded_parity(roslyn_helper, monkeypatch):
    with_helper = _keys(_dotnet(), _parity)
    assert {k[0] for k in with_helper} >= set(NEW_IDS)
    project._CACHE.clear()
    monkeypatch.setattr(helper, "find_helper", lambda *a, **k: None)
    monkeypatch.setattr(helper, "sdk_available", lambda *a, **k: False)
    degraded = _dotnet(allow_degraded=True)
    assert degraded and all(r.degraded for r in degraded)
    assert _keys(degraded, _parity) == with_helper


# -- registry, README and source agree ---------------------------------------------------------

def test_every_new_id_registered():
    readme = README.read_text(encoding="utf-8")
    rows = {ln.split("|")[1].strip() for ln in readme.splitlines() if ln.startswith("| DNL-")}
    dnl = ROOT / "checks" / "dnl"
    sources = [dnl / "rules_secrets_core.py", dnl / "rules_limits_core.py", *sorted(dnl.glob("rules_pipeline*.py"))]
    text = "\n".join(p.read_text(encoding="utf-8") for p in sources)
    for cid in NEW_IDS:
        assert cid in RULES, f"{cid} not in core.owasp_web.RULES"
        assert cid in rows, f"{cid} not in the README rule table"
        assert re.search(r"""["']%s["']""" % re.escape(cid), text), f"{cid} is not a quoted literal in the rule modules"


# -- dotnet_legacy is untouched ----------------------------------------------------------------

# (check_id, file, line) of the dotnet_legacy findings on mvc5_app, recorded from the foundation
# commit before any configuration rule existed.
LEGACY_MVC5 = {
    ("DNL-AUTHZ-001", "MvcApp/Areas/Admin/Controllers/UsersController.cs", 7),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/LooseController.cs", 9),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/PublicController.cs", 7),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/PublicController.cs", 11),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/ReportsController.cs", 9),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/ReportsController.cs", 14),
    ("DNL-AUTHZ-001", "MvcApp/Controllers/ReportsController.cs", 17),
    ("DNL-AUTHZ-001", "MvcVb/Controllers/ordersController.vb", 7),
    ("DNL-AUTHZ-001", "MvcVb/Controllers/ordersController.vb", 16),
    ("DNL-AUTHZ-002", "MvcApp/Controllers/PublicController.cs", 11),
    ("DNL-AUTHZ-003", "MvcApp/Filters/AlwaysAllowAttribute.cs", 7),
    ("DNL-AUTHZ-004", "MvcApp/Controllers/AdminController.cs", 8),
    ("DNL-AUTHZ-004", "MvcApp/Controllers/OrdersApiController.cs", 19),
    ("DNL-CFG-001", "MvcApp/Web.config", 4),
    ("DNL-CFG-005", "MvcApp/Web.config", 3),
    ("DNL-CFG-006", "MvcApp/Web.config", 3),
    ("DNL-CSRF-001", "MvcApp/Controllers/PublicController.cs", 11),
    ("DNL-CSRF-001", "MvcApp/Controllers/ReportsController.cs", 14),
    ("DNL-CSRF-001", "MvcVb/Controllers/ordersController.vb", 16),
    ("DNL-DES-001", "MvcApp/Controllers/PublicController.cs", 11),
    ("DNL-LOG-002", "MvcApp.Data/MvcApp.Data.csproj", 1),
    ("DNL-SESS-002", "MvcApp/Web.config", 3),
}


def test_legacy_unchanged(roslyn_helper):
    results = enumerator.enumerate_target(FX / "dotnet_legacy" / "mvc5_app")
    legacy = {(f.check_id, f.file, f.line) for r in results if r.language == "dotnet_legacy" for f in r.findings}
    assert legacy == LEGACY_MVC5


# -- Development-only settings are silent ------------------------------------------------------

def test_no_dev_noise(roslyn_helper):
    results = _dotnet()
    program = (APP / "Web" / "Program.cs").read_text(encoding="utf-8").splitlines()
    guard = next(i for i, ln in enumerate(program, 1) if "IsDevelopment()" in ln)
    findings = [f for r in results for f in r.findings]
    # Nothing is reported from the guarded block (its developer page, wildcard CORS and OpenAPI map).
    assert not [f for f in findings if f.file == "Web/Program.cs" and f.line >= guard]
    # The Development settings file repeats DetailedErrors / AllowedHosts and holds a weak password.
    assert not [f for f in findings if f.file.endswith("appsettings.Development.json")]
    # The same settings in the base file are reported, so the silence above is the guard, not blindness.
    base = {(f.check_id, f.file) for f in findings}
    assert ("DNL-CFG-008", "Web/appsettings.json") in base and ("DNL-CFG-014", "Web/appsettings.json") in base
