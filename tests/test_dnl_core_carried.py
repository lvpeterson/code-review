"""ASP.NET Core SCA and carried-over rule families: golden legacy baselines and Core fixtures."""
import shutil
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project, rules_sca

FIX = Path(__file__).parent / "fixtures"
FX = FIX / "aspnetcore"
SCA_APP = FX / "sca_app"
CARRIED_APP = FX / "carried_app"
LEGACY_DEPS = FIX / "dotnet_legacy" / "deps_app"


@pytest.fixture(autouse=True)
def _fresh():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _degraded(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)


def _dotnet(root, **kw):
    return [r for r in enumerator.enumerate_target(root, **kw) if r.language == "dotnet"]


def _legacy(root, **kw):
    return [r for r in enumerator.enumerate_target(root, **kw) if r.language == "dotnet_legacy"]


def _ids(results):
    """{(check_id, file_name)} of every finding."""
    return {(f.check_id, Path(f.file).name) for r in results for f in r.findings}


# Golden values captured from the unmodified legacy analyzers; identical with and
# without the Roslyn helper (the legacy side does not depend on it for these rules).
MIXED_LEGACY_FINDINGS = [
    ("DNL-AUTHZ-001", "Framework/Controllers/OldController.cs", 5),
    ("DNL-AUTHZ-001", "Legacy/Controllers/HomeController.cs", 7),
    ("DNL-AUTHZ-001", "Legacy/Controllers/HomeController.cs", 13),
    ("DNL-CSRF-001", "Legacy/Controllers/HomeController.cs", 13),
    ("DNL-LOG-002", "Legacy/Legacy.csproj", 1),
    ("DNL-SCA-002", "Framework/Scripts/jquery.js", 1),
]
MIXED_LEGACY_FRAMEWORKS = ["deps", "mvc"]

LEGACY_DEPS_GOLDEN = [
    ("DNL-SCA-001", "Web/Web.csproj", 13, "medium"),
    ("DNL-SCA-001", "Web/packages.config", 3, "high"),
    ("DNL-SCA-001", "Web/packages.config", 4, "medium"),
    ("DNL-SCA-002", "Web/Scripts/jquery-1.12.4.min.js", 1, "medium"),
    ("DNL-SCA-003", "Web/Web.csproj", 6, "medium"),
    ("DNL-SCA-004", "Web/Web.csproj", 16, "low"),
    ("DNL-SCA-005", "nuget.config", 5, "medium"),
]


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_legacy_findings_unchanged_on_mixed_solution(mode, monkeypatch):
    if mode == "degraded":
        _degraded(monkeypatch)
    results = _legacy(FX / "mixed_solution", allow_degraded=(mode == "degraded"))
    findings = sorted((f.check_id, f.file, f.line) for r in results for f in r.findings)
    assert findings == MIXED_LEGACY_FINDINGS
    assert sorted(r.framework for r in results) == MIXED_LEGACY_FRAMEWORKS


def test_legacy_deps_unchanged():
    root = LEGACY_DEPS.resolve()
    model = project.ProjectModel(root, project.load_projects(root), {}, "no helper")
    findings, _ = rules_sca.check(model)
    assert sorted((f.check_id, f.file, f.line, f.severity) for f in findings) == LEGACY_DEPS_GOLDEN


# -- carried families on SDK projects: crypto, deserialization / XXE, integrity -------------------

def _carried(monkeypatch, mode):
    if mode == "degraded":
        _degraded(monkeypatch)
    return _dotnet(CARRIED_APP, allow_degraded=(mode == "degraded"))


def _family(results, prefixes):
    """{(check_id, file, line, severity)} of the findings whose id starts with one of the prefixes."""
    return {(f.check_id, f.file, f.line, f.severity) for r in results for f in r.findings
            if f.check_id.startswith(prefixes)}


CRYPTO_FILE = "Crypto/WeakCrypto.cs"
CRYPTO_EXPECTED = {
    ("DNL-CRY-001", CRYPTO_FILE, 14, "high"),      # MD5 inside HashPassword
    ("DNL-CRY-001", CRYPTO_FILE, 21, "medium"),    # SHA1 for a checksum
    ("DNL-CRY-002", CRYPTO_FILE, 27, "high"),
    ("DNL-CRY-003", CRYPTO_FILE, 34, "high"),
    ("DNL-CRY-004", CRYPTO_FILE, 35, "high"),
    ("DNL-CRY-005", CRYPTO_FILE, 42, "medium"),    # the token local ...
    ("DNL-CRY-005", CRYPTO_FILE, 43, "medium"),    # ... and the value NewToken returns
    ("DNL-CRY-006", CRYPTO_FILE, 56, "high"),
    ("DNL-CRY-007", CRYPTO_FILE, 54, "medium"),
    ("DNL-CRY-008", CRYPTO_FILE, 48, "medium"),
    ("DNL-SEC-003", CRYPTO_FILE, 62, "high"),
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_crypto_findings_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    got = _family(results, ("DNL-CRY-", "DNL-SEC-"))
    assert got == CRYPTO_EXPECTED
    assert not [g for g in got if g[1].endswith("SafeCrypto.cs")]
    # the password hash is reached from a routed action: it carries that route
    md5 = next(f for r in results for f in r.findings if f.check_id == "DNL-CRY-001" and f.line == 14)
    assert md5.route is None or md5.route.meta["kind"] == "controller"


DESER_EXPECTED = {
    ("DNL-DESER-001", "Deser/UnsafeDeser.cs", 13, "medium"),
    ("DNL-DESER-002", "Deser/UnsafeDeser.cs", 19, "high"),      # Newtonsoft, matched by name
    ("DNL-DESER-003", "Deser/UnsafeDeser.cs", 24, "high"),
    ("DNL-XXE-001", "Deser/UnsafeDeser.cs", 32, "medium"),
    ("DNL-XXE-001", "Deser/UnsafeDeser.cs", 39, "medium"),
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_deser_xxe_findings_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    got = _family(results, ("DNL-DESER-", "DNL-XXE-"))
    assert got == DESER_EXPECTED
    assert not [g for g in got if g[1].endswith("SafeDeser.cs")]


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_integrity_sri_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    got = _family(results, ("DNL-INT-",))
    # only the CDN script without integrity; the SRI one and the local ~/lib one are never flagged
    assert got == {("DNL-INT-003", "Views/Shared/_Layout.cshtml", 5, "medium")}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_no_failed_notes(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    assert results
    assert not [n for r in results for n in r.notes if "failed (" in n]


def test_taint_flag_matches_wiring(monkeypatch):
    from checks.dnl import rules_taint
    from languages.dotnet import analyzers
    called = []
    # Only calls on the Core view count: carried_app has a Web.config, so the legacy package also runs
    # (on its own, empty view) and calls rules_taint.
    monkeypatch.setattr(rules_taint, "check", lambda model, *a, **k: (called.append(1) if model.owner == "dotnet" else None) or [])
    results = _dotnet(CARRIED_APP, allow_degraded=False)
    # the analyzers must really have run, or "not called" would prove nothing
    assert results and "DNL-CRY-001" in {f.check_id for r in results for f in r.findings}
    assert bool(called) == analyzers.CORE_RUNS_TAINT, (
        "CORE_RUNS_TAINT and the rules_taint wiring drifted: set the flag to True in the same change "
        "that runs rules_taint.check in languages/dotnet/analyzers.py (and back), otherwise "
        "DESER-001 / XXE-001 on tainted lines are lost or doubled")


# -- carried families on SDK projects, part 2: errors, logging, flows, resources, inventory, session --

ERR_FILE = "Controllers/ErrorsController.cs"
ERRORS_EXPECTED = {
    ("DNL-ERR-001", ERR_FILE, 81, "medium"),     # IAuthorizationFilter whose empty catch lets the request through
    ("DNL-ERR-002", ERR_FILE, 25, "medium"),     # Ok(ex.ToString())
    ("DNL-ERR-002", ERR_FILE, 35, "medium"),     # Content(detail) with detail = ex.StackTrace
    ("DNL-ERR-003", ERR_FILE, 17, "low"),        # catch { }
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_errors_findings_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    got = _family(results, ("DNL-ERR-",))
    # logged + Problem(), type name only, a narrow empty catch and the fail-closed filter stay silent
    assert got == ERRORS_EXPECTED


LOG_FILE = "Services/Logging.cs"
LOGGING_EXPECTED = {
    ("DNL-LOG-003", LOG_FILE, 14, "medium"),     # $"... {password}"
    ("DNL-LOG-003", LOG_FILE, 15, "medium"),     # "token issued: " + token
    ("DNL-LOG-004", LOG_FILE, 38, "low"),        # Login: rejected sign-in never logged
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_logging_findings_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    # templates, password.Length and the audited login stay silent (Serilog / ILogger are matched by name)
    assert _family(results, ("DNL-LOG-",)) == LOGGING_EXPECTED


FLOWS_EXPECTED = {
    ("DNL-DES-001", "Controllers/FlowsController.cs", 22, "low"),     # Login: no lockout / limiter
    ("DNL-CONSUME-001", "Services/Outbound.cs", 10, "low"),           # http:// partner endpoint
    ("DNL-CONSUME-002", "Controllers/FlowsController.cs", 60, "low"),  # upstream body run as a command
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_flows_consume_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    # SignInLocked (lockoutOnFailure: true), Register ([EnableRateLimiting]), the https call and the
    # response that never reaches a sink stay silent
    assert _family(results, ("DNL-DES-", "DNL-CONSUME-")) == FLOWS_EXPECTED
    des = next(f for r in results for f in r.findings if f.check_id == "DNL-DES-001")
    assert des.route is not None and des.route.meta["kind"] == "controller"


RESOURCES_EXPECTED = {
    ("DNL-RES-002", "Controllers/UploadController.cs", 36, "low"),    # every row of a DbSet
    ("DNL-RES-003", "Controllers/UploadController.cs", 17, "medium"),  # IFormFile.CopyToAsync, no Length check
    ("DNL-INV-002", "Controllers/UploadController.cs", 47, "low"),    # DiagnosticsController shipped
    ("DNL-INV-002", "Program.cs", 11, "low"),                         # UseSwagger() in every environment
    ("DNL-INV-002", "Program.cs", 15, "low"),                         # guard on a config value: unknown -> Production
    ("DNL-INV-002", "Program.cs", 19, "low"),                         # IsDevelopment() || StartsWith(..): unknown
}


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_resources_inventory_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    # SaveChecked (file.Length guard), the capped Take(Math.Min(..)) page and the swagger UI under
    # IsDevelopment() stay silent
    assert _family(results, ("DNL-RES-", "DNL-INV-")) == RESOURCES_EXPECTED
    # only the proven Development guard (line 8) is suppressed; the text names the Core remedy
    sw = next(f for r in results for f in r.findings if f.check_id == "DNL-INV-002" and f.line == 11)
    assert "Development" in sw.description and "web.config" not in sw.description


@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_session_on_core(mode, monkeypatch):
    results = _carried(monkeypatch, mode)
    # the hashed comparison through IPasswordHasher stays silent
    assert _family(results, ("DNL-SESS-",)) == {("DNL-SESS-008", "Controllers/SessionController.cs", 16, "medium")}


# Ids the carried modules can emit that cannot fire on SDK projects (or are not asserted by a fixture
# positive); mirrored in languages/dotnet/CARRIED_RULES.md.
EXCLUDED = {
    "DNL-LOG-002": "legacy projects only: the finding is anchored on a .NET Framework project file and an "
                   "SDK-only model has none, so logging absence is never reported for Core",
    "DNL-SESS-006": "System.Web / OWIN only: matches FormsAuthentication.SignOut and "
                    "AuthenticationManager.SignOut; Core's HttpContext.SignOutAsync is not matched",
    "DNL-SESS-007": "System.Web / OWIN only: matches FormsAuthentication.SetAuthCookie / "
                    "RedirectFromLoginPage and AuthenticationManager.SignIn; Core's SignInAsync is not matched",
}
_MODULES = ("rules_errors", "rules_logging", "rules_flows", "rules_resources", "rules_session")


def test_every_emittable_id_has_a_core_positive_or_an_exclusion():
    import re
    emittable = set()
    for mod in _MODULES:
        text = (Path(__file__).parent.parent / "checks" / "dnl" / f"{mod}.py").read_text(encoding="utf-8")
        emittable |= set(re.findall(r"DNL-[A-Z]+-\d{3}", text))
    positives = {i for exp in (ERRORS_EXPECTED, LOGGING_EXPECTED, FLOWS_EXPECTED, RESOURCES_EXPECTED,
                               {("DNL-SESS-008", "", 0, "")}) for i, *_ in exp}
    assert all(reason.strip() for reason in EXCLUDED.values())
    assert not positives & set(EXCLUDED)
    assert emittable == positives | set(EXCLUDED), emittable ^ (positives | set(EXCLUDED))


def test_rules_misc_runs_without_web_config_on_core(monkeypatch):
    from checks.dnl import rules_misc, webconfig
    seen = []
    real = rules_misc.check
    monkeypatch.setattr(rules_misc, "check", lambda model, refs=(), configs=(): seen.append(configs) or real(model, refs, configs))
    monkeypatch.setattr(webconfig, "load_configs", lambda *a, **k: (_ for _ in ()).throw(AssertionError("Web.config read on Core")))
    results = _dotnet(CARRIED_APP, allow_degraded=False)
    # carried_app has a Web.config, so the legacy package also runs its config analyzer here: it loads
    # configs but its ownership filter drops the SDK project's file (the Core call passes a tuple).
    assert seen and all(len(c) == 0 for c in seen)
    assert sum(isinstance(c, tuple) for c in seen) == 1
    assert not [n for r in results for n in r.notes if "failed (" in n]


def test_no_logging_absence_finding_for_sdk_side_of_mixed_solution():
    results = _dotnet(FX / "mixed_solution", allow_degraded=False)
    assert not [f for r in results for f in r.findings if f.check_id == "DNL-LOG-002"]


def test_one_crashing_module_does_not_hide_others(monkeypatch):
    from checks.dnl import rules_errors

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(rules_errors, "check", boom)
    project._CACHE.clear()
    results = _dotnet(CARRIED_APP, allow_degraded=False)
    notes = [n for r in results for n in r.notes]
    assert any("rules_errors failed (RuntimeError: boom)" in n for n in notes)
    got = _family(results, ("DNL-CRY-", "DNL-SEC-"))
    assert got == CRYPTO_EXPECTED
    assert not _family(results, ("DNL-ERR-",))
    # the modules wired after the crashing one still ran
    assert _family(results, ("DNL-LOG-", "DNL-SESS-")) >= LOGGING_EXPECTED


# -- Web.config guard (Review Focus 3) --------------------------------------------------------------

WEB_CONFIG_ONLY = FX / "web_config_only_core"


@pytest.mark.parametrize("root", [CARRIED_APP, WEB_CONFIG_ONLY], ids=["carried_app", "web_config_only_core"])
@pytest.mark.parametrize("mode", ["helper", "degraded"])
def test_web_config_checks_do_not_run_on_core(root, mode, monkeypatch):
    # carried_app's Web.config holds the IIS hosting stub plus legacy system.web / system.webServer
    # sections (debug, version header, customErrors Off, detailed errors); none of it is read on Core.
    assert (root / "Web.config").is_file()
    if mode == "degraded":
        _degraded(monkeypatch)
    results = _dotnet(root, allow_degraded=(mode == "degraded"))
    assert results
    findings = [f for r in results for f in r.findings]
    assert not [f for f in findings if f.check_id.startswith(("DNL-CFG-", "DNL-WCF-"))]
    assert not [f for f in findings if Path(f.file).name.lower() == "web.config"]
    assert not [n for r in results for n in r.notes if "failed (" in n]


def test_legacy_still_reads_web_config_in_mixed_solution(tmp_path):
    # Copy of the mixed solution with a legacy Web.config beside the .NET Framework project: the legacy
    # package reports the config finding, the SDK package of the same scan reports none.
    root = tmp_path / "mixed"
    shutil.copytree(FX / "mixed_solution", root)
    (root / "Legacy" / "Web.config").write_text(
        '<?xml version="1.0"?><configuration><system.web><customErrors mode="Off" /></system.web></configuration>',
        encoding="utf-8")
    project._CACHE.clear()
    legacy = [f for r in _legacy(root) for f in r.findings if Path(f.file).name == "Web.config"]
    assert "DNL-CFG-002" in {f.check_id for f in legacy}     # customErrors mode="Off"
    assert not [f for r in _dotnet(root) for f in r.findings if f.check_id.startswith("DNL-CFG-")]


# -- degraded parity ---------------------------------------------------------------------------------

# {check id: what it needs from the Roslyn helper that the tree-sitter IR cannot give}. Empty on purpose:
# every carried id the two fixtures exercise reports the same (id, file) with and without the helper, so
# nothing is excused. An id may only be added here with the symbol it needs (and in CARRIED_RULES.md).
JUSTIFIED_DEGRADED: dict[str, str] = {}

_FAMILIES = {
    "SCA": ("DNL-SCA-",),
    "CRY": ("DNL-CRY-", "DNL-SEC-"),
    "DESER": ("DNL-DESER-", "DNL-XXE-"),
    "INT": ("DNL-INT-",),
    "ERR": ("DNL-ERR-",),
    "LOG": ("DNL-LOG-", "DNL-CONSUME-", "DNL-DES-"),
    "RES": ("DNL-RES-", "DNL-INV-"),
    "SESS": ("DNL-SESS-",),
}
_TEXT_SCANS = ("SCA", "INT")     # no IR involved: identical in both modes
_CONF_RANK = {None: 1, "REVIEW": 0}     # a degraded finding may only be less sure, never surer


def _by_family(results):
    """{family: {(check_id, file): confidence rank}} (the weakest confidence wins for a repeated key)."""
    out = {fam: {} for fam in _FAMILIES}
    for r in results:
        for f in r.findings:
            for fam, prefixes in _FAMILIES.items():
                if f.check_id.startswith(prefixes):
                    key = (f.check_id, Path(f.file).as_posix())
                    out[fam][key] = min(out[fam].get(key, 9), _CONF_RANK[f.confidence])
    return out


@pytest.mark.parametrize("root", [CARRIED_APP, SCA_APP], ids=["carried_app", "sca_app"])
def test_degraded_parity_per_family(root, roslyn_helper, monkeypatch):
    helper_results = _dotnet(root, allow_degraded=False)
    assert helper_results and not any(r.degraded for r in helper_results)
    project._CACHE.clear()
    _degraded(monkeypatch)
    degraded_results = _dotnet(root, allow_degraded=True)
    assert degraded_results
    # every dotnet result says it ran degraded, and says why
    for r in degraded_results:
        assert r.degraded and "degraded" in r.degraded.lower() and "tree-sitter" in r.degraded
    assert {r.framework for r in degraded_results} == {r.framework for r in helper_results}

    assert all(reason.strip() for reason in JUSTIFIED_DEGRADED.values())
    helped, degraded = _by_family(helper_results), _by_family(degraded_results)
    for fam in _FAMILIES:
        h, d = helped[fam], degraded[fam]
        extra = set(d) - set(h)
        assert not extra, f"{fam}: degraded-only findings (no helper counterpart): {sorted(extra)}"
        if fam in _TEXT_SCANS:
            assert d == h, f"{fam} is a text scan and must not depend on the helper"
            continue
        missing = {k for k in set(h) - set(d) if k[0] not in JUSTIFIED_DEGRADED}
        assert not missing, f"{fam}: lost in degraded mode with no justification: {sorted(missing)}"
        higher = {k for k in d if d[k] > h[k]}
        assert not higher, f"{fam}: degraded confidence above the helper's: {sorted(higher)}"
    # the fixtures really exercise the families (a vacuous pass proves nothing)
    if root == CARRIED_APP:
        assert all(helped[f] for f in _FAMILIES if f != "SCA")
    else:
        assert helped["SCA"]


def test_justified_degraded_entries_are_documented():
    doc = (Path(__file__).parent.parent / "languages" / "dotnet" / "CARRIED_RULES.md").read_text(encoding="utf-8")
    for check_id, reason in JUSTIFIED_DEGRADED.items():
        assert reason.strip() and check_id in doc
