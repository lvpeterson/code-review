"""ASP.NET Core SCA and carried-over rule families: golden legacy baselines and Core fixtures."""
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


def test_taint_flag_matches_wiring():
    from languages.dotnet import analyzers
    assert analyzers.CORE_RUNS_TAINT == hasattr(analyzers, "rules_taint"), (
        "CORE_RUNS_TAINT and the rules_taint wiring drifted: set the flag to True in the same change "
        "that imports and runs rules_taint in languages/dotnet/analyzers.py (and back), otherwise "
        "DESER-001 / XXE-001 on tainted lines are lost or doubled")
