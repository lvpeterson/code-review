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
