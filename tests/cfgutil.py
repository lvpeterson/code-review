"""Helpers for the ASP.NET Core configuration rule tests: write a tiny app, run the
`rules_pipeline` aggregator over it in helper or degraded (tree-sitter) mode.

Test modules import what they use, including the `mode` fixture:
`from cfgutil import mode, scan, ids  # noqa: F401`.
"""
from pathlib import Path

import pytest

from checks.dnl import helper, project, routes_core, rules_pipeline

CSPROJ = """<Project Sdk="{sdk}">
  <PropertyGroup>
    <TargetFramework>{tfm}</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
  </PropertyGroup>
</Project>
"""


def make_app(tmp_path: Path, files: dict[str, str], *, sdk: str = "Microsoft.NET.Sdk.Web",
             tfm: str = "net8.0") -> Path:
    """Write `App.csproj` (implicit usings on) and the given files (relative path -> text)."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "App.csproj").write_text(CSPROJ.format(sdk=sdk, tfm=tfm), encoding="utf-8")
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return tmp_path


def prepare_model(root: Path, degraded: bool = False):
    """The `dotnet` view of a freshly prepared model plus its route refs."""
    project._CACHE.clear()
    project.prepare(root, degraded)
    model = project.get_model(root, "dotnet")
    return model, routes_core.discover_all(model)


def run_check(root: Path, degraded: bool = False):
    model, refs = prepare_model(root, degraded)
    return rules_pipeline.check(model, refs)


@pytest.fixture(params=["helper", "degraded"])
def mode(request, monkeypatch):
    """Runs a test twice: with the Roslyn helper, and without it (tree-sitter IR)."""
    if request.param == "helper":
        request.getfixturevalue("roslyn_helper")
    else:
        monkeypatch.setattr(helper, "find_helper", lambda *a, **k: None)
        monkeypatch.setattr(helper, "sdk_available", lambda *a, **k: False)
    yield request.param
    project._CACHE.clear()


def scan(tmp_path: Path, files: dict[str, str], mode: str, **kw):
    """Findings of rules_pipeline.check over a synthetic app in the given mode."""
    return run_check(make_app(tmp_path, files, **kw), degraded=(mode == "degraded"))


def ids(findings) -> set[tuple]:
    """{(check_id, severity, confidence)} of a finding list."""
    return {(f.check_id, f.severity, f.confidence) for f in findings}
