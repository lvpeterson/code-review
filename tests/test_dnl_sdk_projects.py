"""SDK-style project model: profiles, owner views, one helper run per scan."""
import shutil
from pathlib import Path

import pytest

import enumerator
from checks.dnl import helper, project
from checks.dnl.project import load_projects, profile_for
from languages.dotnet_legacy import detector

FX = Path(__file__).parent / "fixtures" / "aspnetcore" / "mixed_solution"


@pytest.fixture(autouse=True)
def _fresh_cache():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _by_name(projects, name):
    return next(p for p in projects if p.name == name)


def _rels(root, files):
    return {f.resolve().relative_to(root.resolve()).as_posix() for f in files}


def test_profile_for():
    for tfms in (["net8.0"], ["net8.0-windows"], ["netcoreapp3.1"], ["netstandard2.0"], ["net48", "net8.0"]):
        assert profile_for(tfms) == "netcore", tfms
    for tfms in (["net472"], ["net48"], ["net40"], []):
        assert profile_for(tfms) == "net48", tfms


def test_implicit_usings():
    base = project.implicit_usings("Microsoft.NET.Sdk")
    assert "System.Linq" in base and "Microsoft.AspNetCore.Http" not in base
    web = project.implicit_usings("Microsoft.NET.Sdk.Web")
    assert {"System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.Extensions.Logging"} <= set(web)
    worker = project.implicit_usings("Microsoft.NET.Sdk.Worker")
    assert "Microsoft.Extensions.Hosting" in worker and "Microsoft.AspNetCore.Http" not in worker
    assert project.implicit_usings(None) == []


def test_sdk_project_parsed():
    projects = load_projects(FX)
    modern = _by_name(projects, "Modern")
    assert modern.sdk == "Microsoft.NET.Sdk.Web"
    assert modern.target_frameworks == ["net8.0"]
    assert modern.packages == {"newtonsoft.json": "13.0.3", "serilog": "3.1.1"}
    assert modern.profile == "netcore" and modern.owner == "dotnet"
    assert "Microsoft.AspNetCore.Http" in modern.global_usings
    fw = _by_name(projects, "Framework")
    assert fw.profile == "net48" and fw.owner == "dotnet_legacy"
    assert "system.web.mvc" in fw.references
    legacy = _by_name(projects, "Legacy")
    assert legacy.profile == "net48" and legacy.owner == "dotnet_legacy" and not legacy.global_usings
    assert "mvc" in detector.detect_frameworks(FX)


def test_nested_project_owns_its_files():
    projects = load_projects(FX)
    modern = _by_name(projects, "Modern")
    tests = _by_name(projects, "Modern.Tests")
    assert "Modern/tests/Modern.Tests/PingTests.cs" in _rels(FX, tests.compile_files)
    assert "Modern/tests/Modern.Tests/PingTests.cs" not in _rels(FX, modern.compile_files)
    seen = [f.resolve() for p in projects for f in p.compile_files]
    assert len(seen) == len(set(seen))


def test_compile_remove_and_include(tmp_path):
    (tmp_path / "App" / "Generated").mkdir(parents=True)
    (tmp_path / "Shared").mkdir()
    (tmp_path / "App" / "Real.cs").write_text("class Real {}")
    (tmp_path / "App" / "Generated" / "Gen.cs").write_text("class Gen {}")
    (tmp_path / "Shared" / "Common.cs").write_text("class Common {}")
    (tmp_path / "App" / "App.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>'
        '<ItemGroup><Compile Remove="Generated\\**" /><Compile Include="..\\Shared\\Common.cs" /></ItemGroup></Project>')
    app = _by_name(load_projects(tmp_path), "App")
    rels = _rels(tmp_path, app.compile_files)
    assert "App/Real.cs" in rels and "Shared/Common.cs" in rels
    assert "App/Generated/Gen.cs" not in rels


def test_directory_build_props_tfm(tmp_path):
    (tmp_path / "src" / "App").mkdir(parents=True)
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework>"
        "<ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>")
    (tmp_path / "src" / "App" / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>')
    (tmp_path / "src" / "App" / "A.cs").write_text("class A {}")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == ["net8.0"] and app.profile == "netcore"
    assert "System.Linq" in app.global_usings


def test_no_tfm_sdk_project_is_netcore_with_note(tmp_path):
    (tmp_path / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"></Project>')
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.profile == "netcore" and any("TargetFramework" in n for n in notes)


def test_version_override_and_using_remove(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        '<Project><ItemGroup><PackageVersion Include="Foo" Version="1.0.0" />'
        '<PackageVersion Include="Bar" Version="2.0.0" /></ItemGroup></Project>')
    (tmp_path / "App.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        "<ImplicitUsings>true</ImplicitUsings></PropertyGroup><ItemGroup>"
        '<PackageReference Include="Foo" VersionOverride="1.5.0" /><PackageReference Include="Bar"><Version>2.5.0</Version></PackageReference>'
        '<Using Include="My.Extra" /><Using Remove="System.IO" /></ItemGroup></Project>')
    app = _by_name(load_projects(tmp_path), "App")
    assert app.packages == {"foo": "1.5.0", "bar": "2.5.0"}
    assert "My.Extra" in app.global_usings and "System.IO" not in app.global_usings


def test_request_carries_profiles():
    projects = load_projects(FX)
    req = project._request(projects)
    cs = [p for p in projects if p.language == "cs" and any(f.suffix == ".cs" for f in p.compile_files)]
    assert len(req) == len(cs)
    profiles = {p.name: p.profile for p in projects}
    for r in req:
        assert r["refs"] == profiles[r["name"]]
    modern = next(r for r in req if r["name"] == "Modern")
    assert "Microsoft.AspNetCore.Http" in modern["global_usings"]
    assert "global_usings" not in next(r for r in req if r["name"] == "Legacy")
    paths = [f for r in req for f in r["files"]]
    assert len(paths) == len(set(paths))


def test_loose_core_file_goes_to_dotnet(tmp_path):
    (tmp_path / "Program.cs").write_text("var app = WebApplication.CreateBuilder(args).Build();\n")
    (tmp_path / "Plain.cs").write_text("// WebApplication in a comment\nclass Plain {}\n")
    loose = [p for p in load_projects(tmp_path) if p.name == project.LOOSE]
    core = next(p for p in loose if p.profile == "netcore")
    old = next(p for p in loose if p.profile == "net48")
    assert [f.name for f in core.compile_files] == ["Program.cs"] and core.owner == "dotnet"
    assert [f.name for f in old.compile_files] == ["Plain.cs"] and old.owner == "dotnet_legacy"
    assert project.is_core_source("using Microsoft.AspNetCore.Mvc;\n")
    assert not project.is_core_source("/* ControllerBase */ class A {}")


def test_views_split_by_owner(roslyn_helper):
    project.prepare(FX, False)
    core = project.get_model(FX, "dotnet")
    old = project.get_model(FX, "dotnet_legacy")
    core_types = {t.name.split(".")[-1] for t in core.types()}
    old_types = {t.name.split(".")[-1] for t in old.types()}
    assert {"PingController", "Program"} <= core_types
    assert not core_types & {"HomeController", "OldController"}
    assert {"HomeController", "OldController"} <= old_types
    assert "PingController" not in old_types and "Program" not in old_types
    full = project.get_model(FX)
    assert core.parent is full and old.parent is full and full.view("dotnet") is core
    assert core.notes is full.notes and core.cache is not full.cache
    # Projects and files are filtered by owner, not just the types.
    assert {p.name for p in core.projects} >= {"Modern", "Modern.Tests"}
    assert not {p.name for p in core.projects} & {"Legacy", "Framework"}
    assert {p.name for p in old.projects} >= {"Legacy", "Framework"}
    assert not {p.name for p in old.projects} & {"Modern", "Modern.Tests"}
    assert all(not f.startswith("Modern/") for f in old.files) and old.files
    assert all(f.startswith("Modern/") for f in core.files) and core.files


def test_helper_runs_once_for_both_packages(roslyn_helper, monkeypatch):
    calls = []
    real = helper.parse_projects

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(helper, "parse_projects", counting)
    results = enumerator.enumerate_target(FX)
    assert len(calls) == 1
    # Both packages ran off that one preparation: each yields a ScanResult of its own.
    assert {r.language for r in results} >= {"dotnet", "dotnet_legacy"}
    assert any(r.language == "dotnet" and r.framework == "controllers" for r in results)
    assert any(r.language == "dotnet_legacy" and r.framework == "mvc" for r in results)
    assert project.get_model(FX, "dotnet").files and project.get_model(FX, "dotnet_legacy").files
    assert len(calls) == 1  # get_model reused the prepared model


def _legacy_keys(results, prefix=""):
    out = set()
    for r in results:
        if r.language != "dotnet_legacy":
            continue
        for f in r.findings:
            file = (f.file or "").replace("\\", "/")
            if file.startswith(prefix):
                out.add((f.check_id, file[len(prefix):], f.line))
    return out


def test_legacy_findings_unchanged_in_mixed_solution(roslyn_helper, tmp_path):
    shutil.copytree(FX / "Legacy", tmp_path / "Legacy")
    alone = _legacy_keys(enumerator.enumerate_target(tmp_path), "Legacy/")
    project._CACHE.clear()
    mixed = _legacy_keys(enumerator.enumerate_target(FX), "Legacy/")
    assert alone and mixed == alone


def test_core_project_side_files_never_reach_legacy(roslyn_helper, tmp_path):
    """A web.config, Razor view, bundled script, .aspx and packages.config inside a
    modern project are not analyzed by the legacy package."""
    root = tmp_path / "sol"
    shutil.copytree(FX, root)
    modern = root / "Modern"
    (modern / "wwwroot" / "lib").mkdir(parents=True, exist_ok=True)
    (modern / "Views").mkdir()
    (modern / "web.config").write_text(
        '<configuration><system.web><compilation debug="true" />'
        '<customErrors mode="Off" /></system.web></configuration>')
    (modern / "Views" / "Index.cshtml").write_text("@Html.Raw(Model.Name)")
    (modern / "wwwroot" / "lib" / "jquery-1.6.1.js").write_text("/*! jQuery JavaScript Library v1.6.1 */")
    (modern / "Page.aspx").write_text('<%@ Page Language="C#" %><html></html>')
    (modern / "packages.config").write_text(
        '<packages><package id="jQuery" version="1.6.1" targetFramework="net8.0" /></packages>')
    results = enumerator.enumerate_target(root)
    legacy = [r for r in results if r.language == "dotnet_legacy"]
    assert legacy
    files = [f.file.replace("\\", "/") for r in legacy for f in r.findings]
    files += [rt.file.replace("\\", "/") for r in legacy for rt in r.routes if getattr(rt, "file", None)]
    assert files and not [f for f in files if f.startswith("Modern/")], files
    view = project.get_model(root, "dotnet_legacy")
    assert not view.owns(modern / "web.config") and not view.owns(modern / "Page.aspx")
    assert project.get_model(root, "dotnet").owns(modern / "web.config")


def _sdk_csproj(d, body=""):
    d.mkdir(parents=True, exist_ok=True)
    (d / "App.csproj").write_text(f'<Project Sdk="Microsoft.NET.Sdk">{body}</Project>')
    (d / "A.cs").write_text("class A {}")


def test_tfm_from_directory_packages_props(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework>"
        "<ManagePackageVersionsCentrally>true</ManagePackageVersionsCentrally></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "src" / "App")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.target_frameworks == ["net6.0"] and app.profile == "netcore"
    assert not any("assuming modern" in n for n in notes)


def test_tfm_from_other_directory_props_nearest_wins(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup></Project>")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Directory.Packages.props").write_text(
        "<Project><PropertyGroup><TargetFrameworks>net7.0;net8.0</TargetFrameworks></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "src" / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == ["net7.0", "net8.0"]
    # the project file still overrides every props file
    _sdk_csproj(tmp_path / "src" / "App", "<PropertyGroup><TargetFramework>net9.0</TargetFramework></PropertyGroup>")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == ["net9.0"]


def test_tfm_from_imported_props_and_framework_override(tmp_path):
    (tmp_path / "build").mkdir()
    (tmp_path / "build" / "common.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net472</TargetFramework></PropertyGroup></Project>")
    (tmp_path / "Directory.Build.props").write_text('<Project><Import Project="build/common.props" /></Project>')
    _sdk_csproj(tmp_path / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == ["net472"] and app.profile == "net48"


def test_no_tfm_anywhere_keeps_note(tmp_path):
    (tmp_path / "Directory.Packages.props").write_text("<Project><PropertyGroup/></Project>")
    _sdk_csproj(tmp_path / "App")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.profile == "netcore" and any("assuming modern" in n for n in notes)
