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


def test_conditional_tfms_are_a_union(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup Condition=\"'$(A)' == 'x'\"><TargetFramework>net6.0</TargetFramework></PropertyGroup>"
        "<PropertyGroup Condition=\"'$(A)' != 'x'\"><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert sorted(app.target_frameworks) == ["net6.0", "net8.0"]


def test_unresolved_tfm_value_adds_a_note(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>$(DefaultTfm)</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.target_frameworks == []
    assert any("Directory.Build.props" in n and "$(DefaultTfm)" in n for n in notes)


def test_tfm_property_reference_resolves_from_earlier_props(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><DefaultTfm>net7.0</DefaultTfm>"
        "<TargetFramework>$(DefaultTfm)</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.target_frameworks == ["net7.0"]


def test_nearer_non_chaining_build_props_hides_parent(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup></Project>")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "src" / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == []


@pytest.mark.parametrize("imp", [
    "$([MSBuild]::GetPathOfFileAbove('Directory.Build.props', '$(MSBuildThisFileDirectory)../'))",
    "../Directory.Build.props",
])
def test_chaining_build_props_inherits_parent(tmp_path, imp):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net6.0</TargetFramework></PropertyGroup></Project>")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "Directory.Build.props").write_text(
        f'<Project><Import Project="{imp}" /><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>')
    _sdk_csproj(tmp_path / "src" / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.target_frameworks == ["net6.0"]


def test_test_project_detection(tmp_path):
    for name in ("MyUnitTests", "Shop.Test", "Latest", "Web"):
        _sdk_csproj_named(tmp_path / "src" / name, name)
    (tmp_path / "src" / "Web" / "Controllers" / "Test").mkdir(parents=True)
    (tmp_path / "src" / "Web" / "Controllers" / "Test" / "B.cs").write_text("class B {}")
    model = project.ProjectModel(tmp_path.resolve(), load_projects(tmp_path), {}, "x")
    assert model.is_core_test_file("src/MyUnitTests/A.cs")
    assert model.is_core_test_file("src/Shop.Test/A.cs")
    assert not model.is_core_test_file("src/Latest/A.cs")
    assert not model.is_core_test_file("src/Web/A.cs")
    assert not model.is_core_test_file("src/Web/Controllers/Test/B.cs")


def _sdk_csproj_named(d, name):
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>')
    (d / "A.cs").write_text("class A {}")


def test_conditional_tfm_does_not_move_a_project_between_packages(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup>"
        "<PropertyGroup Condition=\"'$(UseModern)' == 'true'\"><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.owner == "dotnet_legacy" and app.profile == "net48"
    # the conditional framework is still reported
    assert app.target_frameworks == ["net48", "net8.0"]


def test_unconditional_modern_tfm_with_conditional_old_one_stays_core(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>"
        "<PropertyGroup Condition=\"'$(Old)' == 'true'\"><TargetFramework>net472</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.owner == "dotnet" and app.target_frameworks == ["net8.0", "net472"]


def test_conditional_only_csproj_tfm_does_not_override_unconditional_props(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App", "<PropertyGroup Condition=\"'$(Old)' == 'true'\">"
                                  "<TargetFramework>net48</TargetFramework></PropertyGroup>")
    app = _by_name(load_projects(tmp_path), "App")
    assert app.owner == "dotnet" and app.profile == "netcore"
    assert app.target_frameworks == ["net8.0", "net48"]


def test_only_conditional_tfms_keep_old_owner_and_add_a_note(tmp_path):
    _sdk_csproj(tmp_path / "App", "<PropertyGroup Condition=\"'$(X)' == 'a'\"><TargetFramework>net48</TargetFramework></PropertyGroup>")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.owner == "dotnet_legacy"
    assert any("App.csproj" in n and "Condition" in n for n in notes)


def test_unresolved_unconditional_tfm_does_not_hide_a_farther_one(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        "<Project><PropertyGroup><TargetFramework>net48</TargetFramework></PropertyGroup></Project>")
    _sdk_csproj(tmp_path / "App", "<PropertyGroup><TargetFramework>$(Nope)</TargetFramework></PropertyGroup>")
    notes: list[str] = []
    app = _by_name(load_projects(tmp_path, notes), "App")
    assert app.owner == "dotnet_legacy" and app.target_frameworks == ["net48"]
    assert any("App.csproj" in n and "$(Nope)" in n for n in notes)
    assert not any("no TargetFramework found" in n for n in notes)


# -- multi-targeted SDK projects (net4x + modern): analysed under both profiles ----------------

MT = Path(__file__).parent / "fixtures" / "aspnetcore" / "multi_target"


def test_multi_target_profile_set_and_views():
    projects = load_projects(MT)
    multi, s48, s80 = _by_name(projects, "Multi"), _by_name(projects, "Single48"), _by_name(projects, "Single80")
    assert multi.profiles == {"net48", "netcore"}
    # profile / owner stay deterministic single values for code that expects one.
    assert multi.profile == "netcore" and multi.owner == "dotnet"
    assert multi.owners == {"dotnet", "dotnet_legacy"}
    assert s48.profiles == {"net48"} and s48.owners == {"dotnet_legacy"}
    assert s80.profiles == {"netcore"} and s80.owners == {"dotnet"}
    # a multi-target project's references carry the net48 build's MVC assembly names
    assert "system.web.mvc" in multi.references
    rels = {f.name: f for f in multi.compile_files}
    model = project.ProjectModel(MT, projects, {})
    model.projects = projects
    old, core = model.view("dotnet_legacy"), model.view("dotnet")
    assert {p.name for p in old.projects} == {"Multi", "Single48", "Dual", "MultiVb"}
    assert {p.name for p in core.projects} == {"Multi", "Single80", "Dual", "Gated", "MultiVb"}
    rel = model.rel(rels["Program.cs"])
    assert old.is_core_file(rel) is False and core.is_core_file(rel) is True
    assert core.core_project(multi) and not old.core_project(multi)
    assert old.owns(rels["Program.cs"]) and core.owns(rels["Program.cs"])
    s48_rel = model.rel(_by_name(projects, "Single48").compile_files[0])
    assert old.owns(MT / "Single48" / "Controllers" / "OrdersController.cs") and not core.owns(MT / "Single48" / "Controllers" / "OrdersController.cs")
    assert not old.is_core_file(s48_rel) and not core.is_core_file(s48_rel)


def test_multi_target_request_has_one_entry_per_profile():
    req = project._request(load_projects(MT))
    by = {r["name"]: r for r in req}
    assert by["Multi"]["refs"] == "netcore" and "global_usings" in by["Multi"]
    alt = by["Multi" + project.ALT_SUFFIX]
    assert alt["refs"] == "net48" and "global_usings" not in alt
    assert alt["files"] == by["Multi"]["files"]
    assert by["Single48"]["refs"] == "net48" and by["Single80"]["refs"] == "netcore"
    assert {n for n in by if n.endswith(project.ALT_SUFFIX)} == {
        "Multi" + project.ALT_SUFFIX, "Dual" + project.ALT_SUFFIX, "MultiVb" + project.ALT_SUFFIX}


def _mt_keys(results, language):
    return [(f.check_id, (f.file or "").replace("\\", "/"), f.line)
            for r in results if r.language == language for f in r.findings]


def _check_multi_target_scan():
    results = enumerator.enumerate_target(MT)
    legacy, core = _mt_keys(results, "dotnet_legacy"), _mt_keys(results, "dotnet")
    # no double-reporting inside a package
    assert len(legacy) == len(set(legacy)) and len(core) == len(set(core))
    # the legacy package sees the net48 build's controller, and the single-target legacy project
    assert any(f.startswith("Multi/Controllers/AccountController.cs") for _, f, _ in legacy), legacy
    assert any(f.startswith("Single48/") for _, f, _ in legacy), legacy
    # the Core package sees the minimal API of the net8.0 build, and the single-target Core project
    assert any(f == "Multi/Program.cs" for _, f, _ in core), core
    assert any(f.startswith("Single80/") for _, f, _ in core), core
    # single-target projects stay with their own package only
    assert not any(f.startswith("Single80/") for _, f, _ in legacy)
    assert not any(f.startswith("Single48/") for _, f, _ in core)
    # a rule both packages share reports the shared file once per package
    shared_l = [k for k in legacy if k[1] == "Multi/Util/Hashing.cs"]
    shared_c = [k for k in core if k[1] == "Multi/Util/Hashing.cs"]
    assert shared_l and shared_c and len(shared_l) == len(set(shared_l)) and len(shared_c) == len(set(shared_c))
    # Core's controllers of the net48-only file are not reported by Core as a Core controller route
    return legacy, core


def test_multi_target_both_packages_helper(roslyn_helper):
    _check_multi_target_scan()
    full = project.get_model(MT)
    old, core = full.view("dotnet_legacy"), full.view("dotnet")
    assert set(old.files) >= {"Multi/Program.cs", "Single48/Controllers/OrdersController.cs"}
    assert set(core.files) >= {"Multi/Program.cs", "Single80/Program.cs"}
    # each view holds the FileIR parsed under its own profile; project name is the real one
    assert old.files["Multi/Program.cs"] is not core.files["Multi/Program.cs"]
    assert old.files["Multi/Program.cs"].project == "Multi" == core.files["Multi/Program.cs"].project


def test_multi_target_both_packages_degraded(monkeypatch):
    monkeypatch.setattr(helper, "preflight", lambda target, allow_degraded: None)
    _check_multi_target_scan()
    old, core = project.get_model(MT, "dotnet_legacy"), project.get_model(MT, "dotnet")
    assert old.files["Multi/Program.cs"] is core.files["Multi/Program.cs"]
    assert any("multi-target" in n.lower() for n in old.notes)


# -- round 1: VB multi-target, preprocessor symbols, alt-IR fallback note, per-view rule -----------

def test_symbols_for_tfm():
    s = project.symbols_for_tfm("net48")
    assert {"NETFRAMEWORK", "NET48", "NET48_OR_GREATER", "NET472_OR_GREATER", "NET20_OR_GREATER"} <= s
    assert "NET481_OR_GREATER" not in s and "NET" not in s and "NETCOREAPP" not in s
    s472 = project.symbols_for_tfm("net472")
    assert "NET472_OR_GREATER" in s472 and "NET48_OR_GREATER" not in s472
    m = project.symbols_for_tfm("net8.0-windows")
    assert {"NETCOREAPP", "NET", "NET8_0", "NET8_0_OR_GREATER", "NET5_0_OR_GREATER", "NETCOREAPP3_1_OR_GREATER",
            "NETCOREAPP1_0_OR_GREATER"} <= m
    assert "NET9_0_OR_GREATER" not in m and "NETFRAMEWORK" not in m
    c = project.symbols_for_tfm("netcoreapp3.1")
    assert "NETCOREAPP3_1" in c and "NETCOREAPP2_1_OR_GREATER" in c and "NET" not in c
    n = project.symbols_for_tfm("netstandard2.0")
    assert {"NETSTANDARD", "NETSTANDARD2_0", "NETSTANDARD2_0_OR_GREATER", "NETSTANDARD1_6_OR_GREATER"} <= n
    assert "NETSTANDARD2_1_OR_GREATER" not in n and "NET" not in n


def test_project_defines_per_profile():
    projects = load_projects(MT)
    dual, gated = _by_name(projects, "Dual"), _by_name(projects, "Gated")
    legacy, core = set(dual.defines("net48")), set(dual.defines("netcore"))
    assert {"NETFRAMEWORK", "NET48", "TRACE", "CUSTOM_FLAG"} <= legacy and "NET8_0_OR_GREATER" not in legacy
    assert {"NET8_0", "NET8_0_OR_GREATER", "TRACE", "CUSTOM_FLAG"} <= core and "NETFRAMEWORK" not in core
    # conditional property groups are ignored; `$(...)` references are dropped
    assert "DEBUG_ONLY" not in legacy | core and "DEBUG" not in legacy | core
    assert not any("$(" in d for d in legacy | core)
    assert "NET8_0_OR_GREATER" in gated.defines("netcore")
    by = {r["name"]: r for r in project._request(projects)}
    assert "NETFRAMEWORK" in by["Dual" + project.ALT_SUFFIX]["defines"]
    assert "NET8_0_OR_GREATER" in by["Dual"]["defines"] and "NETFRAMEWORK" not in by["Dual"]["defines"]


def test_vb_multi_target_requests_only_net48_entry():
    projects = load_projects(MT)
    vb = _by_name(projects, "MultiVb")
    assert vb.multi and vb.language == "vb"
    names = [r["name"] for r in project._request(projects)]
    assert "MultiVb" + project.ALT_SUFFIX in names and "MultiVb" not in names


def test_vb_multi_target_no_modern_vb_note():
    notes: list[str] = []
    load_projects(MT, notes)
    assert not any("Visual Basic on modern" in n and "MultiVb" in n for n in notes), notes


def _vb_multi_check():
    results = enumerator.enumerate_target(MT)
    legacy = [k for k in _mt_keys(results, "dotnet_legacy") if k[1].startswith("MultiVb/")]
    assert legacy, "legacy package must scan the multi-target VB project"
    # (project-file findings such as end-of-support are reported per package; VB code is legacy-only)
    assert not [k for k in _mt_keys(results, "dotnet") if k[1].startswith("MultiVb/") and k[1].endswith(".vb")]
    core = project.get_model(MT, "dotnet")
    assert not [f for f in list(core.files) + list(core.vb_files) if f.startswith("MultiVb/")]


def test_vb_multi_target_scanned_by_legacy_helper(roslyn_helper):
    _vb_multi_check()


def test_vb_multi_target_scanned_by_legacy_degraded(monkeypatch):
    monkeypatch.setattr(helper, "preflight", lambda target, allow_degraded: None)
    _vb_multi_check()


def test_preprocessor_branches_split_by_view(roslyn_helper):
    results = enumerator.enumerate_target(MT)
    old, core = project.get_model(MT, "dotnet_legacy"), project.get_model(MT, "dotnet")
    old_types = {t.name.split(".")[-1] for f in old.files.values() if f.path == "Dual/Branch.cs" for t in f.types}
    core_types = {t.name.split(".")[-1] for f in core.files.values() if f.path == "Dual/Branch.cs" for t in f.types}
    assert old_types == {"FrameworkBranchController"}, old_types
    assert core_types == {"CoreBranch"}, core_types
    assert any(f.startswith("Dual/Branch.cs") for _, f, _ in _mt_keys(results, "dotnet_legacy"))
    assert any(f.startswith("Dual/Branch.cs") for _, f, _ in _mt_keys(results, "dotnet"))


def test_single_target_core_if_net8_or_greater(roslyn_helper):
    results = enumerator.enumerate_target(MT)
    assert any(f == "Gated/Program.cs" for _, f, _ in _mt_keys(results, "dotnet"))


def test_missing_alt_ir_is_noted(roslyn_helper, monkeypatch):
    real = helper.parse_projects

    def drop_alt(binary, root, projects, **k):
        out = real(binary, root, projects, **k)
        return [o for o in out if not (str(o.get("project", "")).endswith(project.ALT_SUFFIX)
                                       and o.get("path") == "Multi/Util/Hashing.cs")]

    monkeypatch.setattr(helper, "parse_projects", drop_alt)
    model = project.prepare(MT, False)
    assert any("Multi/Util/Hashing.cs" in n and "net48" in n for n in model.notes), model.notes


def test_core_gated_rule_differs_per_view(roslyn_helper):
    results = enumerator.enumerate_target(MT)

    def sec3(lang):
        return [f for r in results if r.language == lang for f in r.findings
                if f.check_id == "DNL-SEC-003" and (f.file or "").replace("\\", "/") == "Multi/Util/Creds.cs"]

    legacy, core = sec3("dotnet_legacy"), sec3("dotnet")
    assert len(legacy) == 1 and len(core) == 1
    assert legacy[0].severity.lower() == "high" and core[0].severity.lower() == "low"


# -- round 2 ------------------------------------------------------------------------------------

def test_symbols_platform_suffix_and_classic_version():
    s = project.symbols_for_tfm("net6.0-windows10.0.19041")
    assert "WINDOWS" in s and "NET6_0" in s and "ANDROID" not in s
    for tfm, sym in (("net8.0-android", "ANDROID"), ("net8.0-ios17.0", "IOS"), ("net8.0-maccatalyst", "MACCATALYST"),
                     ("net8.0-macos", "MACOS"), ("net8.0-tvos", "TVOS"), ("net8.0-browser", "BROWSER")):
        assert sym in project.symbols_for_tfm(tfm), tfm
    assert "WINDOWS" not in project.symbols_for_tfm("net8.0")
    c = project.symbols_for_tfm("v4.7.2")
    assert {"NETFRAMEWORK", "NET472", "NET472_OR_GREATER", "NET462_OR_GREATER"} <= c
    assert "NET48_OR_GREATER" not in c
    assert "NET403_OR_GREATER" not in project.symbols_for_tfm("net48")


def test_dropped_moniker_if_branch_is_noted(tmp_path):
    d = tmp_path / "App"
    d.mkdir()
    (d / "App.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                                  '<TargetFrameworks>net6.0;net8.0</TargetFrameworks></PropertyGroup></Project>')
    (d / "Compat.cs").write_text("class C {\n#if NET6_0\n void Old() {}\n#elif NET8_0_OR_GREATER\n void New() {}\n#endif\n}\n")
    (d / "Plain.cs").write_text("class P {\n#if NET8_0_OR_GREATER\n void New() {}\n#endif\n}\n")
    notes: list[str] = []
    load_projects(tmp_path, notes)
    hit = [n for n in notes if "App/Compat.cs" in n]
    assert len(hit) == 1 and "NET6_0" in hit[0] and "net8.0" in hit[0], notes
    assert not any("Plain.cs" in n for n in notes)


def test_multi_vb_project_keeps_core_project_file_findings():
    # DNL-SCA-003 on the net8.0 moniker of the multi-target VB project is Core's: the project stays in
    # the Core view's projects although its VB sources are excluded.
    results = enumerator.enumerate_target(MT)
    assert ("DNL-SCA-003", "MultiVb/MultiVb.vbproj", 3) in set(_mt_keys(results, "dotnet"))
