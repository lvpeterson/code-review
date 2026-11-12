"""Project model and IR loader for the legacy .NET analyzer (real helper)."""
from pathlib import Path

import pytest

from checks.dnl import helper, ir, project

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"


@pytest.fixture
def mvc_fixture():
    return FX / "mvc5_app"


@pytest.fixture(scope="module")
def model(roslyn_helper):
    project._CACHE.clear()
    return project.prepare(FX / "mvc5_app", False)


def test_projects_and_references(model):
    names = {p.name for p in model.projects}
    assert {"MvcApp", "MvcApp.Data", "(loose)"} <= names
    web = next(p for p in model.projects if p.name == "MvcApp")
    assert "system.web.mvc" in web.references and web.target_framework == "v4.7.2"
    assert any(p.name == "MvcApp.Data.csproj" for p in web.project_refs)


def test_case_mismatched_compile_include_resolves(model):
    web = next(p for p in model.projects if p.name == "MvcApp")
    assert any(f.name == "HomeController.cs" for f in web.compile_files)


def test_base_chain_through_project_types(model):
    home = model.find_types("homecontroller")[0]
    assert model.base_chain(home) == ["BaseController", "Controller"]
    assert model.derives_from(home, {"controller"})


def test_loose_file_parsed_and_project_of(model):
    assert "Scratch/Loose.cs" in model.files
    assert model.project_of("Scratch/Loose.cs").name == "(loose)"
    assert model.project_of("MvcApp/Controllers/HomeController.cs").name == "MvcApp"
    assert model.project_of("nope.cs") is None


def test_get_model_is_cached(model, mvc_fixture):
    assert project.get_model(mvc_fixture) is model


def test_degraded_model(monkeypatch, mvc_fixture):
    monkeypatch.setattr(helper, "preflight", lambda *a, **k: None)
    project._CACHE.clear()
    m = project.prepare(mvc_fixture, allow_degraded=True)
    assert m.files == {} and m.degraded == helper.DEGRADED_REASON


def test_base_chain_cycle_safe(tmp_path):
    def t(name, bases):
        return ir.TypeIR(name=name, namespace="", kind="class", modifiers=[], bases=bases,
                         attributes=[], fields=[], properties=[], methods=[], line=1, end_line=2, file="a.cs")
    fir = ir.FileIR("a.cs", "cs", "p", 0, [t("A", ["B"]), t("B", ["A"])])
    m = project.ProjectModel(tmp_path, [], {"a.cs": fir}, None, [])
    assert m.base_chain(fir.types[0]) == ["B", "A"]


def test_ir_helpers():
    expr = {"k": "call", "line": 1, "fn": {"k": "member", "name": "Add",
            "obj": {"k": "member", "name": "Filters", "obj": {"k": "name", "id": "config"}}},
            "args": [{"k": "lit", "v": "x", "t": "string"}]}
    assert ir.call_name(expr) == "Add"
    assert ir.call_name({"k": "call", "fn": {"k": "name", "id": "MapRoute"}}) == "MapRoute"
    assert ir.receiver_text(expr["fn"]["obj"]) == "config.Filters"
    assert ir.literal_str(expr["args"][0]) == "x" and ir.literal_str(expr) is None
    assert sum(1 for n in ir.walk(expr) if n["k"] == "member") == 2
    attrs = [ir.Attr("Authorize", [], {}, 1)]
    assert ir.has_attr(attrs, "authorize") is attrs[0] and ir.has_attr(attrs, "x") is None
    assert ir.load_file_ir({"path": "a.cs", "error": "boom"}) is None


def test_sdk_style_project_owns_its_sources_but_is_not_parsed(model):
    core = next(p for p in model.projects if p.name == "CoreSide")
    assert not core.is_legacy and any(f.name == "Program.cs" for f in core.compile_files)
    assert "CoreSide/Program.cs" not in model.files
    loose = [f.name for p in model.projects if p.name == "(loose)" for f in p.compile_files]
    assert "Program.cs" not in loose and "Loose.cs" in loose
    assert model.project_of("CoreSide/Program.cs").name == "CoreSide"


def test_base_chain_dedupes_case_insensitively(tmp_path):
    t = ir.TypeIR(name="A", namespace="", kind="class", modifiers=[], bases=["Base", "base"],
                  attributes=[], fields=[], properties=[], methods=[], line=1, end_line=2, file="a.cs")
    m = project.ProjectModel(tmp_path, [], {"a.cs": ir.FileIR("a.cs", "cs", "p", 0, [t])}, None, [])
    assert m.base_chain(t) == ["Base"]


def test_msbuild_escaped_include_resolves(tmp_path):
    # MSBuild writes `@` as %40 (and `;` as %3B, ...) in item specs.
    (tmp_path / "Content").mkdir()
    (tmp_path / "Content" / "logo@2x.png").write_bytes(b"")
    (tmp_path / "W.csproj").write_text(
        '<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">'
        '<ItemGroup><Content Include="Content\\logo%402x.png" /></ItemGroup></Project>')
    notes: list[str] = []
    (p,) = project.load_projects(tmp_path, notes)
    assert notes == [] and [f.name for f in p.content_files] == ["logo@2x.png"]


def test_vendor_build_dirs_are_scanned_but_bin_obj_are_not(tmp_path):
    from checks.dnl.files import iter_dnl_files
    for d in ("Vendor", "Build", "Dist", "Target", "bin", "obj", "packages", "Precompiled_x"):
        (tmp_path / d).mkdir()
    (tmp_path / "Vendor" / "Page.aspx").write_text("<%@ Page %>")
    (tmp_path / "Build" / "Web.config").write_text("<configuration/>")
    (tmp_path / "Dist" / "A.aspx").write_text("<%@ Page %>")
    (tmp_path / "Target" / "B.aspx").write_text("<%@ Page %>")
    for d in ("bin", "obj", "packages", "Precompiled_x"):
        (tmp_path / d / "Skip.aspx").write_text("<%@ Page %>")
    got = {p.relative_to(tmp_path).as_posix() for p in iter_dnl_files(tmp_path, (".aspx", ".config"))}
    assert got == {"Vendor/Page.aspx", "Build/Web.config", "Dist/A.aspx", "Target/B.aspx"}


def test_sdk_project_with_explicit_compile_claims_whole_dir(tmp_path):
    from checks.dnl import project
    (tmp_path / "S.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><Compile Include="a.cs" /></ItemGroup></Project>')
    (tmp_path / "a.cs").write_text("class A {}")
    (tmp_path / "b.cs").write_text("class B {}")
    projs = project.load_projects(tmp_path)
    assert [p.name for p in projs] == ["S"]
    assert {f.name for f in projs[0].compile_files} == {"a.cs", "b.cs"}
