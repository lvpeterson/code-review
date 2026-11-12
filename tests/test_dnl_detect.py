from pathlib import Path
from checks.dnl.files import iter_dnl_files, resolve_ci, read_source, is_legacy_project
from languages.dotnet_legacy import detector

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"

def test_walker_skips_packages_and_precompiled():
    # packages/ and PrecompiledWeb/ hold the only .aspx files; the project
    # files next to them are the positive control that the walk does descend.
    found = {p.name for p in iter_dnl_files(FX / "mvc5_app", (".aspx", ".csproj"))}
    assert not {n for n in found if n.endswith(".aspx")}
    assert {"MvcApp.csproj", "MvcApp.Data.csproj"} <= found


def test_walker_skip_rules_synthetic(tmp_path):
    for d in ("packages/P/content", "precompiledSite", "Site", ".vs", "node_modules/x"):
        (tmp_path / d).mkdir(parents=True)
        (tmp_path / d / "Page.aspx").write_text("x")
    found = [p.relative_to(tmp_path).as_posix() for p in iter_dnl_files(tmp_path, (".aspx",))]
    assert found == ["Site/Page.aspx"]

def test_resolve_ci_handles_backslashes_and_case():
    p = resolve_ci(FX / "mvc5_app" / "MvcApp", r"Controllers\homeController.cs")
    assert p is not None and p.name == "HomeController.cs"
    assert resolve_ci(FX / "mvc5_app", "nope\\x.cs") is None

def test_read_source_bom_and_cp1252(tmp_path):
    (tmp_path / "a.vb").write_bytes(b"\xef\xbb\xbfDim x = 1")
    (tmp_path / "b.vb").write_bytes(b'Dim s = "caf\xe9"')
    assert read_source(tmp_path / "a.vb") == "Dim x = 1"
    assert read_source(tmp_path / "b.vb") == 'Dim s = "café"'

def test_legacy_vs_sdk_projects():
    assert is_legacy_project((FX / "mvc5_app/MvcApp/MvcApp.csproj").read_text())
    assert not is_legacy_project((FX / "core_app/App.csproj").read_text())

def test_detector():
    assert detector.detect_frameworks(FX / "mvc5_app") == ["mvc", "webapi", "config"]
    assert not detector.detect_language(FX / "core_app")
