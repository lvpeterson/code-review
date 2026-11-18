"""appsettings*.json / launchSettings.json reader: flattening, lines, tolerant JSON, env overrides."""
from pathlib import Path

import pytest

from cfgutil import make_app, prepare_model

from checks.dnl.appsettings import load_settings
from checks.dnl.cfgctx import build_ctx

LEGACY_CSPROJ = """<Project ToolsVersion="15.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>
</Project>
"""


def _settings(tmp_path: Path, files: dict[str, str]):
    model, _ = prepare_model(make_app(tmp_path, files), degraded=True)
    return model, load_settings(model)


def test_flatten_nested_objects_and_arrays_with_lines(tmp_path):
    base = '{\n  "Jwt": {\n    "Issuer": "x",\n    "Key": "k"\n  },\n  "Hosts": [\n    "a",\n    "b"\n  ],\n  "N": 5, "F": 1.5, "B": true, "Z": null\n}\n'
    _, s = _settings(tmp_path, {"appsettings.json": base})
    by = {e.key: e for e in s.entries()}
    assert by["Jwt:Key"].line == 4 and by["Jwt:Key"].value == "k"
    assert by["Jwt:Key"].file == "appsettings.json" and by["Jwt:Key"].env is None
    assert by["Hosts:0"].line == 7 and by["Hosts:1"].value == "b"
    assert by["N"].value == 5 and by["F"].value == 1.5 and by["B"].value is True and by["Z"].value is None


def test_comments_trailing_commas_bom_duplicates(tmp_path):
    text = '\ufeff{\n  // line comment\n  "A": 1, /* block\n  comment */\n  "B": {"C": "x",},\n  "a": 2,\n}\n'
    _, s = _settings(tmp_path, {"appsettings.json": text})
    assert not any(f.error for f in s.files)
    eff = s.effective("Production")
    assert eff["a"].value == 2          # duplicate keys, case-insensitive: last wins
    assert eff["b:c"].line == 5


def test_effective_env_override_and_case(tmp_path):
    files = {"appsettings.json": '{"Jwt": {"Key": "base"}, "Only": 1}',
             "appsettings.Production.json": '{"jwt": {"key": "prod"}}',
             "appsettings.Development.json": '{"Jwt": {"Key": "dev"}}'}
    _, s = _settings(tmp_path, files)
    prod = s.effective("Production")
    assert prod["jwt:key"].value == "prod" and prod["jwt:key"].env == "Production"
    assert prod["only"].value == 1
    assert s.effective("Development")["jwt:key"].value == "dev"
    assert s.effective("Staging")["jwt:key"].value == "base"
    assert [e.value for e in s.entries("Production")] == ["prod"]


def test_malformed_file_is_error_and_note_others_load(tmp_path):
    files = {"appsettings.json": '{"A": 1}', "appsettings.Development.json": '{"A": ,}'}
    model, s = _settings(tmp_path, files)
    bad = next(f for f in s.files if f.env == "Development")
    assert bad.error and "appsettings.Development.json" in bad.error
    assert any("appsettings.Development.json" in n for n in model.notes)
    assert s.effective("Production")["a"].value == 1


def test_non_object_and_garbage_never_raise(tmp_path):
    files = {"appsettings.json": "[1, 2]", "appsettings.A.json": "", "appsettings.B.json": '{"x": "unterminated',
             "appsettings.C.json": "[" * 5000}
    model, s = _settings(tmp_path, files)
    assert len(s.files) == 4 and all(f.error for f in s.files)
    assert len(model.notes) >= 4


def test_launch_settings_environment_variables(tmp_path):
    ls = '{"profiles": {"Dev": {"commandName": "Project", "environmentVariables": {"Db__Password": "x", "ASPNETCORE_ENVIRONMENT": "Development"}}}}'
    _, s = _settings(tmp_path, {"Properties/launchSettings.json": ls})
    e = next(e for e in s.entries("launch") if e.key == "Db:Password")
    assert e.value == "x" and e.env == "launch" and e.file == "Properties/launchSettings.json"
    assert s.entries() == []            # launch entries never leak into the base files


def test_bin_obj_wwwroot_ignored(tmp_path):
    files = {"bin/appsettings.json": "{}", "obj/appsettings.json": "{}", "wwwroot/appsettings.json": "{}",
             "appsettings.json": '{"A": 1}'}
    _, s = _settings(tmp_path, files)
    assert [f.path for f in s.files] == ["appsettings.json"]


def test_file_owned_by_other_view_is_skipped(tmp_path):
    files = {"appsettings.json": '{"A": 1}', "Old/Old.csproj": LEGACY_CSPROJ, "Old/appsettings.json": '{"B": 1}'}
    root = make_app(tmp_path, files)
    model, _ = prepare_model(root, degraded=True)
    assert [f.path for f in load_settings(model).files] == ["appsettings.json"]


def test_build_ctx_fills_settings_once(tmp_path):
    model, refs = prepare_model(make_app(tmp_path, {"appsettings.json": '{"A": 1}'}), degraded=True)
    ctx = build_ctx(model, refs)
    assert ctx.settings is not None and ctx.settings.effective("Production")["a"].value == 1
    assert build_ctx(model, refs).settings is ctx.settings


def test_effective_is_scoped_per_directory(tmp_path):
    files = {"A/appsettings.json": '{"Jwt": {"Key": "weak"}}',
             "B/appsettings.json": '{"Jwt": {"Key": "other"}}',
             "B/appsettings.Production.json": '{"Jwt": {"Key": "strong"}}'}
    _, s = _settings(tmp_path, files)
    assert s.scopes() == ["A", "B"]
    assert s.effective("Production", "A")["jwt:key"].value == "weak"     # not masked by B's Production file
    assert s.effective("Production", "B")["jwt:key"].value == "strong"
    assert s.effective("Development", "B")["jwt:key"].value == "other"   # two bases stay distinct
    assert [e.value for e in s.entries(None, "A")] == ["weak"]
    with pytest.raises(ValueError):
        s.effective("Production")


def test_unscoped_effective_single_directory_and_launch_scope(tmp_path):
    ls = '{"profiles": {"P": {"environmentVariables": {"A__B": "1"}}}}'
    _, s = _settings(tmp_path, {"appsettings.json": '{"A": 1}', "Properties/launchSettings.json": ls})
    assert s.scopes() == [""]                      # launchSettings does not add a scope
    assert s.effective("Production")["a"].value == 1
    assert s.effective("Production", "")["a"].value == 1
    assert [e.key for e in s.entries("launch", "")] == ["A:B"]


# -- final fix wave: hostile settings files are not read ------------------------------------------------------


def test_oversized_settings_file_is_skipped_with_a_note(tmp_path):
    big = '{"A": "' + "x" * (5 * 1024 * 1024 + 10) + '"}'
    model, s = _settings(tmp_path, {"appsettings.json": big, "appsettings.Production.json": '{"B": 1}'})
    assert [f.path for f in s.files] == ["appsettings.Production.json"]
    assert any("appsettings.json" in n and "larger than 5 MB" in n for n in model.notes)


def test_symlinked_settings_file_is_skipped_with_a_note(tmp_path):
    root = make_app(tmp_path, {"appsettings.Production.json": '{"B": 1}'})
    try:
        (root / "appsettings.json").symlink_to("/dev/zero")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available here")
    model, _ = prepare_model(root, degraded=True)
    s = load_settings(model)
    assert [f.path for f in s.files] == ["appsettings.Production.json"]
    assert any("appsettings.json" in n and "symbolic link" in n for n in model.notes)
