"""Offline SCA for SDK-style / ASP.NET Core projects (rules_sca_core) and the data it reads."""
import datetime
import json
import re
import shutil
from pathlib import Path

import pytest

from checks.dnl import project, rules_sca, rules_sca_core
from core.owasp_web import RULES

# The end-of-support comparison reads the run date; pin it so these tests do not shift with the calendar.
pytestmark = pytest.mark.usefixtures("pinned_today")

FX = Path(__file__).parent / "fixtures" / "aspnetcore" / "sca_app"
DATA = Path(__file__).resolve().parent.parent / "checks" / "dnl" / "data" / "dnl_advisories.json"
TODAY = datetime.date(2026, 11, 16)


@pytest.fixture(autouse=True)
def _fresh():
    project._CACHE.clear()
    yield
    project._CACHE.clear()


def _model(root: Path) -> project.ProjectModel:
    return project.ProjectModel(root.resolve(), project.load_projects(root.resolve()), {}, "no helper")


def _run(root: Path = FX, today=TODAY):
    return rules_sca_core.check(_model(root), today=today)


def _by(findings, cid):
    return [f for f in findings if f.check_id == cid]


def _line(rel: str, needle: str) -> int:
    for n, text in enumerate((FX / rel).read_text(encoding="utf-8").splitlines(), 1):
        if needle in text:
            return n
    raise AssertionError(needle)


def _pkg(findings, name: str):
    return [f for f in _by(findings, "DNL-SCA-001") if f"package {name} " in f.title or f" {name} " in f.title]


# -- PackageReference versions (SCA-001) -----------------------------------

def test_vulnerable_package_direct():
    findings, _ = _run()
    hits = _pkg(findings, "System.Text.RegularExpressions")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "high" and f.file == "App.csproj"
    assert f.line == _line("App.csproj", 'Include="System.Text.RegularExpressions"')
    assert "GHSA-cmhx-cq75-c4mj" in f.description


def test_central_version_used():
    findings, _ = _run()
    hits = _pkg(findings, "System.Text.Json")
    assert len(hits) == 1
    f = hits[0]
    assert f.severity == "high" and f.file == "App.csproj"
    assert f.line == _line("App.csproj", 'Include="System.Text.Json"')
    assert "8.0.0" in f.title                       # the central version, not an empty one
    assert "Directory.Packages.props" in f.description


def test_version_override_wins():
    findings, _ = _run()
    hits = _pkg(findings, "Microsoft.Data.SqlClient")
    # Central 5.1.3 is fixed, the VersionOverride 4.0.1 is inside >=4.0.0 <4.0.5.
    assert len(hits) == 1
    assert "4.0.1" in hits[0].title and hits[0].file == "App.csproj"
    assert hits[0].line == _line("App.csproj", 'Include="Microsoft.Data.SqlClient"')


def test_fixed_package_clean():
    findings, _ = _run()
    assert not _pkg(findings, "Newtonsoft.Json")


def test_unresolved_versions_are_review():
    findings, _ = _run()
    rev = _by(findings, "DNL-SCA-006")
    assert len(rev) == 3
    assert all(f.confidence == "REVIEW" and f.severity == "low" for f in rev)
    assert {f.line for f in rev} == {_line("App.csproj", 'Include="Serilog"'),
                                     _line("App.csproj", 'Include="Serilog.Sinks.Console"'),
                                     _line("App.csproj", 'Include="Serilog.Extensions.Logging"')}
    kes = _pkg(findings, "Microsoft.AspNetCore.Server.Kestrel.Core")
    assert len(kes) == 1 and "range lower bound" in kes[0].description
    assert kes[0].line == _line("App.csproj", "Kestrel.Core")


@pytest.mark.parametrize("spec,want", [
    ("1.2.3", ("1.2.3", "exact")),
    (" [1.2.3] ", ("1.2.3", "exact")),
    ("[2.0.0,3.0.0)", ("2.0.0", "range-lower")),
    ("[2.0.0,]", ("2.0.0", "range-lower")),
    ("(2.0.0,3.0.0)", ("2.0.0", "range-lower")),
    ("[1.0, 2.0)", ("1.0", "range-lower")),
    ("1.*", (None, "unresolved")),
    ("$(JsonVer)", (None, "unresolved")),
    ("", (None, "unresolved")),
    ("(,3.0.0)", (None, "unresolved")),            # no lower bound: nothing to restore
    ("[latest,3.0)", (None, "unresolved")),
])
def test_resolved_version(spec, want):
    assert rules_sca_core.resolved_version(spec) == want


# -- packages.lock.json ----------------------------------------------------

def test_lock_file_transitive():
    findings, _ = _run()
    hits = _pkg(findings, "System.Net.Http")
    assert len(hits) == 1                           # listed under both TFMs, reported once
    f = hits[0]
    assert f.file == "packages.lock.json" and "transitive" in f.description.lower()
    assert "GHSA-7jgj-8wvc-jh57" in f.description
    assert f.line == _line("packages.lock.json", '"System.Net.Http"')


def test_lock_file_wins_over_csproj():
    findings, _ = _run()
    # csproj says 6.10.0 (vulnerable) but the lock resolved 6.34.0 (fixed).
    assert not _pkg(findings, "System.IdentityModel.Tokens.Jwt")
    # vulnerable in both -> one finding, anchored on the PackageReference
    assert len(_pkg(findings, "System.Text.RegularExpressions")) == 1


def test_lock_file_malformed_is_a_note(tmp_path):
    root = tmp_path / "app"
    shutil.copytree(FX, root, ignore=shutil.ignore_patterns("bin"))
    (root / "packages.lock.json").write_text("{not json", encoding="utf-8")
    findings, notes = _run(root)
    assert any("packages.lock.json" in n for n in notes)
    # Without the lock the csproj versions are used again.
    assert _pkg(findings, "System.IdentityModel.Tokens.Jwt")
    (root / "packages.lock.json").write_text('{"version": 9, "dependencies": {}}', encoding="utf-8")
    _f, notes = _run(root)
    assert any("packages.lock.json" in n and "version" in n for n in notes)


# -- end of support (SCA-003) ----------------------------------------------

def test_eol_tfm():
    findings, notes = _run(today=TODAY)
    eol = _by(findings, "DNL-SCA-003")
    by_tfm = {tfm: f for tfm in ("net6.0", "net8.0") for f in eol if f" {tfm} " in f.title}
    assert set(by_tfm) == {"net6.0", "net8.0"}       # net8.0 ended 2026-11-10
    f = by_tfm["net6.0"]
    assert f.severity == "medium" and f.file == "App.csproj"
    assert "2024-11-12" in f.description and "https://dotnet.microsoft.com" in f.description
    assert f.line == _line("App.csproj", "<TargetFrameworks>")
    assert any("2026-11-16" in n for n in notes)     # eol_as_of is stated


def test_eol_future_tfm_not_flagged():
    findings, _ = _run(today=datetime.date(2025, 6, 1))
    tfms = [f.title for f in _by(findings, "DNL-SCA-003")]
    assert len(tfms) == 1 and "net6.0" in tfms[0]    # net8.0 is supported until 2026-11-10


def test_eol_uses_injected_today():
    findings, _ = _run(today=datetime.date(2020, 1, 1))
    assert not _by(findings, "DNL-SCA-003")


def test_default_clock_is_the_pinned_one(pinned_today, monkeypatch):
    # No `today` argument: both entry points read rules_sca_core._today(), which the fixture pins.
    assert rules_sca_core.eol_tfms() == rules_sca_core.eol_tfms(pinned_today)
    findings, _ = rules_sca_core.check(_model(FX))
    assert {f.title for f in _by(findings, "DNL-SCA-003")} == {f.title for f in _by(_run()[0], "DNL-SCA-003")}
    monkeypatch.setattr(rules_sca_core, "_today", lambda: datetime.date(2020, 1, 1))
    assert not _by(rules_sca_core.check(_model(FX))[0], "DNL-SCA-003")
    assert "net6.0" not in rules_sca_core.eol_tfms()


def test_eol_tfms_helper():
    assert {"net6.0", "net8.0", "netcoreapp3.1"} <= rules_sca_core.eol_tfms(TODAY)
    assert "net10.0" not in rules_sca_core.eol_tfms(TODAY)
    assert "net6.0" not in rules_sca_core.eol_tfms(datetime.date(2020, 1, 1))
    assert all(t == t.lower() for t in rules_sca_core.eol_tfms(TODAY))


def test_eol_suffix_stripped(tmp_path):
    (tmp_path / "W.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net6.0-windows</TargetFramework>'
        "</PropertyGroup></Project>", encoding="utf-8")
    findings, _ = _run(tmp_path)
    assert [f.title for f in _by(findings, "DNL-SCA-003")] == ["Target framework net6.0 is past end of support"]


# -- wwwroot JS (SCA-002) --------------------------------------------------

def test_wwwroot_lib_js():
    findings, _ = _run()
    js = _by(findings, "DNL-SCA-002")
    assert [f.file for f in js] == ["wwwroot/lib/jquery/jquery.js"]


# -- data file -------------------------------------------------------------

_GHSA = re.compile(r"^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$")
_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def test_data_file_entries_well_formed():
    data = json.loads(DATA.read_text(encoding="utf-8"))
    seen = set()
    for e in data["nuget"]:
        assert e["url"] == "https://github.com/advisories/" + e["advisory"], e
        assert rules_sca._range_valid(e["affected"]), e
        key = (e["id"].lower(), e["advisory"], e["affected"])
        assert key not in seen, key
        seen.add(key)
    # every entry added for ASP.NET Core carries a GHSA id (older legacy entries may be CVE ids)
    core = [e for e in data["nuget"] if e["id"].lower().startswith(("microsoft.", "system."))]
    assert core and all(_GHSA.match(e["advisory"]) for e in core)
    assert _ISO.match(data["eol_as_of"])
    for r in data["eol"]:
        datetime.date.fromisoformat(r["eol"])
        assert r["tfm"] == r["tfm"].lower() and r["source"].startswith("https://"), r
    assert {"netcoreapp3.1", "net5.0", "net6.0", "net8.0"} <= {r["tfm"] for r in data["eol"]}


def test_unknown_data_keys_do_not_break_legacy(tmp_path):
    p = tmp_path / "adv.json"
    p.write_text(json.dumps({"nuget": [], "js": [], "eol": [{"x": 1}], "eol_as_of": 3, "other": {}}), encoding="utf-8")
    index, err, skipped = rules_sca._load(p)
    assert err is None and skipped == 0 and index == {"nuget": {}, "js": {}}
    as_of, rows = rules_sca.eol_table()
    assert as_of == json.loads(DATA.read_text(encoding="utf-8"))["eol_as_of"] and rows


def test_eol_table_invalid_rows_dropped(tmp_path):
    p = tmp_path / "adv.json"
    p.write_text(json.dumps({"eol_as_of": "2026-01-01", "eol": [
        {"tfm": "NET6.0", "eol": "2024-11-12", "source": "https://x.example/p"},
        {"tfm": "net7.0", "eol": "soon", "source": "https://x.example/p"},
        {"tfm": "net9.0", "eol": "2026-11-10"}]}), encoding="utf-8")
    as_of, rows = rules_sca.eol_table(p)
    assert as_of == "2026-01-01" and [r["tfm"] for r in rows] == ["net6.0"]
    assert rules_sca.eol_table(tmp_path / "missing.json") == (None, [])


def test_rule_registered():
    assert RULES["DNL-SCA-006"][1:] == RULES["DNL-SCA-001"][1:]


# -- lock file attachment and fallbacks -------------------------------------

def _copy(tmp_path) -> Path:
    root = tmp_path / "app"
    shutil.copytree(FX, root, ignore=shutil.ignore_patterns("bin"))
    return root


def test_stray_nested_lock_is_ignored(tmp_path):
    root = _copy(tmp_path)
    stray = root / "samples" / "vendored"
    stray.mkdir(parents=True)
    # A deeper lock must neither replace the real one nor be reported itself.
    (stray / "packages.lock.json").write_text(json.dumps({"version": 1, "dependencies": {"net8.0": {
        "System.Text.RegularExpressions": {"type": "Direct", "resolved": "9.9.9"},
        "System.Net.Http": {"type": "Transitive", "resolved": "4.1.0"}}}}), encoding="utf-8")
    findings, _ = _run(root)
    assert not _pkg(findings, "System.IdentityModel.Tokens.Jwt")          # real lock (6.34.0) still wins
    assert len(_pkg(findings, "System.Text.RegularExpressions")) == 1
    assert [f.file for f in _pkg(findings, "System.Net.Http")] == ["packages.lock.json"]
    assert not any("samples" in f.file for f in findings)


def test_unresolvable_spec_with_lock_entry_is_not_review(tmp_path):
    root = _copy(tmp_path)
    lock = json.loads((root / "packages.lock.json").read_text(encoding="utf-8"))
    lock["dependencies"]["net8.0"]["Serilog"] = {"type": "Direct", "requested": "[1.*, )", "resolved": "1.5.14"}
    (root / "packages.lock.json").write_text(json.dumps(lock), encoding="utf-8")
    findings, _ = _run(root)
    review = " ".join(f.title for f in _by(findings, "DNL-SCA-006"))
    assert "Serilog " not in review + " " and len(_by(findings, "DNL-SCA-006")) == 2


def test_package_without_textual_reference_falls_back_to_line_1(tmp_path):
    (tmp_path / "Directory.Build.props").write_text(
        '<Project><ItemGroup><PackageReference Include="System.Net.Http" Version="4.3.0" /></ItemGroup></Project>',
        encoding="utf-8")
    (tmp_path / "A.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net8.0</TargetFramework>'
        "</PropertyGroup></Project>", encoding="utf-8")
    findings, _ = _run(tmp_path)
    # No textual reference: the id is only known lower-cased (Project.packages keys).
    hits = _by(findings, "DNL-SCA-001")
    assert len(hits) == 1 and "system.net.http 4.3.0" in hits[0].title and hits[0].file == "A.csproj" and hits[0].line == 1


def test_lock_file_below_project_not_beside_csproj_is_a_note(tmp_path):
    root = _copy(tmp_path)
    stray = root / "samples" / "vendored"
    stray.mkdir(parents=True)
    (stray / "packages.lock.json").write_text(json.dumps({"version": 1, "dependencies": {}}), encoding="utf-8")
    _, notes = _run(root)
    want = "samples/vendored/packages.lock.json: packages.lock.json is not next to a project file; ignored"
    assert notes.count(want) == 1


# -- end to end: detector, analyzer, owner routing ---------------------------

import enumerator  # noqa: E402
from languages.dotnet import detector as core_detector  # noqa: E402

FXROOT = Path(__file__).parent / "fixtures" / "aspnetcore"
MIXED = FXROOT / "mixed_solution"
CONTROLLERS_API = FXROOT / "controllers_api"


def _core_project(tmp_path, body="", tfm="net10.0") -> Path:
    (tmp_path / "A.csproj").write_text(
        f'<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>{tfm}</TargetFramework>'
        f"</PropertyGroup>{body}</Project>", encoding="utf-8")
    return tmp_path


def test_detector_registers_deps(tmp_path):
    assert core_detector.detect_frameworks(FX)[-2:] == ["config", "deps"]
    # Whether controllers_api gets it is decided by what its project file says.
    csproj = "".join(p.read_text(encoding="utf-8") for p in CONTROLLERS_API.glob("*.csproj"))
    expect = "PackageReference" in csproj or any(t in csproj for t in rules_sca_core.eol_tfms())
    assert ("deps" in core_detector.detect_frameworks(CONTROLLERS_API)) == expect
    # Nothing to judge: supported TFM, no packages, no lock file, no JS.
    assert core_detector.detect_frameworks(_core_project(tmp_path)) == ["config"]


@pytest.mark.parametrize("what", ["package", "lock", "js", "eol"])
def test_detector_deps_triggers(tmp_path, what):
    root = _core_project(tmp_path, tfm="net6.0" if what == "eol" else "net10.0",
                         body='<ItemGroup><PackageReference Include="X" Version="1.0.0" /></ItemGroup>'
                         if what == "package" else "")
    if what == "lock":
        (root / "packages.lock.json").write_text("{}", encoding="utf-8")
    if what == "js":
        (root / "wwwroot" / "lib").mkdir(parents=True)
        (root / "wwwroot" / "lib" / "a.js").write_text("//", encoding="utf-8")
    assert core_detector.detect_frameworks(root) == ["config", "deps"]


def test_detector_deps_ignores_js_outside_lib_dirs_and_build_output(tmp_path):
    root = _core_project(tmp_path)
    (root / "wwwroot" / "js").mkdir(parents=True)
    (root / "wwwroot" / "js" / "site.js").write_text("//", encoding="utf-8")
    (root / "bin" / "lib").mkdir(parents=True)
    (root / "bin" / "lib" / "a.js").write_text("//", encoding="utf-8")
    assert core_detector.detect_frameworks(root) == ["config"]


def test_deps_end_to_end():
    results = [r for r in enumerator.enumerate_target(FX, allow_degraded=True) if r.language == "dotnet"]
    deps = [r for r in results if r.framework == "deps"]
    assert len(deps) == 1 and deps[0].routes == []
    ids = {f.check_id for f in deps[0].findings}
    assert {"DNL-SCA-001", "DNL-SCA-002", "DNL-SCA-003", "DNL-SCA-006"} <= ids
    model = project.get_model(FX, "dotnet")
    assert deps[0].degraded == model.degraded
    assert any("end-of-support dates verified" in n for r in results for n in r.notes)


def test_deps_crash_becomes_a_note(monkeypatch):
    def boom(model):
        raise RuntimeError("boom")
    monkeypatch.setattr(rules_sca_core, "check", boom)
    results = [r for r in enumerator.enumerate_target(FX, allow_degraded=True) if r.language == "dotnet"]
    deps = next(r for r in results if r.framework == "deps")
    assert deps.findings == []
    assert any("rules_sca_core failed (RuntimeError: boom)" in n for n in deps.notes)


def test_route_less_findings_never_go_to_deps(monkeypatch):
    """A route-less AUTHZ finding lands in config; without config, in the first route analyzer; never deps."""
    from checks.dnl import rules_auth_core
    from checks.dnl.findings import dnl_finding
    from languages.dotnet import analyzers
    real = rules_auth_core.check
    monkeypatch.setattr(rules_auth_core, "check", lambda m, refs: real(m, refs) + [
        dnl_finding("DNL-AUTHZ-001", "high", "route-less", "d", "x.cs", 1)])
    model = project.get_model(CONTROLLERS_API, "dotnet")
    for running, owner in ((["controllers", "config", "deps"], "config"),
                           (["controllers", "deps"], "controllers"),
                           (["deps", "controllers"], "controllers"),
                           (["deps"], "config")):
        model.cache.pop("code_results", None)
        (model.parent or model).cache.setdefault("running", {})["dotnet"] = running
        res = analyzers._code_results(model)
        placed = [k for k, (_r, fs) in res.items() if any(f.title == "route-less" for f in fs)]
        assert placed == [owner], running
        assert "deps" not in res, running


def test_mixed_solution_each_file_once(tmp_path):
    root = tmp_path / "mixed"
    shutil.copytree(MIXED, root)
    for rel in ("Modern/bin/Debug/wwwroot/lib/jquery", "Modern/obj/lib/jquery", "Framework/bin/Scripts",
                "Modern/node_modules/x/lib"):
        d = root / rel
        d.mkdir(parents=True)
        shutil.copy(MIXED / "Modern/wwwroot/lib/jquery/jquery.js", d / "jquery.js")
    results = enumerator.enumerate_target(root, allow_degraded=True)

    def js(language):
        return sorted(f.file for r in results if r.language == language and r.framework == "deps"
                      for f in r.findings if f.check_id == "DNL-SCA-002")
    assert js("dotnet_legacy") == ["Framework/Scripts/jquery.js"]
    assert js("dotnet") == ["Modern/wwwroot/lib/jquery/jquery.js"]


def test_detector_deps_survives_a_file_that_resolves_outside_its_owner(tmp_path, monkeypatch):
    # A loose Core project owns files outside any project file; a symlinked or junctioned .js that
    # resolves outside the scan root has no path relative to that owner and must not abort detection.
    root = tmp_path / "scan"
    (root / "App").mkdir(parents=True)
    (root / "App" / "App.csproj").write_text(
        '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net10.0</TargetFramework>'
        "</PropertyGroup></Project>", encoding="utf-8")
    (root / "Program.cs").write_text(
        "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGet(\"/\", () => \"ok\");\napp.Run();\n",
        encoding="utf-8")
    outside = tmp_path / "elsewhere" / "wwwroot" / "lib" / "x.js"
    outside.parent.mkdir(parents=True)
    outside.write_text("//", encoding="utf-8")
    real = core_detector.iter_dnl_files
    monkeypatch.setattr(core_detector, "iter_dnl_files",
                        lambda target, exts: iter([outside]) if ".js" in exts else real(target, exts))
    assert "deps" not in core_detector.detect_frameworks(root)
