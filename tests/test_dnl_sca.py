"""Offline SCA rules (DNL-SCA-001..005) and the advisory data they read."""
import json
from pathlib import Path

import pytest

from checks.dnl import project, rules_sca
from core.owasp_web import RULES
from languages.dotnet_legacy import detector

FX = Path(__file__).parent / "fixtures" / "dotnet_legacy"
DEPS = FX / "deps_app"
DATA = Path(__file__).resolve().parent.parent / "checks" / "dnl" / "data" / "dnl_advisories.json"


def _model(root: Path) -> project.ProjectModel:
    return project.ProjectModel(root.resolve(), project.load_projects(root.resolve()), {}, "no helper")


def _run(root: Path):
    return rules_sca.check(_model(root))


def _by(findings, cid):
    return [f for f in findings if f.check_id == cid]


# -- version ranges -------------------------------------------------------

@pytest.mark.parametrize("rng,ver,want", [
    ("<13.0.1", "13.0.1", False),
    ("<13.0.1", "13.0.0", True),
    ("<13.0.1", "6.0.8", True),
    (">=5.0 <5.5.12", "5.5.12", False),
    (">=5.0 <5.5.12", "5.5.11", True),
    (">=5.0 <5.5.12", "4.9.9", False),
    ("<1.2.3", "1.2.3-beta", True),         # prerelease sorts below the release
    ("<1.2.3-beta", "1.2.3", False),
    ("<1.2.3", "1.2.3", False),
    (">=107.0.0-preview.1 <112.0.0", "107.0.0-preview.1", True),
    (">=107.0.0-preview.1 <112.0.0", "106.12.0", False),
    (">=107.0.0-preview.1 <112.0.0", "112.0.0", False),
    ("<2.0.10", "2.0.8.1", True),            # 4-part versions
    ("<2.0.10", "2.0.10.0", False),          # trailing zero part is equal
    (">=1.3.0 <=1.8.3", "1.8.3", True),
    (">=1.3.0 <=1.8.3", "1.8.4", False),
    ("<1.12.2 || >=1.12.3 <3.0.0", "1.12.2", False),
    ("<1.12.2 || >=1.12.3 <3.0.0", "1.12.4", True),
    ("<1.12.2 || >=1.12.3 <3.0.0", "3.0.0", False),
    ("<1.0.0-beta.2", "1.0.0-beta.11", False),  # numeric prerelease identifiers compare as numbers
    ("<1.0.0-beta.11", "1.0.0-beta.2", True),
    ("<1.0.0-rc.1", "1.0.0-beta", True),
    ("<1.0.0", "1.0.0+build5", False),       # build metadata ignored
    ("<1.0.0-RC.2", "1.0.0-rc.1", True),     # prerelease labels are case-insensitive
    ("<1.0.0-beta", "1.0.0-BETA", False),
])
def test_version_in(rng, ver, want):
    assert rules_sca.version_in(rng, ver) is want


def test_version_in_unparsable_is_not_a_match():
    assert rules_sca.version_in("<13.0.1", "latest") is False


# -- data file ------------------------------------------------------------

def test_data_schema():
    data = json.loads(DATA.read_text(encoding="utf-8"))
    assert set(data) == {"nuget", "js"}
    for kind, key in (("nuget", "id"), ("js", "library")):
        assert data[kind]
        for e in data[kind]:
            for k in (key, "advisory", "url", "affected", "severity", "summary"):
                assert e.get(k), (kind, e)
            assert e["advisory"].startswith(("GHSA-", "CVE-")), e
            assert e["advisory"] in e["url"], e
            assert e["severity"] in ("high", "medium", "low"), e
            # every range parses and a probe version is handled without error
            rules_sca.version_in(e["affected"], "1.0.0")
            assert rules_sca._range_valid(e["affected"]), e   # every comparator: operator + valid version
    # the families the rule table promises
    nug = {e["id"].lower() for e in data["nuget"]}
    assert {"newtonsoft.json", "jquery", "jquery.ui.combined", "jquery.validation", "bootstrap",
            "restsharp", "log4net"} <= nug
    js = {e["library"] for e in data["js"]}
    assert {"jquery", "jquery-ui", "jquery-validation", "bootstrap"} <= js


# -- DNL-SCA-001 ----------------------------------------------------------

def test_sca001_packages_config_vulnerable_and_fixed():
    findings, _ = _run(DEPS)
    hits = _by(findings, "DNL-SCA-001")
    files = {(f.file, f.line) for f in hits}
    # Newtonsoft 12.0.3 (line 3) and jQuery 1.12.4 (line 4) are vulnerable;
    # Bootstrap 3.4.1 and Api's Newtonsoft 13.0.3 are the fixed versions.
    assert ("Web/packages.config", 3) in files
    assert ("Web/packages.config", 4) in files
    assert not any(f.file == "Api/packages.config" for f in hits)
    assert not any(f.file == "Web/packages.config" and f.line == 5 for f in hits)
    nj = next(f for f in hits if f.line == 3 and f.file == "Web/packages.config")
    assert nj.severity == "high"
    assert "GHSA-5crp-9r3c-p9vr" in nj.description
    assert "https://github.com/advisories/GHSA-5crp-9r3c-p9vr" in nj.description


def test_sca001_one_finding_per_package_with_all_advisories():
    findings, _ = _run(DEPS)
    jq = next(f for f in _by(findings, "DNL-SCA-001") if f.file == "Web/packages.config" and f.line == 4)
    assert jq.severity == "medium"
    for adv in ("GHSA-gxr4-xjj5-5px2", "GHSA-6c3j-c64m-qhgq", "GHSA-rmxg-73gg-4p98"):
        assert adv in jq.description


def test_sca001_hintpath_only_prerelease_package():
    findings, _ = _run(DEPS)
    rs = [f for f in _by(findings, "DNL-SCA-001") if f.file == "Web/Web.csproj"]
    assert len(rs) == 1, [f.title for f in rs]
    # anchored at the HintPath line, not the Reference line
    text = (DEPS / "Web" / "Web.csproj").read_text().splitlines()
    assert "RestSharp.107.0.0-preview.1" in text[rs[0].line - 1]
    assert "GHSA-4rr6-2v9v-wcpc" in rs[0].description


def test_sca001_hintpath_not_duplicated_when_in_packages_config():
    findings, _ = _run(DEPS)
    # Newtonsoft is in Web/packages.config: the csproj HintPath must not report it again.
    assert not any("newtonsoft" in f.title.lower() for f in _by(findings, "DNL-SCA-001") if f.file == "Web/Web.csproj")


def test_sca001_id_is_case_insensitive(tmp_path):
    (tmp_path / "packages.config").write_text(
        '<packages>\n  <package id="NEWTONSOFT.JSON" version="9.0.1" targetFramework="net45" />\n</packages>\n')
    findings, _ = _run(tmp_path)
    assert [f.line for f in _by(findings, "DNL-SCA-001")] == [2]


def test_sca001_attribute_order_and_missing_version(tmp_path):
    (tmp_path / "packages.config").write_text(
        '<packages>\n  <package version="9.0.1" id="Newtonsoft.Json" />\n  <package id="Newtonsoft.Json" />\n</packages>\n')
    findings, _ = _run(tmp_path)
    assert [f.line for f in _by(findings, "DNL-SCA-001")] == [2]


def test_sca001_unparsable_packages_config_does_not_crash(tmp_path):
    (tmp_path / "packages.config").write_text("<packages><package id=\n")
    findings, _ = _run(tmp_path)
    assert findings == []


# -- DNL-SCA-002 ----------------------------------------------------------

def test_sca002_bundled_jquery():
    findings, _ = _run(DEPS)
    js = _by(findings, "DNL-SCA-002")
    assert [(f.file, f.line) for f in js] == [("Web/Scripts/jquery-1.12.4.min.js", 1)]
    assert "1.12.4" in js[0].title and "GHSA-gxr4-xjj5-5px2" in js[0].description


@pytest.mark.parametrize("banner,advisory", [
    ("/*! jQuery UI - v1.12.1 - 2016-09-14\n * http://jqueryui.com */", "GHSA-h6gj-6jjq-h8g9"),
    ("/*! jQuery Validation Plugin - v1.17.0 - 7/29/2017\n * https://jqueryvalidation.org/ */", "GHSA-ffmh-x56j-9rc3"),
    ("/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */", "GHSA-9v3m-8fp8-mj99"),
    ("//! moment.js\n//! version : 2.24.0\n//! license : MIT", "GHSA-wc69-rhjr-hc9g"),
    ("/**\n * Knockout JavaScript library v3.4.2\n * (c) The Knockout.js team */", "GHSA-vcjj-xf2r-mwvc"),
    ("/**\n * @license AngularJS v1.5.8\n * (c) 2010-2016 Google, Inc. */", "GHSA-4w4v-5hc9-xrr2"),
    ("/**!\n @license\n handlebars v4.0.5\n*/", "GHSA-f2jv-r9rf-7988"),
    ("/**\n * @license\n * Lodash <https://lodash.com/>\n * lodash 4.17.4 (Custom Build) */", "GHSA-35jh-r3h4-6jhm"),
])
def test_sca002_banner_variants(tmp_path, banner, advisory):
    d = tmp_path / "lib"
    d.mkdir()
    (d / "x.js").write_text(banner + "\n")
    findings, _ = _run(tmp_path)
    hits = _by(findings, "DNL-SCA-002")
    assert len(hits) == 1, [f.title for f in hits]
    assert advisory in hits[0].description and hits[0].line == 1


def test_sca002_fixed_versions_and_other_dirs_are_quiet(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "a.js").write_text("/*! jQuery v3.7.1 | (c) OpenJS Foundation */\n")
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "b.js").write_text("/*! jQuery v1.12.4 | (c) jQuery Foundation */\n")  # not a bundle dir
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


def test_sca002_banner_only_read_from_file_head(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "app.js").write_text("var x = 1;\n" * 2000 + "/* jQuery v1.12.4 was mentioned */\n")
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


# -- DNL-SCA-003 ----------------------------------------------------------

def test_sca003_old_target_framework():
    findings, _ = _run(DEPS)
    hits = _by(findings, "DNL-SCA-003")
    assert [(f.file, f.line) for f in hits] == [("Web/Web.csproj", 6)]
    assert hits[0].severity == "medium" and "v4.5" in hits[0].title


@pytest.mark.parametrize("tfv,flag", [("v2.0", True), ("v3.5", True), ("v4.0", True), ("v4.6.1", True),
                                      ("v4.6.2", False), ("v4.7", False), ("v4.8", False), ("v4.8.1", False)])
def test_sca003_boundary(tmp_path, tfv, flag):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0"><PropertyGroup>\n<TargetFrameworkVersion>%s</TargetFrameworkVersion>\n'
        '</PropertyGroup></Project>' % tfv)
    findings, _ = _run(tmp_path)
    assert bool(_by(findings, "DNL-SCA-003")) is flag


# -- DNL-SCA-004 ----------------------------------------------------------

def test_sca004_unmanaged_dll():
    findings, _ = _run(DEPS)
    hits = _by(findings, "DNL-SCA-004")
    assert [f.file for f in hits] == ["Web/Web.csproj"]
    assert "Vendor.Widgets" in hits[0].title or "Vendor.Widgets" in hits[0].description
    assert hits[0].severity == "low" and hits[0].confidence == "REVIEW"


def test_sca004_versioned_package_and_matching_id_are_quiet(tmp_path):
    (tmp_path / "packages.config").write_text('<packages>\n<package id="Foo.Bar" version="1.0.0" />\n</packages>\n')
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0"><ItemGroup>'
        '<Reference Include="Foo.Bar"><HintPath>lib\\Foo.Bar.dll</HintPath></Reference>'
        '<Reference Include="Baz"><HintPath>..\\packages\\Baz.2.1.0\\lib\\net45\\Baz.dll</HintPath></Reference>'
        '</ItemGroup></Project>')
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-004") == []


# -- DNL-SCA-005 ----------------------------------------------------------

def test_sca005_http_source():
    findings, _ = _run(DEPS)
    hits = _by(findings, "DNL-SCA-005")
    assert [(f.file, f.line) for f in hits] == [("nuget.config", 5)]
    assert hits[0].severity == "medium"


def test_sca005_https_and_local_sources_are_quiet(tmp_path):
    (tmp_path / "NuGet.Config").write_text(
        '<configuration><packageSources>\n<add key="a" value="https://x.example/v3/index.json" />\n'
        '<add key="b" value="\\\\share\\feed" /></packageSources></configuration>')
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-005") == []


# -- wiring ---------------------------------------------------------------

def test_rules_registered():
    for rid in ("DNL-SCA-001", "DNL-SCA-002", "DNL-SCA-003", "DNL-SCA-004", "DNL-SCA-005"):
        assert rid in RULES
    assert RULES["DNL-SCA-001"][:2] == ("A03", "A06") and RULES["DNL-SCA-005"][:2] == ("A03", "A08")
    assert RULES["DNL-SCA-003"][2:] == ("API9", "always")


def test_deps_framework_detected():
    assert detector.detect_frameworks(DEPS)[-1] == "deps"


def test_deps_framework_absent_without_inputs(tmp_path):
    (tmp_path / "W.aspx").write_text('<%@ Page Language="C#" %>')
    assert "deps" not in detector.detect_frameworks(tmp_path)


def test_deps_analyzer_runs_degraded_through_registry():
    from core.registry import get_analyzer
    from languages.dotnet_legacy import analyzers  # noqa: F401  (registers)
    an = get_analyzer("dotnet_legacy", "deps")(DEPS)
    an._model = _model(DEPS)
    res = an.analyze()
    assert res.framework == "deps" and res.routes == []
    assert {f.check_id for f in res.findings} == {
        "DNL-SCA-001", "DNL-SCA-002", "DNL-SCA-003", "DNL-SCA-004", "DNL-SCA-005"}


# -- fix round 1 ----------------------------------------------------------

def test_advisory_data_missing_or_corrupt_does_not_crash(tmp_path, monkeypatch):
    (tmp_path / "packages.config").write_text(
        '<packages>\n<package id="Newtonsoft.Json" version="9.0.1" />\n</packages>\n')
    (tmp_path / "nuget.config").write_text(
        '<configuration><packageSources>\n<add key="a" value="http://x.example/i.json" />\n'
        '</packageSources></configuration>')
    for name, content in (("missing.json", None), ("corrupt.json", "{not json"), ("list.json", "[1, 2]")):
        bad = tmp_path / name
        if content is not None:
            bad.write_text(content)
        monkeypatch.setattr(rules_sca, "_DATA", bad)
        findings, notes = _run(tmp_path)
        assert _by(findings, "DNL-SCA-001") == [] and _by(findings, "DNL-SCA-002") == []
        assert [f.line for f in _by(findings, "DNL-SCA-005")] == [2]   # unrelated rules still run
        assert any("advisory data unavailable" in n and "DNL-SCA-001/002 skipped" in n for n in notes), notes


@pytest.mark.parametrize("hint", [
    r"$(SolutionDir)packages\Newtonsoft.Json.9.0.1\lib\net45\Newtonsoft.Json.dll",
    r"$(SolutionDir)..\packages\Newtonsoft.Json.9.0.1\lib\net45\Newtonsoft.Json.dll",
    r"$(MSBuildThisFileDirectory)..\packages\Newtonsoft.Json.9.0.1\lib\net45\Newtonsoft.Json.dll",
    "$(SolutionDir)/packages/Newtonsoft.Json.9.0.1/lib/net45/Newtonsoft.Json.dll",
])
def test_hintpath_macro_prefixes_are_matched(tmp_path, hint):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0"><ItemGroup><Reference Include="Newtonsoft.Json">\n<HintPath>%s</HintPath>\n'
        '</Reference></ItemGroup></Project>' % hint)
    findings, _ = _run(tmp_path)
    assert [f.line for f in _by(findings, "DNL-SCA-001")] == [2]


def test_hintpath_macro_prefix_unmanaged_dll_still_sca004(tmp_path):
    (tmp_path / "A.csproj").write_text(
        r'<Project ToolsVersion="12.0"><ItemGroup><Reference Include="Z"><HintPath>$(SolutionDir)packages\Z\Z.dll'
        r'</HintPath></Reference><Reference Include="Y"><HintPath>$(SolutionDir)..\lib\Y.dll</HintPath></Reference>'
        r'</ItemGroup></Project>')
    findings, _ = _run(tmp_path)
    assert len(_by(findings, "DNL-SCA-004")) == 2


def test_plugin_header_requiring_jquery_is_not_a_banner(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "plugin.js").write_text(
        "/*!\n * Fancy plugin 2.0\n * Requires jQuery v1.7+ and Bootstrap v3.3.7\n */\n(function(){})();\n")
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


def test_banner_behind_leading_comment_or_code_is_found(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "late.js").write_text("// helper\n/*! jQuery v1.12.4 | (c) jQuery Foundation */\n")
    (tmp_path / "Scripts" / "strict.js").write_text('"use strict";\n/*! jQuery v1.12.4 | (c) jQuery Foundation */\n')
    (tmp_path / "Scripts" / "iife.js").write_text(
        ";(function(){})();\n/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */\n")
    (tmp_path / "Scripts" / "lic.js").write_text("/* MIT license text */\n// lodash 4.17.4 (Custom Build)\n")
    findings, _ = _run(tmp_path)
    assert sorted(f.file for f in _by(findings, "DNL-SCA-002")) == [
        "Scripts/iife.js", "Scripts/late.js", "Scripts/lic.js", "Scripts/strict.js"]


@pytest.mark.parametrize("line", ["Requires jQuery v1.7+", "depends on jQuery v1.12.4",
                                  "Compatible with jQuery v1.12.4", "Tested with jQuery v1.12.4"])
def test_dependency_mentions_never_match_even_in_named_files(tmp_path, line):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "jquery-1.x-plugin.js").write_text("/*!\n * Plugin\n * %s\n */\n" % line)
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


def test_invalid_advisory_entries_are_skipped_with_one_note(tmp_path, monkeypatch):
    good = {"id": "Newtonsoft.Json", "advisory": "GHSA-x", "url": "https://example.test/GHSA-x",
            "affected": "<13.0.1", "severity": "high", "summary": "s"}
    data = {"nuget": [good, dict(good, affected=None), dict(good, severity="critical"), dict(good, affected="<abc"),
                      dict(good, url=7), "junk"], "js": [{"library": "jquery", "advisory": "GHSA-y"}]}
    f = tmp_path / "adv.json"
    f.write_text(json.dumps(data))
    monkeypatch.setattr(rules_sca, "_DATA", f)
    (tmp_path / "packages.config").write_text(
        '<packages>\n<package id="Newtonsoft.Json" version="9.0.1" />\n</packages>\n')
    findings, notes = _run(tmp_path)
    assert [x.line for x in _by(findings, "DNL-SCA-001")] == [2]       # the valid sibling still works
    assert notes.count("6 advisory entries skipped: invalid fields") == 1, notes


@pytest.mark.parametrize("hint,line", [
    (r"$(NuGetPackageRoot)Newtonsoft.Json.9.0.1\lib\net45\Newtonsoft.Json.dll", 2),
    ("$(NuGetPackageRoot)newtonsoft.json/9.0.1/lib/net45/Newtonsoft.Json.dll", 2),
    (r"$(PkgNewtonsoft_Json)\lib\net45\Newtonsoft.Json.dll", None),   # macro is the package dir: unmanaged, REVIEW
])
def test_package_root_macros(tmp_path, hint, line):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0"><ItemGroup><Reference Include="N">\n<HintPath>%s</HintPath>\n'
        '</Reference></ItemGroup></Project>' % hint)
    findings, _ = _run(tmp_path)
    if line:
        assert [f.line for f in _by(findings, "DNL-SCA-001")] == [line]
    else:
        assert _by(findings, "DNL-SCA-001") == [] and len(_by(findings, "DNL-SCA-004")) == 1


@pytest.mark.parametrize("fname,text,adv", [
    ("jquery-1.12.4.js", "/*!\n * jQuery JavaScript Library v1.12.4\n * http://jquery.com/\n */\n", "GHSA-gxr4-xjj5-5px2"),
    ("x.js", "/*!\n * jQuery JavaScript Library v1.12.4\n * http://jquery.com/\n */\n", "GHSA-gxr4-xjj5-5px2"),
    ("jquery-ui.js", "/*! jQuery UI - v1.11.4 - 2015-03-11\n* http://jqueryui.com */\n", "GHSA-h6gj-6jjq-h8g9"),
    ("bootstrap.js", "/*!\n * Bootstrap v3.3.7 (http://getbootstrap.com)\n */\n", "GHSA-9v3m-8fp8-mj99"),
    ("lodash.js", "/**\n * @license\n * lodash 4.17.4 (Custom Build)\n */\n", "GHSA-35jh-r3h4-6jhm"),
    ("jquery.js", "/* vendored copy */\n", None),
])
def test_banner_context_positive(tmp_path, fname, text, adv):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / fname).write_text(text)
    findings, _ = _run(tmp_path)
    hits = _by(findings, "DNL-SCA-002")
    if adv is None:
        assert hits == []
    else:
        assert len(hits) == 1 and adv in hits[0].description


def test_named_file_accepts_library_led_or_version_only_lines(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "jquery-1.12.4.js").write_text("/*!\n * jQuery custom build, see the notes, v1.12.4\n */\n")
    (tmp_path / "Scripts" / "jquery-3.7.1.js").write_text("/*!\n * Custom build\n * v1.12.4\n */\n")
    findings, _ = _run(tmp_path)
    assert sorted(f.file for f in _by(findings, "DNL-SCA-002")) == ["Scripts/jquery-1.12.4.js", "Scripts/jquery-3.7.1.js"]


def test_commented_out_csproj_items_are_ignored(tmp_path):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0">\n<!--\n<TargetFrameworkVersion>v3.5</TargetFrameworkVersion>\n'
        r'<HintPath>..\packages\Newtonsoft.Json.9.0.1\lib\a.dll</HintPath>' '\n-->\n'
        '<PropertyGroup><TargetFrameworkVersion>v4.5</TargetFrameworkVersion></PropertyGroup></Project>')
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-001") == []
    assert [f.line for f in _by(findings, "DNL-SCA-003")] == [6]


# -- fix round 3 ----------------------------------------------------------

def test_non_string_severity_skips_only_that_entry(tmp_path, monkeypatch):
    good = {"id": "Newtonsoft.Json", "advisory": "GHSA-x", "url": "https://example.test/GHSA-x",
            "affected": "<13.0.1", "severity": "high", "summary": "s"}
    data = {"nuget": [dict(good, severity=["high"]), dict(good, severity={"a": 1}), good], "js": []}
    f = tmp_path / "adv.json"
    f.write_text(json.dumps(data))
    monkeypatch.setattr(rules_sca, "_DATA", f)
    (tmp_path / "packages.config").write_text(
        '<packages>\n<package id="Newtonsoft.Json" version="9.0.1" />\n</packages>\n')
    findings, notes = _run(tmp_path)
    assert [x.line for x in _by(findings, "DNL-SCA-001")] == [2]
    assert "2 advisory entries skipped: invalid fields" in notes


def test_library_named_file_does_not_take_a_mention_as_banner(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "bootstrap-tour.js").write_text("// Tour for Bootstrap v3.3.7\n")
    (tmp_path / "Scripts" / "bootstrap-tour-0.12.0.js").write_text("// Tour for Bootstrap v3.3.7\n")
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


# -- fix round 4 ----------------------------------------------------------

def test_versioned_file_name_is_last_resort_version(tmp_path):
    # A mention never counts as a banner, but an exact versioned name still reports (may-insecure).
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "bootstrap-3.3.7.js").write_text("// Tour for Bootstrap v3.3.7\n")
    (tmp_path / "Scripts" / "jquery-1.12.4.min.js").write_text("/*!\n * Based on jQuery v1.12.4\n */\n")
    findings, _ = _run(tmp_path)
    assert sorted(f.file for f in _by(findings, "DNL-SCA-002")) == [
        "Scripts/bootstrap-3.3.7.js", "Scripts/jquery-1.12.4.min.js"]


def test_strict_banner_in_later_block_beats_bare_version_line(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "jquery-1.x.js").write_text(
        "/* build\n 3.7.1\n */\n/*! jQuery v1.12.4 | (c) jQuery Foundation */\n")
    findings, _ = _run(tmp_path)
    hits = _by(findings, "DNL-SCA-002")
    assert len(hits) == 1 and "1.12.4" in hits[0].title


def test_file_name_version_not_used_when_another_strict_banner_present(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "jquery-1.12.4.js").write_text("/*! jQuery UI - v1.13.2 */\n")
    findings, _ = _run(tmp_path)
    assert not any("jQuery 1.12.4" in f.title for f in _by(findings, "DNL-SCA-002"))


def test_jquery_named_file_with_ui_banner_is_not_jquery(tmp_path):
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "jquery-1.12.4.js").write_text("/*! jQuery UI - v1.13.2 - 2022-07-14 */\n")
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-002") == []


@pytest.mark.parametrize("hint", [
    r"$(PkgNewtonsoft_Json)\lib\net45\Newtonsoft.Json.dll",
    r"$(PkgRoot)\Newtonsoft.Json.9.0.1\lib\net45\Newtonsoft.Json.dll",
])
def test_pkg_macros_are_unversioned_never_a_root(tmp_path, hint):
    (tmp_path / "A.csproj").write_text(
        '<Project ToolsVersion="12.0"><ItemGroup><Reference Include="N">\n<HintPath>%s</HintPath>\n'
        '</Reference></ItemGroup></Project>' % hint)
    findings, _ = _run(tmp_path)
    assert _by(findings, "DNL-SCA-001") == [] and len(_by(findings, "DNL-SCA-004")) == 1
