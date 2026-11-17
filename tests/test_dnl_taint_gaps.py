"""Taint gaps found on real-world shapes, reproduced on the synthetic taint_gaps fixture: missing System.IO /
Compression path sinks and zip-slip sources, TryGetValue and StreamReader propagation, stream arguments of
StreamReader / StreamWriter, IsLocalUrl over member paths and SSRF where only a path is tainted. Each case
runs with the Roslyn helper and degraded (tree-sitter)."""
from pathlib import Path

import pytest

from checks.dnl import project, rules_taint
from checks.dnl.routes_core import discover_all

ROOT = Path(__file__).parent / "fixtures" / "aspnetcore" / "taint_gaps"


@pytest.fixture(scope="module", params=[False, True], ids=["helper", "degraded"])
def findings(request, roslyn_helper):
    mp = pytest.MonkeyPatch()
    if request.param:
        mp.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
        mp.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    project._CACHE.clear()
    project.prepare(ROOT, request.param)
    model = project.get_model(ROOT, "dotnet")
    out = rules_taint.check(model, discover_all(model))
    yield out
    project._CACHE.clear()
    mp.undo()


def hits(findings, handler, rule=None):
    return [f for f in findings if f.route is not None and f.route.handler_name == handler
            and (rule is None or f.check_id == rule)]


# -- D2: path sinks ---------------------------------------------------------------------------

FILE_SINKS = ["Create", "CreateText", "AppendText", "AppendAllLines", "AppendAllLinesAsync", "ReadLines",
              "ReadAllTextAsync", "ReadAllBytesAsync", "ReadAllLinesAsync", "WriteAllTextAsync",
              "WriteAllBytesAsync", "WriteAllLinesAsync", "AppendAllTextAsync", "Replace", "EnumFiles",
              "EnumDirs", "EnumEntries", "GetDirs", "Move", "Extract", "CreateZip", "OpenZip", "EntryTo"]


@pytest.mark.parametrize("action", FILE_SINKS)
def test_path_sinks(findings, action):
    got = hits(findings, f"FileSinksController.{action}", "DNL-PATH-001")
    assert len(got) == 1 and got[0].severity == "high", action


def test_constant_paths_are_clean(findings):
    assert not hits(findings, "FileSinksController.Fixed")
    assert not hits(findings, "ArchiveController.Fixed")


def test_project_entries_collection_is_not_an_archive(findings):
    assert not hits(findings, "ArchiveController.OwnEntries")


def test_zip_slip_sources(findings):
    for action in ("SlipBody", "SlipDisk", "SlipName", "SlipItem", "SlipTyped"):
        got = hits(findings, f"ArchiveController.{action}", "DNL-PATH-001")
        assert len(got) == 1, action
    for action in ("SlipDisk", "SlipName"):
        # the archive is opened from a constant path: only the entry name is the source
        assert "archive entry name" in hits(findings, f"ArchiveController.{action}", "DNL-PATH-001")[0].description


# -- D3: TryGetValue and StreamReader propagation ----------------------------------------------

@pytest.mark.parametrize("action", ["Query", "Form", "Header", "Cookie", "RouteVal", "Typed"])
def test_try_get_value_taints_out_variable(findings, action):
    assert len(hits(findings, f"CollectionsController.{action}", "DNL-INJ-002")) == 1, action


def test_try_get_value_on_constants_is_clean(findings):
    assert not hits(findings, "CollectionsController.Dict")


@pytest.mark.parametrize("action", ["ReadToEnd", "ReadToEndSync", "ReadLine", "Upload"])
def test_stream_reader_carries_body_taint(findings, action):
    assert len(hits(findings, f"CollectionsController.{action}", "DNL-INJ-002")) == 1, action


def test_reader_over_fixed_file_is_clean(findings):
    assert not hits(findings, "CollectionsController.FixedReader")


# -- N3: streams are not paths -------------------------------------------------------------------

@pytest.mark.parametrize("action", ["Body", "RespBody", "Upload", "Typed", "Inferred"])
def test_stream_arguments_are_not_paths(findings, action):
    assert not hits(findings, f"StreamsController.{action}", "DNL-PATH-001"), action


@pytest.mark.parametrize("action", ["StringPath", "WriterPath", "FileStreamPath", "UserOpen", "FormPath"])
def test_string_paths_still_flag(findings, action):
    assert len(hits(findings, f"StreamsController.{action}", "DNL-PATH-001")) == 1, action


# -- N2: IsLocalUrl over member paths -------------------------------------------------------------

@pytest.mark.parametrize("handler", ["RedirectController.Then", "RedirectController.Early",
                                     "RedirectController.Simple", "LoginModel.OnPostInput",
                                     "LoginModel.OnPostThis"])
def test_is_local_url_cleanses_member_paths(findings, handler):
    assert not hits(findings, handler, "DNL-REDIR-001"), handler


@pytest.mark.parametrize("handler", ["RedirectController.Unguarded", "RedirectController.OtherMember",
                                     "LoginModel.OnPostOther", "RedirectController.NoExit",
                                     "RedirectController.Reassign", "RedirectController.LoopShadow"])
def test_unguarded_redirects_still_flag(findings, handler):
    assert len(hits(findings, handler, "DNL-REDIR-001")) == 1, handler


# -- N5: SSRF with a path-only taint ----------------------------------------------------------------

@pytest.mark.parametrize("action", ["Relative", "Concat", "FieldPrefix", "ConstPrefix", "LocalPrefix", "ViaVar"])
def test_ssrf_path_only_is_low_review(findings, action):
    got = hits(findings, f"FetchController.{action}", "DNL-SSRF-001")
    assert len(got) == 1, action
    assert got[0].severity == "low" and got[0].confidence == "REVIEW", action
    assert "only the path" in got[0].description


@pytest.mark.parametrize("action", ["Full", "HostFirst", "SchemeOnly", "HostNoSlash"])
def test_ssrf_full_url_stays_high(findings, action):
    got = hits(findings, f"FetchController.{action}", "DNL-SSRF-001")
    assert len(got) == 1 and got[0].severity == "high" and got[0].confidence != "REVIEW", action
