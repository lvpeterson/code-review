"""Tests for core/report.py's console and JSON output. Entry points were
added to ScanResult after routes/findings were already wired into both
output paths, and it's easy for a new ScanResult field to end up rendered
in the HTML report but silently missing from --json/console -- these guard
against that.
"""
import json

from core.models import EntryPoint, ScanResult
from core.report import _scan_result_to_dict, print_console, write_json


def _result_with_entry_point() -> ScanResult:
    return ScanResult(
        language="java",
        framework="spring",
        entry_points=[
            EntryPoint(
                kind="Scheduled",
                detail="cron=0 0 * * * *",
                handler_name="cleanupOldFiles",
                file="Jobs.java",
                line=5,
                source_start_line=5,
                source_end_line=8,
            )
        ],
    )


def test_scan_result_to_dict_includes_entry_points():
    payload = _scan_result_to_dict(_result_with_entry_point())
    assert payload["entry_points"] == [
        {
            "kind": "Scheduled",
            "detail": "cron=0 0 * * * *",
            "handler_name": "cleanupOldFiles",
            "file": "Jobs.java",
            "line": 5,
            "source_start_line": 5,
            "source_end_line": 8,
        }
    ]


def test_write_json_round_trips_entry_points(tmp_path):
    out_path = tmp_path / "report.json"
    write_json([_result_with_entry_point()], out_path)
    payload = json.loads(out_path.read_text(encoding="utf-8"))
    assert payload[0]["entry_points"][0]["handler_name"] == "cleanupOldFiles"


def test_print_console_lists_entry_points(capsys):
    print_console([_result_with_entry_point()])
    out = capsys.readouterr().out
    assert "entry points found: 1" in out
    assert "cleanupOldFiles" in out
    assert "cron=0 0 * * * *" in out


def test_print_console_omits_entry_points_section_when_none(capsys):
    result = ScanResult(language="python", framework="flask")
    print_console([result])
    out = capsys.readouterr().out
    assert "entry points found" not in out
