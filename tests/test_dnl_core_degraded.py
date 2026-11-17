"""Degraded-mode parity on ASP.NET Core: the taint_app fixture scanned with the Roslyn helper and without it
must give the same proven findings per route style, apart from a short list of things only the helper sees."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project

ROOT = Path(__file__).parent / "fixtures" / "aspnetcore" / "taint_app"

TAINT_FAMILY = ("INJ", "XSS", "PATH", "REDIR", "SSRF", "LOG", "DESER", "XXE")
OBJECT_RULES = ("DNL-AUTHZ-005", "DNL-AUTHZ-006", "DNL-AUTHZ-007")


def _proven(allow_degraded=False):
    project._CACHE.clear()
    res = [r for r in enumerator.enumerate_target(ROOT, allow_degraded=allow_degraded) if r.language == "dotnet"]
    out = set()
    for r in res:
        for f in r.findings:
            if f.confidence is None and f.route is not None and (f.check_id.split("-")[1] in TAINT_FAMILY or f.check_id in OBJECT_RULES):
                out.add((f.check_id, f.file, f.line, f.route.meta.get("kind"), f.route.handler_name))
    project._CACHE.clear()
    return out


# Proven findings only the helper run produces. Empty today: the text fallbacks reach every proven taint,
# template and object finding of the fixture. A new entry must say why degraded mode cannot see it (for
# example a sink whose receiver type only the helper resolves, with no name-based row).
HELPER_ONLY: set = set()


def test_degraded_one_taint_finding_per_style(roslyn_helper, monkeypatch):
    full = _proven()
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    deg = _proven(True)
    for kind in ("controller", "razorpage", "minimalapi"):
        assert any(k[3] == kind and k[0].split("-")[1] in TAINT_FAMILY for k in deg), kind
    assert deg == full - HELPER_ONLY
