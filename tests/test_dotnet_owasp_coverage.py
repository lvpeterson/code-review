"""Every OWASP Web 2025 (A01-A10) and API 2023 (API1-API10) category is reachable for an ASP.NET Core target,
statically (rule inventory) and end to end (findings on the synthetic Core fixtures), with and without the helper."""
from pathlib import Path

import pytest

import enumerator
from checks.dnl import project
from core.owasp_web import RULES, TITLES
from tests import owasp_inventory as inv

FX = Path(__file__).parent / "fixtures" / "aspnetcore"
WEB = {f"A{n:02d}" for n in range(1, 11)}
API = {f"API{n}" for n in range(1, 11)}

# Categories no merged rule can produce on Core yet because their only rules are configuration rules (CORS,
# cookies, JWT, Identity options, secrets, limits...) that arrive with the configuration branch. The test asserts
# this set is exactly what is missing, so it must become empty (and be deleted) once that branch merges.
PENDING_CONFIG_BRANCH: set = set()

# Categories that only the Roslyn helper can reach. Each entry needs a reason.
HELPER_ONLY_CATEGORIES: set = set()


def _apps():
    out = []
    for p in sorted(FX.iterdir()):
        if not p.is_dir():
            continue
        if p.name == "pipelines":
            out.extend(sorted(q for q in p.iterdir() if q.is_dir()))
        else:
            out.append(p)
    return out


def _tags(degraded: bool):
    """(web codes, api codes, code -> rule ids seen) over all Core fixtures."""
    web, api, seen = set(), set(), {}
    for app in _apps():
        project._CACHE.clear()
        for r in enumerator.enumerate_target(app, allow_degraded=degraded):
            if r.language != "dotnet":
                continue
            for f in r.findings:
                o = f.owasp or {}
                if o.get("2025"):
                    web.add(o["2025"].split(":")[0])
                if o.get("api2023"):
                    api.add(o["api2023"].split(":")[0])
    project._CACHE.clear()
    return web, api


def _mapped(code: str) -> list[str]:
    return sorted(i for i, v in RULES.items() if v[0] == code or v[2] == code)


def _missing_msg(web, api):
    return "; ".join(f"{c} <- {_mapped(c)}" for c in sorted((WEB - web) | (API - api)))


def test_static_dotnet_row_covers_everything():
    row = next(r for r in inv.coverage_rows(RULES) if r.startswith("| dotnet |"))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert cells[3] == "none" and cells[5] == "none", row
    assert set(TITLES["2025"]) == WEB and set(TITLES["api2023"]) == API


def test_end_to_end_every_category_on_core_fixtures(roslyn_helper):
    web, api = _tags(False)
    missing = (WEB - web) | (API - api)
    assert missing == PENDING_CONFIG_BRANCH, _missing_msg(web, api)


def test_degraded_categories(monkeypatch):
    monkeypatch.setattr("checks.dnl.helper.find_helper", lambda *a, **k: None)
    monkeypatch.setattr("checks.dnl.helper.sdk_available", lambda *a, **k: False)
    web, api = _tags(True)
    missing = (WEB - web) | (API - api)
    assert missing == PENDING_CONFIG_BRANCH | HELPER_ONLY_CATEGORIES, _missing_msg(web, api)
