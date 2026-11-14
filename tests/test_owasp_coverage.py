"""Every OWASP category (Web 2025, Web 2021, API 2023) has a DNL- rule, and
the dotnet_legacy README coverage table matches RULES exactly."""
from __future__ import annotations

from pathlib import Path

from core import owasp_web
from core.owasp_web import TITLES

README = Path(__file__).resolve().parent.parent / "languages" / "dotnet_legacy" / "README.md"
_LISTS = ("2025", "2021", "api2023")


def rules_for(rules, key: str, code: str) -> list[str]:
    """Sorted DNL- rule ids mapping to `code` in list `key` (API: either mode)."""
    idx = {"2025": 0, "2021": 1, "api2023": 2}[key]
    return sorted(r for r, v in rules.items() if r.startswith("DNL-") and v[idx] == code)


def uncovered(rules) -> list[str]:
    return [
        f"{key} {code} ({title}) has no DNL- rule"
        for key in _LISTS
        for code, title in TITLES[key].items()
        if not rules_for(rules, key, code)
    ]


def test_every_category_has_a_rule():
    missing = uncovered(owasp_web.RULES)
    assert not missing, f"uncovered categories: {missing}"


def test_coverage_check_names_a_dropped_category(monkeypatch):
    only = rules_for(owasp_web.RULES, "api2023", "API6")
    assert only, "API6 should currently be covered"
    reduced = {r: v for r, v in owasp_web.RULES.items() if r not in only}
    monkeypatch.setattr(owasp_web, "RULES", reduced)
    missing = uncovered(owasp_web.RULES)
    assert len(missing) == 1 and "API6" in missing[0] and "api2023" in missing[0], missing


def test_readme_coverage_table_matches_rules():
    rows = {}
    for ln in README.read_text(encoding="utf-8").splitlines():
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if ln.startswith("| ") and len(cells) == 4 and cells[0] in _LISTS:
            rows[(cells[0], cells[1])] = [x.strip() for x in cells[3].split(",") if x.strip()]
    for key in _LISTS:
        for code in TITLES[key]:
            assert (key, code) in rows, f"{key} {code} missing from README coverage table"
            assert rows[(key, code)] == rules_for(owasp_web.RULES, key, code), (key, code)
    assert len(rows) == sum(len(TITLES[k]) for k in _LISTS)
