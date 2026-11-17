"""DNL rule ids count for the dotnet family only when the module that holds
them is reachable by imports from languages/dotnet (not from dotnet_legacy)."""
from __future__ import annotations

import owasp_inventory as inv
from core.owasp_web import RULES


def test_dotnet_counts_reachable_dnl_ids():
    ids = inv.dnl_ids_for_dotnet()
    assert "DNL-AUTHZ-001" in ids
    assert "DNL-AUTHZ-008" in ids
    # Legacy-only modules (WCF and Web.config rules) must not leak in.
    assert "DNL-WCF-001" not in ids
    assert "DNL-CFG-001" not in ids


def test_inventory_counts_plan2_ids():
    ids = inv.dnl_ids_for_dotnet()
    for rid in ("DNL-INJ-001", "DNL-XSS-003", "DNL-AUTHZ-005", "DNL-AUTHZ-006", "DNL-AUTHZ-007"):
        assert rid in ids, rid
    assert "DNL-WCF-001" not in ids
    assert "DNL-CFG-001" not in ids


def test_dotnet_row_nonempty_and_api5():
    row = next(r for r in inv.coverage_rows(RULES) if r.startswith("| dotnet |"))
    cells = [c.strip() for c in row.strip("|").split("|")]
    assert int(cells[1]) >= 5
    assert "API5" in cells[4].split()


def test_unreachable_module_not_counted(monkeypatch):
    real = inv._dnl_imports

    def without_auth_core_rules(path):
        mods = set(real(path))
        if path.as_posix().endswith("languages/dotnet/analyzers.py"):
            mods.discard("rules_auth_core")
        return mods

    monkeypatch.setattr(inv, "_dnl_imports", without_auth_core_rules)
    assert "DNL-AUTHZ-008" not in inv.dnl_ids_for_dotnet()
