"""Logging, business-flow, resource, inventory and API-consumption rules (DNL-LOG-002..004, DES-001,
RES-002..003, INV-002, CONSUME-001..002), one entry point for the analyzers.

The work lives in three modules: rules_logging (LOG-*), rules_flows (DES-001, CONSUME-*) and
rules_resources (RES-002/003, INV-002); flowutil holds what they share. In degraded mode (no Roslyn
helper) every rule still runs, on the tree-sitter C# IR, gated on model.files; only VB sources have no IR.
"""
from __future__ import annotations

from checks.dnl import rules_flows, rules_logging, rules_resources
from core.models import Finding


def check(model, refs=(), configs=()) -> tuple[list[Finding], list[str]]:
    """(findings, notes). `configs` are the loaded web.config files (checks.dnl.webconfig.load_configs)."""
    out: list[Finding] = []
    if model.files:
        out += rules_logging.check(model, refs)
    else:
        out += rules_logging.check_log002(model)
    out += rules_flows.check(model, refs, configs)
    out += rules_resources.check(model, refs, configs)
    return out, []
