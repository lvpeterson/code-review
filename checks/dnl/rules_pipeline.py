"""Aggregator of the ASP.NET Core configuration rules: builds the shared context once, then runs each
rule group in a fixed order. A group that crashes adds a model note (its findings are missing) and
never hides the others. Later tasks add their group to _GROUPS.
"""
from __future__ import annotations

from checks.dnl.cfgctx import Ctx, build_ctx
from checks.dnl.project import ProjectModel
from checks.dnl.routes_core import CoreRouteRef
from core.models import Finding

# (name, fn(ctx)) in run order; each fn appends to ctx.out.
_GROUPS: list = []


def check(model: ProjectModel, refs: list[CoreRouteRef]) -> list[Finding]:
    ctx: Ctx = build_ctx(model, refs)
    for name, fn in _GROUPS:
        try:
            fn(ctx)
        except Exception as exc:  # noqa: BLE001
            note = f"{name} failed ({type(exc).__name__}: {exc}); its findings are missing"
            if note not in model.notes:
                model.notes.append(note)
    return ctx.out
