"""Shared, framework-agnostic IDOR heuristics.

These operate purely on the Route objects an analyzer already extracted, so
they work the same way whether the route came from Flask, Spring, or Express.
They are deliberately shallow (regex/naming heuristics) -- the goal is to
flag candidates for a human to look at, not to prove exploitability. Add
framework-specific IDOR checks (e.g. "does the handler body compare the path
id against request.user") alongside these in each analyzer.
"""
from __future__ import annotations

import re

from core.models import Finding, Route

# Path segments that look like they carry an object identifier, e.g.
# /users/<id>, /users/{userId}, /users/:id, /orders/{order_id}
_ID_PARAM_PATTERN = re.compile(r"[:{<]([a-zA-Z_]*(?:id|uuid|guid)[a-zA-Z_]*)[}>]?", re.IGNORECASE)


def find_id_like_params(route: Route) -> list[str]:
    return [m.group(1) for m in _ID_PARAM_PATTERN.finditer(route.path)]


def check_id_param_routes(routes: list[Route]) -> list[Finding]:
    """Flag routes whose path takes an object id -- classic IDOR candidates.

    TODO: extend this to inspect the handler body (once analyzers capture
    it) for an ownership check like `if resource.owner_id != current_user.id`.
    """
    findings: list[Finding] = []
    for route in routes:
        id_params = find_id_like_params(route)
        if not id_params:
            continue
        findings.append(
            Finding(
                check_id="IDOR-001",
                severity="info",
                title=f"Route takes object identifier(s): {', '.join(id_params)}",
                description=(
                    "Path includes an id-like parameter. Verify the handler checks "
                    "that the authenticated user actually owns/may access the "
                    "referenced object before returning or mutating it."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
