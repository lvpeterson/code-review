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
from core.paths import extract_path_param_names

# The id/uuid/guid check is a whole-word check (not substring), since
# "valid", "width", "hidden", "provider" etc all contain "id"/"uuid"-ish
# substrings without being object identifiers at all.
_ID_WORDS = {"id", "ids", "uuid", "guid"}
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _is_id_like(param_name: str) -> bool:
    words = _CAMEL_BOUNDARY.sub("_", param_name).split("_")
    return any(w.lower() in _ID_WORDS for w in words if w)


def find_id_like_params(route: Route) -> list[str]:
    return [name for name in extract_path_param_names(route.path) if _is_id_like(name)]


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
