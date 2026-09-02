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
_ID_WORDS = {"id", "ids", "uid", "uuid", "guid"}
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _is_id_like(param_name: str) -> bool:
    # kebab-case is a common URL path-segment convention (`{order-id}`), so
    # split on hyphens too -- otherwise "order-id" is treated as one opaque
    # word and never matches "id", even though it plainly is one.
    words = _CAMEL_BOUNDARY.sub("_", param_name).replace("-", "_").split("_")
    return any(w.lower() in _ID_WORDS for w in words if w)


def find_id_like_params(route: Route) -> list[str]:
    """Id-like names from the path only -- kept for anything that still
    wants just that (e.g. the HTML report highlights path params
    specifically, since those are the ones it can underline in the URL).
    """
    return [name for name in extract_path_param_names(route.path) if _is_id_like(name)]


def check_id_param_routes(routes: list[Route]) -> list[Finding]:
    """Flag routes that take an object id via the path *or* a query-string/
    body/form field -- classic IDOR candidates either way. `Route.path`
    covers the former; `Route.extra_param_names` (best-effort, populated per
    analyzer -- see each `_extract_extra_params`-style helper) covers the
    latter, since `/search?user_id=123` or a JSON body `{"user_id": 123}`
    is just as much an object reference as `/users/<user_id>`.

    TODO: extend this to inspect the handler body (once analyzers capture
    it) for an ownership check like `if resource.owner_id != current_user.id`.
    """
    findings: list[Finding] = []
    for route in routes:
        path_ids = [name for name in extract_path_param_names(route.path) if _is_id_like(name)]
        extra_ids = [name for name in route.extra_param_names if _is_id_like(name)]
        if not path_ids and not extra_ids:
            continue

        if path_ids and extra_ids:
            where = f"path parameter(s) {', '.join(path_ids)} and query/body field(s) {', '.join(extra_ids)}"
        elif path_ids:
            where = f"path parameter(s) {', '.join(path_ids)}"
        else:
            where = f"query/body field(s) {', '.join(extra_ids)}"

        findings.append(
            Finding(
                check_id="IDOR-001",
                severity="info",
                title=f"Route takes object identifier(s) via {where}",
                description=(
                    "Verify the handler checks that the authenticated user actually "
                    "owns/may access the referenced object before returning or "
                    "mutating it."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
