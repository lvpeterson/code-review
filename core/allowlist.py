"""Filters out AUTH-001 findings for routes the user has explicitly told us
are intentionally public (health checks, login endpoints, public webhooks,
...) via glob patterns matched against the route path -- addresses the TODO
in checks/auth.py: without this, the same intentionally-public routes get
reflagged on every single run with no way to permanently mark them clean.
"""
from __future__ import annotations

import fnmatch

from core.models import ScanResult


def apply_allowlist(results: list[ScanResult], patterns: list[str]) -> None:
    """Mutate `results` in place, dropping AUTH-001 findings for any route
    whose path matches one of `patterns` (fnmatch-style wildcards -- `*`
    and `?` -- e.g. "/health", "/api/public/*", "/webhooks/*").

    Deliberately only touches AUTH-001: an allowlisted route being public
    on purpose doesn't mean its IDOR-001 candidacy or a CONFIG-* finding
    stops mattering.
    """
    if not patterns:
        return
    for result in results:
        result.findings = [
            f for f in result.findings
            if not (f.check_id == "AUTH-001" and f.route and _matches_any(f.route.path, patterns))
        ]


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
