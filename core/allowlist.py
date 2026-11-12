"""Filters out AUTH-001 findings for routes the user has explicitly told us
are intentionally public (health checks, login endpoints, public webhooks,
...) via glob patterns matched against the route path -- addresses the TODO
in checks/auth.py: without this, the same intentionally-public routes get
reflagged on every single run with no way to permanently mark them clean.
"""
from __future__ import annotations

import fnmatch

from core.models import ScanResult

# Missing-authentication check ids the allowlist may suppress: the generic
# AUTH-001 and the .NET legacy analyzer's DNL-AUTHZ-001.
MISSING_AUTH_IDS = {"AUTH-001", "DNL-AUTHZ-001"}


def apply_allowlist(results: list[ScanResult], patterns: list[str]) -> None:
    """Mutate `results` in place, dropping AUTH-001 findings for any route
    whose path matches one of `patterns` (fnmatch-style wildcards -- `*`
    and `?` -- e.g. "/health", "/api/public/*", "/webhooks/*").

    Deliberately only touches the missing-auth ids: an allowlisted route being public
    on purpose doesn't mean its IDOR-001 candidacy or a CONFIG-* finding
    stops mattering.
    """
    if not patterns:
        return
    for result in results:
        result.findings = [
            f for f in result.findings
            if not (f.check_id in MISSING_AUTH_IDS and f.route
                    and _matches_any(f.route.path, patterns, ignore_case=f.check_id.startswith("DNL-")))
        ]


def _matches_any(path: str, patterns: list[str], ignore_case: bool = False) -> bool:
    if ignore_case:
        # ASP.NET routes are case-insensitive; fnmatch.fnmatch only folds case on Windows.
        return any(fnmatch.fnmatchcase(path.lower(), pattern.lower()) for pattern in patterns)
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
