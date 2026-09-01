"""Framework-agnostic project-level misconfiguration findings -- debug mode
left on, CORS allowing all origins, etc. These aren't tied to a specific
route (unlike IDOR-001/AUTH-001), so `Finding.route` stays None; each
analyzer detects its own framework-specific statement and calls the
matching helper here to build the Finding consistently.
"""
from __future__ import annotations

from core.models import Finding


def debug_mode_finding(file: str, line: int, description: str) -> Finding:
    return Finding(
        check_id="CONFIG-001",
        severity="medium",
        title="Debug mode appears to be enabled",
        description=(
            f"{description}. Debug mode typically exposes stack traces, source "
            "snippets, and an interactive debugger/console to anyone who can "
            "trigger an error -- confirm this isn't enabled in production."
        ),
        file=file,
        line=line,
    )


def cors_wildcard_finding(file: str, line: int, description: str) -> Finding:
    return Finding(
        check_id="CONFIG-002",
        severity="medium",
        title="CORS appears to allow all origins",
        description=(
            f"{description}. Allowing any origin lets any website make "
            "authenticated cross-origin requests on a visitor's behalf if "
            "credentials/cookies are also allowed -- confirm this is intended."
        ),
        file=file,
        line=line,
    )


def outdated_framework_finding(
    file: str, line: int, severity: str, framework_label: str, version: str, note: str
) -> Finding:
    return Finding(
        check_id="CONFIG-003",
        severity=severity,
        title=f"{framework_label} {version} detected",
        description=note,
        file=file,
        line=line,
    )
