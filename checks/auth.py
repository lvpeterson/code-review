"""Shared, framework-agnostic auth-coverage heuristics.

Each analyzer tells us what "looks like an auth control" for its framework
(decorator names, middleware names, annotation names -- e.g. @login_required
for Flask, @PreAuthorize for Spring, an `authMiddleware` entry for Express)
via `known_auth_indicators`. These checks then just look for the absence of
any of those on a given route.
"""
from __future__ import annotations

from core.models import Finding, Route

# Verbs that typically mutate or return sensitive data -- worth flagging
# more loudly than a GET on public/static content.
_SENSITIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def check_missing_auth_indicator(routes: list[Route], known_auth_indicators: set[str]) -> list[Finding]:
    """Flag routes with no recognized auth decorator/middleware attached.

    This is a coverage check, not proof of a vuln -- plenty of routes are
    intentionally public (health checks, login itself, static assets).
    TODO: let analyzers pass an allowlist of intentionally-public paths.
    """
    findings: list[Finding] = []
    for route in routes:
        if any(indicator in known_auth_indicators for indicator in route.auth_decorators):
            continue

        severity = "medium" if _SENSITIVE_METHODS & set(route.methods) else "low"
        findings.append(
            Finding(
                check_id="AUTH-001",
                severity=severity,
                title="No recognized auth control detected on route",
                description=(
                    "No known auth decorator/middleware/annotation was found on this "
                    "route. Confirm whether it's intentionally public; if not, check "
                    "for auth enforced elsewhere (global middleware, gateway, base class)."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
