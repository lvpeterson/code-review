"""Shared, framework-agnostic auth-coverage heuristics.

Each analyzer tells us what "looks like an auth control" for its framework
(decorator names, middleware names, annotation names -- e.g. @login_required
for Flask, @PreAuthorize for Spring, an `authMiddleware` entry for Express)
via `known_auth_indicators`. These checks then just look for the absence of
any of those on a given route.
"""
from __future__ import annotations

from core.models import Finding, Route, ScanResult

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


def method_security_not_enabled_finding(file: str, line: int, indicator_names: list[str]) -> Finding:
    """Project-wide, not tied to any one route -- anchored at the first
    place a method-security annotation was actually found, since there's no
    natural location for an *absence*. `indicator_names` is every distinct
    annotation name seen in use (e.g. ["PreAuthorize", "Secured"]), so the
    reader immediately knows what's affected without cross-referencing.
    """
    names = ", ".join(f"@{n}" for n in indicator_names)
    return Finding(
        check_id="AUTH-002",
        severity="high",
        title=f"{names} used, but no @EnableMethodSecurity/@EnableGlobalMethodSecurity found",
        description=(
            "Spring only evaluates @PreAuthorize/@PostAuthorize/@Secured/@RolesAllowed at "
            "all when @EnableMethodSecurity (or the legacy @EnableGlobalMethodSecurity) is "
            "present on some @Configuration class. Without it, every one of these "
            "annotations is pure decoration -- the routes using them look protected but "
            "aren't. This check scanned the entire target and found none; if that's a false "
            "negative (an unusual location, a different module not included in this scan), "
            "verify manually before treating every AUTH-annotated route as unauthorized."
        ),
        file=file,
        line=line,
        route=None,
    )


def csrf_disabled_finding(file: str, line: int) -> Finding:
    return Finding(
        check_id="AUTH-003",
        severity="medium",
        title="CSRF protection appears to be disabled",
        description=(
            "Found a `.csrf(...).disable()`/`.csrf().disable()` call. This is normal and "
            "correct for a pure stateless bearer-token API (JWT in an Authorization header, "
            "no cookies involved) -- but if any part of this application also uses "
            "cookie-based session authentication, disabling CSRF reopens a real "
            "cross-site-request-forgery hole. Confirm which auth mechanism is actually in "
            "play here before treating this as fine."
        ),
        file=file,
        line=line,
        route=None,
    )


def actuator_exposure_finding(file: str, line: int, exposed: str) -> Finding:
    return Finding(
        check_id="AUTH-004",
        severity="high" if "*" in exposed else "medium",
        title=f"Actuator endpoint(s) exposed: {exposed}",
        description=(
            f"`management.endpoints.web.exposure.include` includes {exposed}. Exposed "
            "Actuator endpoints commonly leak environment variables/secrets (`env`), full "
            "heap dumps (`heapdump`), bean wiring and internal config (`beans`, "
            "`configprops`), or your entire route map (`mappings`) -- and some (`shutdown`) "
            "let a caller stop the application outright. Confirm these are actually "
            "protected by the security config (see AUTH-005 if a matcher check was run) or "
            "narrow this list to only what monitoring actually needs (typically `health`)."
        ),
        file=file,
        line=line,
        route=None,
    )


def actuator_not_covered_finding(file: str, line: int, verdict: str) -> Finding:
    return Finding(
        check_id="AUTH-005",
        severity="high",
        title=f"Actuator base path resolves to \"{verdict}\" in the security matcher chain",
        description=(
            "The parsed SecurityFilterChain matcher rules resolve the Actuator base path "
            "(/actuator/**) to a rule that doesn't require authentication. Combined with "
            "whatever's actually exposed (see AUTH-004), this means those endpoints are "
            "reachable by anyone. This resolution is regex-based and best-effort -- verify "
            "against the actual chain before treating it as certain."
        ),
        file=file,
        line=line,
        route=None,
    )


def apply_matcher_verdict(finding: Finding, verdict: str) -> None:
    """Fold a resolved SecurityFilterChain matcher verdict into an existing
    AUTH-001 finding for one route -- downgrading its severity/wording once
    we actually know (not just suspect) how the global chain treats this
    specific path, rather than leaving every route with the same generic
    "go check" caveat regardless of how confident the resolution is.
    """
    lowered = verdict.lower()
    if lowered.startswith("permitall"):
        finding.severity = "info"
        finding.title = "Route explicitly public per SecurityFilterChain (permitAll)"
        finding.description = (
            f"The global SecurityFilterChain's matcher rules resolve this path to "
            f"`{verdict}` -- it's explicitly, intentionally public per the security config, "
            "not an accidental gap. Confirm that's actually the intent for this specific "
            "route."
        )
    elif lowered.startswith("denyall"):
        finding.severity = "low"
        finding.title = "Route resolves to denyAll() per SecurityFilterChain"
        finding.description = (
            f"The global SecurityFilterChain's matcher rules resolve this path to "
            f"`{verdict}` -- nobody can reach it through this rule. Likely dead code or a "
            "route that's meant to go through a different path; not a security gap as such."
        )
    else:
        finding.severity = "low"
        finding.title = f"Route covered by SecurityFilterChain ({verdict}), no per-method annotation"
        finding.description = (
            f"No @PreAuthorize/@Secured/etc annotation on this route, but the global "
            f"SecurityFilterChain's matcher rules resolve this path to `{verdict}` -- it "
            "does appear to require authentication at the global level. This resolution is "
            "regex-based and best-effort (matcher patterns built from variables/loops rather "
            "than literal strings won't resolve); verify against the actual chain before "
            "fully trusting it."
        )


def apply_global_auth_note(result: ScanResult, file: str, line: int, description: str) -> None:
    """Attach a "this project has some global auth mechanism" caveat to a
    scan result: stored structurally on `result.global_auth_source` so the
    HTML report can render a real "open in editor" link to it (the same way
    it links route code), and appended in plain text -- file:line included,
    so it's readable without cross-referencing anything -- to every AUTH-001
    finding's description.

    This is deliberately presence-only, not per-route -- we know *something*
    that plausibly enforces auth globally exists at this exact location, not
    which specific routes it actually covers (that needs simulating each
    framework's real path-matching/registration-order semantics, which is a
    lot of surface area for a heuristic tool to get wrong silently). Treat
    this as "go check this file," not "this route is covered."
    """
    result.global_auth_source = (file, line, description)
    caveat = (
        f" Note: {file}:{line} defines what looks like a global auth mechanism "
        f"({description}) -- verify this route isn't already covered by it "
        f"before treating this as a real gap."
    )
    for finding in result.findings:
        if finding.check_id == "AUTH-001":
            finding.description += caveat
