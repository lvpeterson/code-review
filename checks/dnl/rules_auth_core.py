"""AUTHZ rules for ASP.NET Core routes, on top of auth_core.resolve (three-state).

Mirrors rules_auth (the legacy MVC / Web API rules) for ids and severities: every unprotected route
gets DNL-AUTHZ-001, an UNKNOWN one gets DNL-AUTHZ-001 as a medium REVIEW item (never silence), an
explicitly anonymous one gets info (and DNL-AUTHZ-002 when it mutates). Routes that only exist when
the environment is Development get no AUTHZ finding.
"""
from __future__ import annotations


from checks.dnl import auth_core
from checks.dnl.auth_core import ANONYMOUS, PROTECTED, UNKNOWN, _sensitive
from checks.dnl.findings import dnl_finding
from checks.dnl.pipeline import pipeline_for
from checks.dnl.project import ProjectModel
from checks.dnl.routes_core import CoreRouteRef
from core.models import Finding

_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}
_UNPROTECTED = ("No [Authorize], RequireAuthorization (endpoint, group or Map call), global filter, "
                "Razor Pages convention or fallback policy covers this route.")


def _mutating_verbs(route) -> str:
    return ", ".join(sorted(_MUTATING & {v.upper() for v in route.methods}))


def _route_findings(ref: CoreRouteRef, info: auth_core.CoreAuth) -> list[Finding]:
    r = ref.route
    kw = {"route": r, "api_surface": bool(r.meta.get("api_surface", False))}
    mutating = bool(_MUTATING & {v.upper() for v in r.methods})
    where = f"{r.handler_name} ({', '.join(r.methods)} {r.path})"
    notes = f" Notes: {'; '.join(info.notes)}." if info.notes else ""
    out: list[Finding] = []

    if info.state == ANONYMOUS:
        out.append(dnl_finding(
            "DNL-AUTHZ-001", "info", f"Anonymous action {r.handler_name}",
            f"{where} is explicitly public via {info.source}; confirm this is intended.{notes}",
            r.file, r.line, **kw))
        if mutating:
            out.append(dnl_finding(
                "DNL-AUTHZ-002", "medium", f"Anonymous state-changing action {r.handler_name}",
                f"{r.handler_name} accepts {_mutating_verbs(r)} without authentication ({info.source}). "
                "Confirm anonymous callers may change state here.", r.file, r.line, confidence="REVIEW", **kw))
    elif info.state == UNKNOWN:
        out.append(dnl_finding(
            "DNL-AUTHZ-001", "medium", f"Authentication of {r.handler_name} could not be determined",
            f"{where}: authorization could not be resolved, so this route may be unprotected. Reasons: "
            f"{'; '.join(info.reasons) or 'unspecified'}.{notes}", r.file, r.line, confidence="REVIEW", **kw))
    elif info.state != PROTECTED:
        why = _UNPROTECTED
        if info.source != "none":
            why += f" The only candidate ({info.source}) does not protect it."
        out.append(dnl_finding(
            "DNL-AUTHZ-001", "high" if mutating else "medium", f"Unauthenticated action {r.handler_name}",
            f"{where}: {why}{notes}", r.file, r.line, **kw))

    # AUTHZ-004: authenticated-only gate on something that smells privileged.
    if (info.state == PROTECTED and not info.roles and not info.policies
            and ref.style in ("controller", "razorpage") and _sensitive(ref)):
        out.append(dnl_finding(
            "DNL-AUTHZ-004", "low", f"Privileged-looking action {r.handler_name} has no role or policy",
            f"{r.handler_name} is protected by {info.source} with no Roles or Policy, so any authenticated "
            "user can call it. Confirm no finer-grained check is needed.",
            r.file, r.line, confidence="REVIEW", **kw))
    return out


def _project_findings(model: ProjectModel) -> list[Finding]:
    """Route-less findings: never-denying handlers, policies and filters (AUTHZ-003), the middleware
    order of each pipeline (AUTHZ-008)."""
    out: list[Finding] = []
    for t in auth_core.never_denying_handlers(model):
        out.append(dnl_finding(
            "DNL-AUTHZ-003", "high", f"Authorization handler {t.name} never denies a request",
            f"{t.name} succeeds on every path and never calls Fail, so every requirement it handles is "
            "always satisfied and the policies using it protect nothing.", t.file, t.line))
    for t in auth_core.never_denying_filters(model):
        out.append(dnl_finding(
            "DNL-AUTHZ-003", "high", f"Authorization filter {t.name} never denies a request",
            f"{t.name} implements an authorization filter but never sets context.Result (no deny path), so "
            "every action it decorates is effectively anonymous.", t.file, t.line))
    seen: set[tuple] = set()
    for proj in model.projects:
        pipe = pipeline_for(model, proj)
        for name, pol in sorted(auth_core.policies(model, pipe).items()):
            if pol.never_denies and (name, pol.file, pol.line) not in seen:
                seen.add((name, pol.file, pol.line))
                out.append(dnl_finding(
                    "DNL-AUTHZ-003", "high", f"Authorization policy {name} never denies a request",
                    f"Policy \"{name}\" is built only from requirements that always succeed"
                    + (f" ({pol.why})" if pol.why else "") + ". Routes using it are effectively anonymous.",
                    pol.file, pol.line))
        issue = auth_core.middleware_issue(pipe)
        if issue is not None and (issue[0], issue[1], issue[2]) not in seen:
            msg, file, line, suppressed = issue
            seen.add((msg, file, line))
            extra = (" SuppressCheckForUnhandledSecurityMetadata is true, so endpoints with authorization "
                     "metadata run unprotected instead of failing." if suppressed else
                     " Endpoints carrying authorization metadata fail at request time instead of being protected.")
            out.append(dnl_finding(
                "DNL-AUTHZ-008", "high" if suppressed else "medium", "Authorization middleware misconfigured",
                msg + "." + extra, file, line, api_surface=True))
    return out


def _failed(ref: CoreRouteRef, exc: Exception) -> list[Finding]:
    """A route whose resolution or finding building crashed: never silent, never protected."""
    r = ref.route
    r.auth_decorators = []
    r.explicit_access = None
    r.meta["auth"] = {"state": UNKNOWN, "source": "none", "reasons": [f"{type(exc).__name__}: {exc}"], "notes": []}
    if r.meta.get("env") == "Development":
        return []
    return [dnl_finding(
        "DNL-AUTHZ-001", "medium", f"Authentication of {r.handler_name} could not be determined",
        f"{r.handler_name} ({', '.join(r.methods)} {r.path}): authorization analysis failed "
        f"({type(exc).__name__}: {exc}), so this route may be unprotected. Review it by hand.",
        r.file, r.line, confidence="REVIEW", route=r, api_surface=bool(r.meta.get("api_surface", False)))]


def check(model: ProjectModel, refs: list[CoreRouteRef]) -> list[Finding]:
    out: list[Finding] = []
    for ref in refs:
        r = ref.route
        try:
            info = auth_core.resolve(model, ref, pipeline_for(model, ref.project))
            found = [] if r.meta.get("env") == "Development" else _route_findings(ref, info)
        except Exception as exc:  # noqa: BLE001
            out += _failed(ref, exc)
            continue
        r.auth_decorators = [info.source] if info.state == PROTECTED else []
        if info.state == ANONYMOUS:
            r.explicit_access = "PermitAll"
        r.meta["auth"] = {"state": info.state, "source": info.source, "reasons": list(info.reasons),
                          "notes": list(info.notes)}
        out += found
    try:
        out += _project_findings(model)
    except Exception as exc:  # noqa: BLE001
        note = f"route-less authorization rules failed ({type(exc).__name__}: {exc}); their findings are missing"
        if note not in model.notes:
            model.notes.append(note)
    return out
