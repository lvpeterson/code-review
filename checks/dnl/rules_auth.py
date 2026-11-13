"""AUTHZ and CSRF rules for MVC 5 / Web API 2 routes, on top of auth.resolve."""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Callable

from checks.dnl import auth
from checks.dnl.findings import dnl_finding
from checks.dnl.ir import Attr, TypeIR
from checks.dnl.project import ProjectModel
from checks.dnl.routes import RouteRef
from checks.dnl.webconfig import load_configs
from core.models import Finding

_VERB_ATTRS = {f"http{v}" for v in ("get", "post", "put", "delete", "patch", "head", "options")} | {"acceptverbs"}
_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}
_SENSITIVE_CONTROLLER = re.compile(r"(?i)admin|manage|role|permission|setting|config")
_SENSITIVE_ACTION = re.compile(r"(?i)^(delete|remove|purge|approve|grant|revoke|reset)")
_ANTIFORGERY = {"ValidateAntiForgeryToken", "ValidateAntiForgeryTokenAttribute"}
_UNPROTECTED_PAGE = "No web.config authorization rule or code-behind check covers this page."
_UNPROTECTED_WCF = ("No [PrincipalPermission], in-operation check, serviceAuthorization behavior with "
                    "credentialed bindings or web.config rule covers this operation.")
_UNPROTECTED = "No [Authorize], global filter, base controller or web.config rule covers this action."


def _explicit_mutating(ref: RouteRef) -> bool:
    """Verbs come from a verb attribute (not the GET+POST / name-prefix default) and include a mutating one."""
    if ref.method is None or not any(auth.strip_attr(a.name) in _VERB_ATTRS for a in ref.method.attributes):
        return False
    return bool(_mutating_verbs(ref))


def _mutating_verbs(ref: RouteRef) -> str:
    return ", ".join(sorted(_MUTATING & {v.upper() for v in ref.route.methods}))


def _is_antiforgery(model: ProjectModel, name: str) -> bool:
    if auth.strip_attr(name) == "validateantiforgerytoken":
        return True
    simple = name.split(".")[-1]
    return any(model.derives_from(t, _ANTIFORGERY)
               for n in (simple, simple + "Attribute") for t in model.find_types(n))


def _has_antiforgery(model: ProjectModel, ref: RouteRef, filters: list[auth.GlobalFilter]) -> bool:
    types: list[TypeIR] = [ref.type] + [bt for b in model.base_chain(ref.type) for bt in model.find_types(b)]
    attrs: list[Attr] = list(ref.method.attributes if ref.method else [])
    for t in types:
        attrs.extend(t.attributes)
    if any(_is_antiforgery(model, a.name) for a in attrs):
        return True
    return any(kind == "mvc" and _is_antiforgery(model, name) for kind, name, _, _ in filters)


def check_routes(model: ProjectModel, refs: list[RouteRef], filters: list[auth.GlobalFilter],
                 chain_for: Callable[[RouteRef], list[ET.Element]]) -> list[Finding]:
    out: list[Finding] = []
    configs = None  # loaded lazily, only WebForms pages need the raw configs

    # AUTHZ-003: auth filters whose code lets everything through, used or not.
    for name, t in sorted(auth.auth_attribute_types(model).items()):
        if auth.never_denies(t, model):
            out.append(dnl_finding(
                "DNL-AUTHZ-003", "high", f"Auth filter {t.name} never denies a request",
                f"{t.name} derives from an authorization filter but its override always allows the request "
                "(no deny path, no base call). Every action decorated with it is effectively anonymous.",
                t.file, t.line))

    for ref in refs:
        r = ref.route
        webforms = r.meta.get("kind") == "webforms"
        wcf = r.meta.get("kind") == "wcf"
        if webforms or wcf:
            if configs is None:
                configs = load_configs(model.root)
            info = (auth.resolve_webforms if webforms else auth.resolve_wcf)(model, ref, configs)
        else:
            info = auth.resolve(model, ref, filters, chain_for)
        r.auth_decorators = [info.source] if info.protected else []
        api = bool(r.meta.get("api_surface", False))
        mutating = _explicit_mutating(ref)
        kw = {"route": r, "api_surface": api}

        if info.anonymous:
            # R5: explicitly public routes are still listed, at info.
            out.append(dnl_finding(
                "DNL-AUTHZ-001", "info", f"Anonymous action {r.handler_name}",
                f"{r.handler_name} ({', '.join(r.methods)} {r.path}) is explicitly public via "
                "[AllowAnonymous]; confirm this is intended.", r.file, r.line, **kw))
            if mutating:
                out.append(dnl_finding(
                    "DNL-AUTHZ-002", "medium", f"Anonymous state-changing action {r.handler_name}",
                    f"{r.handler_name} accepts {_mutating_verbs(ref)} without "
                    "authentication ([AllowAnonymous]). Confirm anonymous callers may change state here.",
                    r.file, r.line, confidence="REVIEW", **kw))
        elif not info.protected:
            why = _UNPROTECTED_PAGE if webforms else _UNPROTECTED_WCF if wcf else _UNPROTECTED
            if info.source != "none":
                why += f" The only candidate ({info.source}) never denies a request."
            out.append(dnl_finding(
                "DNL-AUTHZ-001", "high" if mutating else "medium", f"Unauthenticated action {r.handler_name}",
                f"{r.handler_name} ({', '.join(r.methods)} {r.path}): {why}", r.file, r.line, **kw))
        elif info.review:
            # R17: protection inferred from code (hand-rolled check) -- a human confirms it.
            what = info.detail or info.source
            out.append(dnl_finding(
                "DNL-AUTHZ-001", "low", f"Action {r.handler_name} relies on an inferred auth check",
                f"{r.handler_name} ({', '.join(r.methods)} {r.path}): Protected only by {what} "
                f"({info.source}); the check was inferred from code -- verify it actually denies "
                "unauthenticated requests.", r.file, r.line, confidence="REVIEW", **kw))

        # AUTHZ-004: authenticated-only gate on something that smells privileged.
        if (ref.type is not None and info.protected and info.source.startswith(("attribute:", "base:"))
                and not info.roles and not info.users):
            ctl = ref.type.name.split(".")[-1]
            ctl = ctl[: -len("controller")] if ctl.lower().endswith("controller") else ctl
            action = ref.method.name if ref.method else ""
            if _SENSITIVE_CONTROLLER.search(ctl) or _SENSITIVE_ACTION.search(action):
                out.append(dnl_finding(
                    "DNL-AUTHZ-004", "low", f"Privileged-looking action {r.handler_name} has no role check",
                    f"{r.handler_name} is protected by {info.source} with no Roles or Users, so any "
                    "authenticated user can call it. Confirm no finer-grained check is needed.",
                    r.file, r.line, confidence="REVIEW", **kw))

        # CSRF-001: MVC form posts without anti-forgery validation (Web API is token/header based).
        if r.meta.get("kind") == "mvc" and mutating and not _has_antiforgery(model, ref, filters):
            out.append(dnl_finding(
                "DNL-CSRF-001", "medium", f"State-changing MVC action {r.handler_name} lacks anti-forgery validation",
                f"{r.handler_name} accepts {_mutating_verbs(ref)} but no "
                "[ValidateAntiForgeryToken] on the action, controller, base controllers or global filters.",
                r.file, r.line, **kw))
    return out
