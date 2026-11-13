"""Effective authorization for MVC 5 / Web API 2 routes.

For each route this walks the places a legacy ASP.NET app can put an auth
decision, most specific first: [AllowAnonymous] on the action or controller,
an auth attribute on the action / controller / base controllers, a global
filter registered in FilterConfig or WebApiConfig, a web.config
<authorization> rule, and finally a hand-rolled OnAuthorization override on a
base controller. Custom attributes are only trusted when their own code can
actually deny a request (see never_denies).

All type, attribute and member names compare case-insensitively (VB).
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Callable

from checks.dnl.ir import Attr, MethodIR, TypeIR, attr_key, attr_simple, call_name, has_attr, literal_str, receiver_text, walk
from checks.dnl.project import ProjectModel
from checks.dnl.routes import RouteRef
from checks.dnl.webconfig import LINE, ORIGIN, anonymous_denied, config_chain, load_configs

_AUTH_BASES = {"AuthorizeAttribute", "AuthorizationFilterAttribute", "IAuthorizationFilter", "IAuthenticationFilter"}
_DECIDE_METHODS = {"authorizecore", "isauthorized"}
_CACHE_ATTR = "_dnl_auth_types"

# (kind, type_name, file, line)
GlobalFilter = tuple[str, str, str, int]


@dataclass
class AuthInfo:
    protected: bool
    source: str
    roles: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    anonymous: bool = False
    review: bool = False
    file: str | None = None
    line: int | None = None
    # For review=True: what was inferred, e.g. "a hand-rolled check in Base.OnAuthorization".
    detail: str | None = None


def strip_attr(name: str) -> str:
    """`Foo.BarAttribute` -> `bar` (namespace, generic args and suffix dropped, lowered)."""
    return attr_key(name)


# -- auth attribute types -----------------------------------------------------

def auth_attribute_types(model: ProjectModel) -> dict[str, TypeIR]:
    """Project types that act as auth filters, keyed by `strip_attr` name."""
    cached = getattr(model, _CACHE_ATTR, None)
    if cached is not None:
        return cached
    out: dict[str, TypeIR] = {}
    for t in model.types():
        if t.kind == "class" and model.derives_from(t, _AUTH_BASES):
            out.setdefault(strip_attr(t.name), t)
    # Stashed on the instance: the model is immutable once prepared.
    setattr(model, _CACHE_ATTR, out)
    return out


def is_auth_attr(model: ProjectModel, name: str) -> bool:
    key = strip_attr(name)
    return key == "authorize" or key in auth_attribute_types(model)


def _methods(t: TypeIR, names: set[str]) -> list[MethodIR]:
    return [m for m in t.methods if m.name.lower() in names]


def _is_true(expr) -> bool:
    return isinstance(expr, dict) and expr.get("k") == "lit" and expr.get("v") is True


def _denies(body: list) -> bool:
    """Does an OnAuthorization body itself reject a request?"""
    for n in walk(body):
        k = n.get("k")
        if k == "throw":
            return True
        if k == "assign":
            tgt = n.get("target") or {}
            if tgt.get("k") == "member" and (tgt.get("name") or "").lower() in ("result", "response"):
                return True
        if k == "call" and (call_name(n) or "").lower() == "handleunauthorizedrequest":
            return True
    return False


def _calls_base_on_authorization(body: list) -> bool:
    for n in walk(body):
        if (n.get("k") == "call" and (call_name(n) or "").lower() == "onauthorization"
                and receiver_text((n.get("fn") or {}).get("obj")).lower() in ("base", "mybase")):
            return True
    return False


def never_denies(t: TypeIR, model: ProjectModel | None = None, _seen: set[str] | None = None) -> bool:
    """True when the type's own code lets every request through.

    An OnAuthorization override that neither denies nor calls the base
    decides everything; otherwise an AuthorizeCore / IsAuthorized override
    whose every `return` is literal true never denies. A type with neither
    inherits the verdict of its project base types (when a model is given).
    """
    on_auth = _methods(t, {"onauthorization"})
    if on_auth:
        bodies = [m.body for m in on_auth]
        if any(_denies(b) for b in bodies):
            return False
        if not any(_calls_base_on_authorization(b) for b in bodies):
            return True
    decide = _methods(t, _DECIDE_METHODS)
    if decide:
        returns = [n for m in decide for n in walk(m.body) if n.get("k") == "return"]
        return bool(returns) and all(_is_true(r.get("value")) for r in returns)
    # An OnAuthorization override that calls base reaches here: the base type decides.
    if model is None:
        return False
    seen = _seen if _seen is not None else {t.name.lower()}
    for b in t.bases:
        if b.lower() in seen:
            continue
        seen.add(b.lower())
        if any(never_denies(bt, model, seen) for bt in model.find_types(b)):
            return True
    return False


# -- global filters -----------------------------------------------------------

def global_filters(model: ProjectModel) -> list[GlobalFilter]:
    """Every `<...>Filters.Add(new X(...))` registration in the solution."""
    out: list[GlobalFilter] = []
    for t in model.types():
        for m in t.methods:
            for n in walk(m.body):
                if n.get("k") != "call" or (call_name(n) or "").lower() != "add":
                    continue
                fn = n.get("fn") or {}
                recv = receiver_text(fn.get("obj")) if fn.get("k") == "member" else ""
                args = n.get("args") or []
                if not recv.lower().endswith("filters") or not args or (args[0] or {}).get("k") != "new":
                    continue
                low = recv.lower()
                webapi = ("config." in low or "globalconfiguration" in low
                          or t.name.split(".")[-1].lower() == "webapiconfig")
                type_name = (args[0].get("type") or "").split("<")[0].split(".")[-1]
                out.append(("webapi" if webapi else "mvc", type_name, t.file, n.get("line") or m.line))
    return out


# -- resolution ---------------------------------------------------------------

def chain_for_model(model: ProjectModel) -> Callable[[RouteRef], list[ET.Element]]:
    """Config chain per route: MVC URLs are not physical paths, so the app
    root config (the project dir) is both app_dir and page_dir."""
    configs = load_configs(model.root)

    def chain_for(ref: RouteRef) -> list[ET.Element]:
        if ref.project is None:
            return []
        return config_chain(configs, ref.project.dir, ref.project.dir)

    return chain_for


def _split_named(a: Attr, key: str) -> list[str]:
    """Roles / Users of an [Authorize]; a non-literal value (Roles = RoleNames.Admin)
    still means a role check exists, so its expression text is kept instead."""
    for k, v in (a.named or {}).items():
        if k.lower() == key:
            s = literal_str(v)
            if s is None:
                return [receiver_text(v) or "<expr>"]
            return [x.strip() for x in s.split(",") if x.strip()]
    return []


def _from_attr(model: ProjectModel, a: Attr, source: str, file: str) -> AuthInfo:
    custom = auth_attribute_types(model).get(strip_attr(a.name))
    protected = not (custom is not None and never_denies(custom, model))
    return AuthInfo(protected, source, _split_named(a, "roles"), _split_named(a, "users"),
                    file=file, line=a.line)


def _base_types(model: ProjectModel, t: TypeIR) -> list[TypeIR]:
    """Project types along the base chain, nearest first."""
    out: list[TypeIR] = []
    for b in model.base_chain(t):
        out.extend(model.find_types(b))
    return out


def _reads_is_authenticated(node) -> bool:
    return any((n.get("k") == "member" and (n.get("name") or "").lower() == "isauthenticated")
               or (n.get("k") == "name" and (n.get("id") or "").lower() == "isauthenticated")
               for n in walk(node))


def _rejects(branch) -> bool:
    """Does an if-branch end the request: set Result/Response, throw, redirect or return?"""
    for n in walk(branch):
        k = n.get("k")
        if k in ("throw", "return"):
            return True
        if k == "assign":
            tgt = n.get("target") or {}
            if tgt.get("k") == "member" and (tgt.get("name") or "").lower() in ("result", "response"):
                return True
        if k == "call":
            name = (call_name(n) or "").lower()
            if name.startswith("redirect") or name == "handleunauthorizedrequest":
                return True
    return False


# Names that make an `if` condition about the caller's identity (R20).
_AUTH_NAMES = {"session", "user", "identity", "isauthenticated", "principal"}
_IDENT = re.compile(r"[A-Za-z_]\w*")


def _cond_tokens(cond) -> set[str]:
    """Lowered identifiers of an if-condition: names, member names, call names and
    the raw text of `unknown` nodes (the VB lowering keeps `Not X.Y` only as text)."""
    out: set[str] = set()
    for n in walk(cond):
        for key in ("id", "name"):
            if isinstance(n.get(key), str):
                out.add(n[key].lower())
        if n.get("k") == "unknown" and isinstance(n.get("text"), str):
            out.update(t.lower() for t in _IDENT.findall(n["text"]))
    return out


def _cond_auth_relevant(cond) -> bool:
    """Does an if-condition reference Session / User / Identity / IsAuthenticated /
    Principal, or IsInRole (case-insensitive name or member match)?"""
    toks = _cond_tokens(cond)
    return bool(toks & _AUTH_NAMES) or "isinrole" in toks


def _cond_checks_caller(cond) -> bool:
    """IsAuthenticated read or IsInRole call in an if-condition (a rejecting branch
    then makes it a check; Session / User alone are left to the login-redirect rule)."""
    return bool(_cond_tokens(cond) & {"isauthenticated", "isinrole"})


def _has_call(branch, names: set[str]) -> bool:
    return any(n.get("k") == "call" and (call_name(n) or "").lower() in names for n in walk(branch))


def _body_checks_auth(body: list, extra_calls: frozenset[str] = frozenset()) -> bool:
    """Does a method body contain an auth check: a Result assignment, or an `if`
    whose condition tests IsAuthenticated or IsInRole and whose branch rejects
    the request. Bare reads (ViewBag fill, a button's
    Visible flag) are not checks. `extra_calls` are call names that count when
    they sit in a branch of an auth-relevant `if` (WebForms: RedirectToLoginPage)."""
    for n in walk(body):
        k = n.get("k")
        if k == "if":
            relevant = _cond_auth_relevant(n.get("cond"))
            branches = (n.get("then"), n.get("else"))
            if _cond_checks_caller(n.get("cond")) and any(_rejects(b) for b in branches):
                return True
            if relevant and extra_calls and any(_has_call(b, set(extra_calls)) for b in branches):
                return True
        if k == "assign":
            tgt = n.get("target") or {}
            if tgt.get("k") == "member" and (tgt.get("name") or "").lower() == "result":
                return True
    return False


def _redirects_to_login(branch) -> bool:
    """A Redirect call whose URL argument contains a "login" literal (Login.aspx, ~/Account/Login?...)."""
    for n in walk(branch):
        if n.get("k") == "call" and (call_name(n) or "").lower() == "redirect":
            if any("login" in (literal_str(a) or "").lower() for arg in (n.get("args") or [])[:1] for a in walk(arg)):
                return True
    return False


def _conditional_login_redirect(body: list) -> bool:
    """An if (or VB Select Case arm) whose condition reads the session / user
    (R20) and whose branch redirects to a login page: the classic session gate
    (`If Session("User") Is Nothing Then Response.Redirect("Login.aspx")`). An
    unconditional redirect (a logout page) or one on an unrelated condition
    (`If helpRequested Then Redirect("LoginHelp.aspx")`) does not count."""
    return any(n.get("k") == "if" and _cond_auth_relevant(n.get("cond"))
               and (_redirects_to_login(n.get("then")) or _redirects_to_login(n.get("else")))
               for n in walk(body))


def _hand_rolled(t: TypeIR) -> MethodIR | None:
    """An OnAuthorization / OnActionExecuting override that looks like an auth check."""
    return next((m for m in _methods(t, {"onauthorization", "onactionexecuting"})
                 if _body_checks_auth(m.body)), None)


_PAGE_LIFECYCLE = {"page_load", "page_init", "oninit", "onload", "onpreinit"}


def _own_calls(body: list) -> set[str]:
    """Lowered names of methods called on the page itself: `Foo()`, `Me.Foo()`, `MyBase.Foo()`."""
    out = set()
    for n in walk(body):
        if n.get("k") != "call":
            continue
        fn = n.get("fn") or {}
        if fn.get("k") == "name" or (fn.get("k") == "member" and receiver_text(fn.get("obj")) in ("this", "base")):
            out.add((call_name(n) or "").lower())
    return out


def _page_check_candidates(types: list[TypeIR]) -> list[tuple[TypeIR, MethodIR]]:
    """Lifecycle methods of the page and its base pages, then the page's own
    methods they call (one level: `Page_Load` -> `ValidateSession()`)."""
    lifecycle = [(ct, m) for ct in types for m in _methods(ct, _PAGE_LIFECYCLE)]
    called = set().union(*(_own_calls(m.body) for _, m in lifecycle)) - _PAGE_LIFECYCLE if lifecycle else set()
    helpers = [(ct, m) for ct in types for m in _methods(ct, called)] if called else []
    return lifecycle + helpers


def resolve_webforms(model: ProjectModel, ref: RouteRef, configs: list) -> AuthInfo:
    """Auth for an .aspx/.asmx page: web.config <authorization> first, then a
    page-lifecycle method on the code-behind (or a project base page) that
    performs an auth check -- the same tightened semantics as MVC hand-rolled
    checks, plus RedirectToLoginPage or a branch that redirects to a login page,
    also inside a page method a lifecycle method calls. The latter is inferred,
    so review=True."""
    route, proj = ref.route, ref.project
    if proj is not None:
        page_dir = (proj.dir / route.path.lstrip("/")).parent
        denied, el = anonymous_denied(config_chain(configs, proj.dir, page_dir), route.path)
        if denied:
            return AuthInfo(True, "web.config", file=el.get(ORIGIN) if el is not None else None,
                            line=int(el.get(LINE) or 0) if el is not None else None)
    if ref.type is not None:
        for ct, m in _page_check_candidates([ref.type] + _base_types(model, ref.type)):
            where = f"{ct.name.split('.')[-1]}.{m.name}"
            if _body_checks_auth(m.body, frozenset({"redirecttologinpage"})):
                return AuthInfo(True, "code-behind check", review=True, file=ct.file, line=m.line, detail=where)
            if _conditional_login_redirect(m.body):
                return AuthInfo(True, "code-behind check", review=True, file=ct.file, line=m.line,
                                detail=f"a conditional login redirect in {where}")
    return AuthInfo(False, "none")


def resolve(model: ProjectModel, ref: RouteRef, filters: list[GlobalFilter],
            config_chain_for: Callable[[RouteRef], list[ET.Element]]) -> AuthInfo:
    t, m, route = ref.type, ref.method, ref.route
    m_attrs = m.attributes if m is not None else []

    bases = _base_types(model, t)

    # 1. [AllowAnonymous] wins over every authorize filter. MVC 5 / Web API 2
    #    skip authorization when it is on the action or the controller, and
    #    the attribute is Inherited=true, so a base controller counts too.
    for attrs, file, line in ([(m_attrs, t.file, route.line), (t.attributes, t.file, t.line)]
                              + [(bt.attributes, bt.file, bt.line) for bt in bases]):
        a = has_attr(attrs, "AllowAnonymous")
        if a is not None:
            return AuthInfo(False, "AllowAnonymous", anonymous=True, file=file, line=a.line or line)

    # 2. Auth attribute on the action, the controller, then base controllers.
    for attrs in (m_attrs, t.attributes):
        a = next((x for x in attrs if is_auth_attr(model, x.name)), None)
        if a is not None:
            return _from_attr(model, a, f"attribute:{attr_simple(a.name)}", t.file)
    for bt in bases:
        a = next((x for x in bt.attributes if is_auth_attr(model, x.name)), None)
        if a is not None:
            return _from_attr(model, a, f"base:{bt.name.split('.')[-1]}", bt.file)

    # 3. Global filter of the route's kind, in the same project when known.
    kind = route.meta.get("kind", "mvc")
    for fkind, fname, ffile, fline in filters:
        if fkind != kind or not is_auth_attr(model, fname):
            continue
        # A global filter only covers its own app: require both projects known and equal.
        if ref.project is None or model.project_of(ffile) is not ref.project:
            continue
        custom = auth_attribute_types(model).get(strip_attr(fname))
        protected = not (custom is not None and never_denies(custom, model))
        return AuthInfo(protected, f"global filter ({kind})", file=ffile, line=fline)

    # 4. web.config <authorization> rules for the route path.
    denied, el = anonymous_denied(config_chain_for(ref), route.path)
    if denied:
        return AuthInfo(True, "web.config", file=el.get(ORIGIN) if el is not None else None,
                        line=int(el.get(LINE) or 0) if el is not None else None)

    # 5. A controller / base controller that rolls its own check.
    for ct in [t] + bases:
        hm = _hand_rolled(ct)
        if hm is not None:
            return AuthInfo(True, "base OnAuthorization override", review=True, file=ct.file, line=hm.line,
                            detail=f"a hand-rolled check in {ct.name.split('.')[-1]}.{hm.name}")

    return AuthInfo(False, "none")


# -- WCF ----------------------------------------------------------------------

_SECURITY_CTX = {"servicesecuritycontext", "primaryidentity", "windowsidentity"}
# Bindings whose transport/message credential defaults to None when the config names none.
_ANON_BINDINGS = {"basichttpbinding", "basichttpsbinding", "webhttpbinding", "basichttpcontextbinding"}


def _principal_permission(attrs: list[Attr], file: str) -> AuthInfo | None:
    """[PrincipalPermission(SecurityAction.Demand, Role/Name = ..., Authenticated = true)]:
    only a Demand with a Role, a Name or Authenticated=true actually gates the caller."""
    for a in attrs:
        if attr_key(a.name) != "principalpermission":
            continue
        demand = any(n.get("k") == "member" and (n.get("name") or "").lower() == "demand"
                     for arg in a.args[:1] for n in walk(arg))
        named = {k.lower(): v for k, v in (a.named or {}).items()}
        roles, users = _split_named(a, "role"), _split_named(a, "name")
        authed = _is_true(named.get("authenticated"))
        if demand and (roles or users or authed):
            return AuthInfo(True, "attribute:PrincipalPermission", roles, users, file=file, line=a.line)
    return None


def _wcf_body_check(body: list) -> bool:
    """An in-body gate: PrincipalPermission(...).Demand(), an IsInRole / IsAuthenticated test
    whose branch rejects, or a rejecting test on ServiceSecurityContext.Current."""
    nodes = list(walk(body))

    def is_pp(e) -> bool:
        return isinstance(e, dict) and e.get("k") == "new" and "principalpermission" in (e.get("type") or "").lower()

    # Variables holding a PrincipalPermission: `Demand` only gates the caller on one of those (or on a
    # chained `new PrincipalPermission(...)`), never on an unrelated permission object.
    pp_vars = {(n.get("name") or "").lower() for n in nodes if n.get("k") == "local" and is_pp(n.get("init"))}
    pp_vars |= {(n["target"].get("id") or n["target"].get("name") or "").lower() for n in nodes
                if n.get("k") == "assign" and isinstance(n.get("target"), dict) and is_pp(n.get("value"))}
    pp_vars.discard("")
    for n in nodes:
        if n.get("k") == "call" and (call_name(n) or "").lower() == "demand":
            obj = (n.get("fn") or {}).get("obj")
            if is_pp(obj) or (isinstance(obj, dict) and obj.get("k") == "name"
                              and (obj.get("id") or "").lower() in pp_vars):
                return True
        if n.get("k") == "if" and _cond_tokens(n.get("cond")) & _SECURITY_CTX \
                and any(_rejects(b) for b in (n.get("then"), n.get("else"))):
            return True
    return _body_checks_auth(body)


def _sm(root: ET.Element, path: str) -> list[ET.Element]:
    return root.findall(f"system.serviceModel/{path}")


# Binding -> (default security mode, credential default for Transport, for Message). Anything not
# listed (customBinding, third-party, blank) is treated as carrying no credentials.
_BINDING_DEFAULTS = {
    "basichttpbinding": ("none", "none", "windows"), "webhttpbinding": ("none", "none", "windows"),
    "basichttpsbinding": ("transport", "none", "windows"), "basichttpcontextbinding": ("none", "none", "windows"),
    "wshttpbinding": ("message", "none", "windows"), "ws2007httpbinding": ("message", "none", "windows"),
    "wsdualhttpbinding": ("message", "none", "windows"), "wsfederationhttpbinding": ("message", "none", "windows"),
    "ws2007federationhttpbinding": ("message", "none", "windows"),
    "nettcpbinding": ("transport", "windows", "windows"), "netnamedpipebinding": ("transport", "windows", "windows"),
    "netmsmqbinding": ("transport", "windows", "windows"),
}


def _binding_element(chain: list[ET.Element], binding: str, cfg_name: str | None) -> ET.Element | None:
    for root in reversed(chain):
        for tag in _sm(root, "bindings/*"):
            if tag.tag.lower() != binding.lower():
                continue
            for b in tag.findall("binding"):
                if (b.get("name") or None) == cfg_name:
                    return b
    return None


def _binding_security(chain: list[ET.Element], ep: ET.Element
                      ) -> tuple[str | None, str, ET.Element | None, ET.Element | None]:
    """(security mode lowered, clientCredentialType lowered, binding element, security element)
    of an endpoint. The mode is None when it cannot be determined (standard `kind=` endpoints,
    blank / unknown / custom bindings); the credential is `none` whenever it cannot be shown
    to demand one. The credential element read is the one matching the security mode."""
    binding = (ep.get("binding") or "").lower()
    if ep.get("kind") or not binding:
        return None, "none", None, None
    cfg = _binding_element(chain, binding, ep.get("bindingConfiguration") or None)
    sec = cfg.find("security") if cfg is not None else None
    if binding == "custombinding":
        mode = ((sec.get("authenticationMode") or "") if sec is not None else "").lower()
        return None, ("none" if mode in ("", "none") or mode.startswith("anonymous") else mode), cfg, sec
    if binding not in _BINDING_DEFAULTS:
        return None, "none", cfg, sec
    dmode, dtransport, dmessage = _BINDING_DEFAULTS[binding]
    mode = ((sec.get("mode") if sec is not None else None) or dmode).lower()
    if mode == "none":
        return mode, "none", cfg, sec
    # Message-level credential for Message / Both / TransportWithMessageCredential, else the transport one.
    use_message = mode in ("message", "both", "transportwithmessagecredential")
    el = sec.find("message" if use_message else "transport") if sec is not None else None
    cred = (el.get("clientCredentialType") if el is not None else None) or (dmessage if use_message else dtransport)
    return mode, cred.lower(), cfg, sec


def _binding_credential(chain: list[ET.Element], ep: ET.Element) -> str:
    """Effective clientCredentialType (lowered) of an endpoint, `none` whenever it cannot be shown
    to demand one (see `_binding_security`)."""
    return _binding_security(chain, ep)[1]


def _wcf_behavior_auth(ref: RouteRef, chain: list[ET.Element]) -> AuthInfo | None:
    """serviceAuthorization (manager type or role mode) on the service's behavior, with every
    non-mex endpoint on a binding that demands credentials."""
    full = ref.type.full_name.lower()
    for root in reversed(chain):
        for svc in _sm(root, "services/service"):
            if (svc.get("name") or "").lower() != full:
                continue
            beh = svc.get("behaviorConfiguration") or None
            el = None
            for r2 in reversed(chain):
                for b in _sm(r2, "behaviors/serviceBehaviors/behavior"):
                    if (b.get("name") or None) == beh and b.find("serviceAuthorization") is not None:
                        el = b.find("serviceAuthorization")
                        break
                if el is not None:
                    break
            if el is None:
                return None
            mode = (el.get("principalPermissionMode") or "").lower()
            if not (el.get("serviceAuthorizationManagerType") or mode in ("useaspnetroles", "usewindowsgroups")):
                return None
            eps = [e for e in svc.findall("endpoint")
                   if (e.get("contract") or "").lower() != "imetadataexchange"
                   and (e.get("kind") or "").lower() != "mexendpoint"
                   and not (e.get("binding") or "").lower().startswith("mex")]
            if not eps or any(_binding_credential(chain, e) == "none" for e in eps):
                return None
            what = ("serviceAuthorization manager" if el.get("serviceAuthorizationManagerType")
                    else f"serviceAuthorization {el.get('principalPermissionMode')}")
            return AuthInfo(True, "wcf binding/behavior", review=True, file=el.get(ORIGIN),
                            line=int(el.get(LINE) or 0), detail=f"{what} on behavior '{beh or ''}' (callers must authenticate via the binding; "
                                   "no per-operation authorization found)")
    return None


def resolve_wcf(model: ProjectModel, ref: RouteRef, configs: list) -> AuthInfo:
    """Auth for a WCF operation: [PrincipalPermission] on the method or service class, an
    in-body gate (inferred, review=True), a serviceAuthorization behavior plus credentialed
    bindings (inferred, review=True), then web.config <authorization> when ASP.NET
    compatibility is on; otherwise unprotected."""
    t, m, route, proj = ref.type, ref.method, ref.route, ref.project
    for attrs, file in ((m.attributes if m else [], route.file), (t.attributes, t.file)):
        info = _principal_permission(attrs, file)
        if info is not None:
            return info
    if m is not None and _wcf_body_check(m.body):
        where = f"{t.name.split('.')[-1]}.{m.name}"
        return AuthInfo(True, "operation body check", review=True, file=route.file, line=m.line,
                        detail=f"a hand-rolled check in {where}")
    if proj is None:
        return AuthInfo(False, "none")
    # Chain, behavior auth and the per-hosting-dir chain depend only on the project / service / hosting
    # dir, so they are computed once per model however many operations the service has.
    # The entry keeps the `configs` list it was built from (identity check), so a reload starts clean.
    held = model.cache.get("wcf_auth")
    if held is None or held[0] is not configs:
        held = model.cache["wcf_auth"] = (configs, {})
    cache = held[1]
    chain = cache.get(("chain", proj.dir))
    if chain is None:
        chain = cache[("chain", proj.dir)] = config_chain(configs, proj.dir, proj.dir)
    bkey = ("behavior", t.full_name.lower(), proj.dir)
    if bkey not in cache:
        cache[bkey] = _wcf_behavior_auth(ref, chain)
    info = cache[bkey]
    if info is not None:
        return info
    compat = any((e.get("aspNetCompatibilityEnabled") or "").lower() == "true"
                 for root in chain for e in _sm(root, "serviceHostingEnvironment"))
    if compat:
        svc_path = "/" + route.meta["svc"]
        hdir = (proj.dir / route.meta["svc"]).parent
        hkey = ("hosting", hdir)
        if hkey not in cache:
            cache[hkey] = config_chain(configs, proj.dir, hdir)
        denied, el = anonymous_denied(cache[hkey], svc_path)
        if denied:
            return AuthInfo(True, "web.config", file=el.get(ORIGIN) if el is not None else None,
                            line=int(el.get(LINE) or 0) if el is not None else None)
    return AuthInfo(False, "none")
