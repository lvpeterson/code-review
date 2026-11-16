"""Three-state authorization for ASP.NET Core routes: PROTECTED, ANONYMOUS, UNPROTECTED or UNKNOWN.

Reporting a route as protected when it is not is the worst outcome of this module, so every
path that cannot prove a denying mechanism ends in UNKNOWN (a review item), never PROTECTED.

Order (most specific first, anonymous beats everything as ASP.NET Core does):
 1. ANONYMOUS: [AllowAnonymous] on the action / class / base, `.AllowAnonymous()` on the endpoint, a
    group or the Map call, an AllowAnonymousTo* Razor Pages convention.
 2. PROTECTED from [Authorize] (or a project attribute deriving from it, or an authorization filter
    attribute that can set context.Result), RequireAuthorization(...) on the endpoint / a group / the
    Map call. Razor Pages read the PageModel class and bases only; a handler-method attribute is noted
    and ignored.
 3. PROTECTED from a global AuthorizeFilter (controllers, pages) or an Authorize* Razor Pages convention.
 4. PROTECTED from a fallback policy, only for endpoints with no authorization metadata at all.

A policy is protective when it holds a requirement that can deny, "never denies" when every
requirement always succeeds (RequireAssertion(_ => true), or requirements whose handlers always call
Succeed and never Fail), and unknown otherwise (not defined, defined conditionally, built from an
expression this module cannot read, a custom IAuthorizationPolicyProvider is registered).

Registrations come from the pipeline: only calls that certainly run in Production count; a call under
an environment condition the pipeline could not parse (Pipeline.uncertain) is never a protective
source, it becomes a reason for UNKNOWN. Lambdas passed as arguments are read from PipeCall.node,
and `if` statements inside them get the same environment treatment (an unparseable or non-environment
condition makes what it guards uncertain).

Reasons for UNKNOWN (ref.unknown, untraced conventions, endpoint filters, unresolved extension calls,
Conventions.Add, ...) only apply to a route that would otherwise be UNPROTECTED: they never downgrade a
route a definite mechanism protects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl.ir import (Attr, MethodIR, TypeIR, attr_key, attr_simple, call_chain, call_name, const_str,
                           literal_str, receiver_text, walk)
from checks.dnl.pipeline import _Ctx, _eval, _exits, _pred, Pipeline
from checks.dnl.project import ProjectModel
from checks.dnl.routes_core import CoreRouteRef, _chain_types

PROTECTED, ANONYMOUS, UNPROTECTED, UNKNOWN = "protected", "anonymous", "unprotected", "unknown"

# Registrations that cannot grant or remove authorization (scheme handlers, data, docs, logging).
# Extend only with names that stay inside that definition.
_NON_AUTHZ_EXTENSIONS = frozenset("""
AddJwtBearer AddOpenIdConnect AddMicrosoftIdentityWebApi AddMicrosoftIdentityWebApp AddGoogle AddFacebook
AddMicrosoftAccount AddNegotiate AddCertificate AddDbContext AddDbContextPool AddDbContextFactory
AddEntityFrameworkStores AddDefaultIdentity AddIdentity AddIdentityCore AddDefaultTokenProviders AddDefaultUI
AddSwaggerGen UseSwagger UseSwaggerUI AddAutoMapper AddMediatR AddValidatorsFromAssembly
AddFluentValidationAutoValidation AddSerilog UseSerilog UseSerilogRequestLogging AddApplicationInsightsTelemetry
AddStackExchangeRedisCache AddHangfire AddHangfireServer AddMassTransit AddOpenTelemetry AddNewtonsoftJson
""".split())
# Calls this module reads itself, so an unresolved occurrence (degraded mode) is not a blind spot.
_ANALYSED = frozenset({"AddMvcOptions", "AddRazorPagesOptions", "AddAuthorizationCore"})
# Convention links (on an endpoint, a group or a Map call) that cannot change authorization.
_BENIGN_CONVENTIONS = frozenset("""
WithTags WithName WithOpenApi WithDisplayName WithGroupName WithSummary WithDescription Produces ProducesProblem
ProducesValidationProblem Accepts RequireCors RequireRateLimiting RequireHost DisableAntiforgery
ExcludeFromDescription DisableRateLimiting CacheOutput WithRequestTimeout ShortCircuit WithOrder
DisableRequestTimeout RequireAntiforgery
""".split())
_ENDPOINT_FILTERS = frozenset({"AddEndpointFilter", "AddEndpointFilterFactory"})
# Razor Pages conventions that only change routing.
_ROUTE_CONVENTIONS = frozenset("""
AddPageRoute AddAreaPageRoute AddPageRouteModelConvention AddFolderRouteModelConvention
AddAreaPageRouteModelConvention AddAreaFolderRouteModelConvention
""".split())
_AUTHZ_NAMED = re.compile(r"authoriz|permission|role|scope|claim|polic", re.IGNORECASE)
_OPTION_CALLS = frozenset("""
AddAuthorization AddAuthorizationCore AddControllers AddControllersWithViews AddMvc AddMvcCore AddRazorPages
AddRazorPagesOptions AddMvcOptions Configure PostConfigure ConfigureOptions
""".split())
_POLICY_DEFS = frozenset({"AddPolicy", "AddDefaultPolicy", "AddFallbackPolicy"})
_KNOWN_DENY_REQS = frozenset("""
DenyAnonymousAuthorizationRequirement RolesAuthorizationRequirement ClaimsAuthorizationRequirement
NameAuthorizationRequirement AssertionRequirement
""".split())
_CTX = _Ctx()
_UNK = ("unknown",)
_SUPPRESS = "SuppressCheckForUnhandledSecurityMetadata"


@dataclass
class CoreAuth:
    state: str
    source: str
    roles: list[str] = field(default_factory=list)
    policies: list[str] = field(default_factory=list)
    file: str | None = None
    line: int | None = None
    reasons: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class PolicyInfo:
    name: str
    file: str
    line: int
    roles: list[str]
    never_denies: bool
    # Why the policy could not be read (non-empty: neither protective nor never-denying).
    unknown: list[str] = field(default_factory=list)


# -- small helpers ---------------------------------------------------------------

def _simple(t: str | None) -> str:
    return (t or "").split("<")[0].strip().rstrip("?").split(".")[-1]


def _dedup(xs) -> list:
    return list(dict.fromkeys(xs))


def _runs(guards: tuple) -> bool | None:
    """PipeCall.runs_in("Production") for a bare guard tuple."""
    res: bool | None = True
    for pred, taken in guards:
        v = _eval(pred, "production")
        if v is not None and not taken:
            v = not v
        if v is False:
            return False
        if v is None:
            res = None
    return res


def _both(a: bool | None, b: bool | None) -> bool | None:
    if a is False or b is False:
        return False
    return True if a is True and b is True else None


def _is_null(e) -> bool:
    return isinstance(e, dict) and e.get("k") == "lit" and e.get("v") is None


def _is_true(e) -> bool:
    return isinstance(e, dict) and e.get("k") == "lit" and e.get("v") is True


def _typeof(e) -> str | None:
    """Simple name inside `typeof(X)` (the helper lowers it to an `unknown` node with its text)."""
    if isinstance(e, dict):
        text = e.get("text") or ""
        m = re.fullmatch(r"\s*typeof\s*\(\s*([\w.<>,\s?]+?)\s*\)\s*", text)
        if m:
            return _simple(m.group(1))
    return None


def _const(model: ProjectModel, e) -> str | None:
    """A compile-time string: a literal, nameof, a concatenation, or `Type.Const` of a solution const."""
    s = const_str(e)
    if s is not None or not isinstance(e, dict) or e.get("k") != "member":
        return s
    owner = _simple(receiver_text(e.get("obj")))
    for t in model.find_types(owner) if owner else []:
        for f in t.fields:
            if f.name == e.get("name") and f.is_const:
                return const_str(f.init)
    return None


def _strs(e) -> list[str]:
    return [v for n in walk(e) if (v := literal_str(n))]


def _arg(call: dict, idx: int, *named: str):
    for k, v in (call.get("named") or {}).items():
        if k.lower() in named:
            return v
    args = call.get("args") or []
    return args[idx] if idx < len(args) else None


# -- lambda bodies: calls and assignments with their environment guards ----------------

def _expr_events(e, guards: tuple):
    if not isinstance(e, dict):
        return
    k = e.get("k")
    if k == "assign":
        yield ("assign", e, guards, None)
        yield from _expr_events(e.get("value"), guards)
    elif k == "call":
        root, calls = call_chain(e)
        for c in calls:
            yield ("call", c, guards, root)
    elif k == "cond":
        # A ternary: either branch may run.
        g = guards + ((_UNK, True),)
        for n in walk(e):
            if n is not e and n.get("k") in ("call", "assign"):
                yield from _expr_events(n, g)
                break


def _stmt_events(stmts, guards: tuple):
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        k = s.get("k")
        if k == "expr":
            yield from _expr_events(s.get("expr"), guards)
        elif k == "assign":
            yield from _expr_events(s, guards)
        elif k == "local":
            yield from _expr_events(s.get("init"), guards)
        elif k in ("return", "throw"):
            yield from _expr_events(s.get("value"), guards)
            return
        elif k == "if":
            pred = _pred(s.get("cond"), {}, _CTX) or _UNK
            t_g, e_g = guards + ((pred, True),), guards + ((pred, False),)
            yield from _stmt_events(s.get("then"), t_g)
            yield from _stmt_events(s.get("else"), e_g)
            t_exit, e_exit = _exits(s.get("then")), _exits(s.get("else"))
            if t_exit and e_exit:
                return
            if t_exit:
                guards = e_g
            elif e_exit:
                guards = t_g
        elif k == "loop":
            yield from _stmt_events(s.get("body"), guards + ((_UNK, True),))
        elif k == "using":
            yield from _stmt_events(s.get("resource"), guards)
            yield from _stmt_events(s.get("body"), guards)
        elif k == "try":
            yield from _stmt_events(s.get("body"), guards)
            for c in s.get("catches") or []:
                yield from _stmt_events(c.get("body"), guards + ((_UNK, True),))
            yield from _stmt_events(s.get("finally"), guards)


def _lambda_events(lam: dict, guards: tuple = ()):
    body = lam.get("body")
    if isinstance(body, list):
        yield from _stmt_events(body, guards)
    else:
        yield from _expr_events(body, guards)


# -- handlers and requirements ----------------------------------------------------------

_HANDLE_METHODS = ("handlerequirementasync", "handleasync")


def _bases(model: ProjectModel, t: TypeIR) -> set[str]:
    return {_simple(b).lower() for b in model.base_chain(t)}


def _handler_methods(chain: list[TypeIR]) -> list[MethodIR]:
    return [m for ct in chain for m in ct.methods if m.name.lower() in _HANDLE_METHODS]


def _succeeds_always(body: list) -> bool:
    """A Succeed call reached on every path: a top-level statement (or a top-level loop over the
    pending requirements) with no `return` / `throw` before it."""
    for s in body or []:
        if not isinstance(s, dict):
            continue
        k = s.get("k")
        if k == "expr" and any(n.get("k") == "call" and call_name(n) == "Succeed" for n in walk(s.get("expr"))):
            return True
        if k == "loop" and any(c.get("k") == "expr" and any(call_name(n) == "Succeed" for n in walk(c))
                               for c in s.get("body") or [] if isinstance(c, dict)):
            return True
        if any(n.get("k") in ("return", "throw") for n in walk(s)):
            return False
    return False


def _calls_fail(bodies: list[list]) -> bool:
    return any(n.get("k") == "call" and call_name(n) == "Fail" for b in bodies for n in walk(b))


def _handler_facts(model: ProjectModel) -> dict:
    """Per handler type: the requirement it is bound to (None: any), whether it always succeeds and
    whether any of its code can Fail. Cached on the model."""
    cached = model.cache.get("auth_core_handlers")
    if cached is not None:
        return cached
    out: dict = {}
    for t in model.types():
        if t.kind != "class" or not ({"authorizationhandler", "iauthorizationhandler"} & _bases(model, t)
                                     or any(_simple(b).lower() == "iauthorizationhandler" for b in t.bases)):
            continue
        chain = _chain_types(model, t)
        methods = _handler_methods(chain)
        if not methods:
            continue
        bound = None
        for m in methods:
            if m.name.lower() == "handlerequirementasync" and len(m.params) >= 2:
                bound = _simple(m.params[1].type)
        bodies = [m.body for m in methods]
        out[id(t)] = {"type": t, "req": bound, "always": any(_succeeds_always(b) for b in bodies),
                      "fails": _calls_fail(bodies)}
    model.cache["auth_core_handlers"] = out
    return out


def never_denying_handlers(model: ProjectModel) -> list[TypeIR]:
    """Authorization handlers whose code succeeds on every path and never calls Fail."""
    return [h["type"] for h in _handler_facts(model).values() if h["always"] and not h["fails"]]


def _requirement_verdict(model: ProjectModel, name: str) -> tuple[str, str]:
    """("deny" | "never" | "unknown", detail) for `new <name>(...)` used as a policy requirement."""
    if name in _KNOWN_DENY_REQS:
        return "deny", name
    types = [t for t in model.find_types(name) if t.kind == "class"]
    if not types:
        return "unknown", f"requirement {name} is not defined in the solution"
    facts = list(_handler_facts(model).values())
    bound = [h for h in facts if h["req"] in (None, name) or h["type"] in types]
    if not bound:
        return "unknown", f"requirement {name} has no authorization handler in the solution"
    good = [h for h in bound if h["always"]]
    if good and not any(h["fails"] for h in bound):
        return "never", f"handler {good[0]['type'].name.split('.')[-1]} always succeeds for {name}"
    return "deny", name


# -- policies ---------------------------------------------------------------------------

@dataclass
class _Pol:
    deny: int = 0
    never: list[str] = field(default_factory=list)      # why each always-succeeding requirement never denies
    reqs: int = 0
    roles: list[str] = field(default_factory=list)
    unknown: list[str] = field(default_factory=list)

    @property
    def can_deny(self) -> bool:
        return self.deny > 0

    @property
    def never_denies(self) -> bool:
        return not self.deny and self.reqs > 0 and len(self.never) == self.reqs and not self.unknown

    def why(self) -> str:
        return "; ".join(self.never)


def _always_true_lambda(e) -> bool:
    if not (isinstance(e, dict) and e.get("k") == "lambda"):
        return False
    body = e.get("body")
    if isinstance(body, list):
        rets = [n for n in walk(body) if n.get("k") == "return"]
        return bool(rets) and all(_is_true(r.get("value")) or _from_result_true(r.get("value")) for r in rets)
    return _is_true(body) or _from_result_true(body)


def _from_result_true(e) -> bool:
    return (isinstance(e, dict) and e.get("k") == "call" and call_name(e) == "FromResult"
            and len(e.get("args") or []) == 1 and _is_true(e["args"][0]))


def _apply_link(model: ProjectModel, pol: _Pol, link: dict, runs: bool | None) -> None:
    name = call_name(link) or ""
    if name in ("Build", "AddAuthenticationSchemes"):
        return
    known = name in ("RequireAuthenticatedUser", "RequireRole", "RequireClaim", "RequireUserName",
                     "RequireAssertion", "AddRequirements")
    if known and runs is not True:
        pol.unknown.append(f"{name} is applied under a condition")
        return
    if name in ("RequireAuthenticatedUser", "RequireClaim", "RequireUserName"):
        pol.deny += 1
    elif name == "RequireRole":
        pol.deny += 1
        pol.roles += _strs(link.get("args"))
    elif name == "RequireAssertion":
        pol.reqs += 1
        arg = _arg(link, 0, "handler")
        if _always_true_lambda(arg):
            pol.never.append("RequireAssertion always returns true")
        else:
            pol.deny += 1
    elif name == "AddRequirements":
        for a in link.get("args") or []:
            if isinstance(a, dict) and a.get("k") == "new":
                pol.reqs += 1
                verdict, detail = _requirement_verdict(model, _simple(a.get("type")))
                if verdict == "deny":
                    pol.deny += 1
                elif verdict == "never":
                    pol.never.append(detail)
                else:
                    pol.unknown.append(detail)
            else:
                pol.unknown.append("AddRequirements argument is not a `new` expression")
    else:
        pol.unknown.append(f"{name} is not analysed")


def _policy_expr(model: ProjectModel, e) -> _Pol:
    """What a policy argument stands for: a builder lambda (`p => p.RequireRole(..)`) or a
    `new AuthorizationPolicyBuilder()...Build()` chain. Anything else is unknown."""
    pol = _Pol()
    if isinstance(e, dict) and e.get("k") == "lambda":
        params = e.get("params") or []
        p = params[0] if params and isinstance(params[0], str) else None
        for kind, node, guards, root in _lambda_events(e):
            if kind != "call" or not (isinstance(root, dict) and root.get("k") == "name" and root.get("id") == p):
                if kind == "call" and any(isinstance(a, dict) and a.get("k") == "name" and a.get("id") == p
                                          for a in node.get("args") or []):
                    pol.unknown.append(f"the policy builder is passed to {call_name(node)}")
                continue
            runs = _runs(guards)
            if runs is False:
                continue
            _apply_link(model, pol, node, runs)
    elif isinstance(e, dict) and e.get("k") == "call":
        root, calls = call_chain(e)
        if isinstance(root, dict) and root.get("k") == "new" and _simple(root.get("type")) == "AuthorizationPolicyBuilder":
            for c in calls:
                _apply_link(model, pol, c, True)
        else:
            pol.unknown.append("the policy expression is not analysed")
    else:
        pol.unknown.append("the policy expression is not analysed")
    if not (pol.deny or pol.reqs):
        pol.unknown.append("the policy has no requirement this module recognises")
    return pol


# -- registrations (settings) -----------------------------------------------------------

@dataclass
class _Fact:
    data: dict
    certain: bool
    file: str
    line: int


@dataclass
class _Settings:
    policies: dict[str, PolicyInfo] = field(default_factory=dict)
    pols: dict[str, _Pol] = field(default_factory=dict)
    policy_unknown: dict[str, str] = field(default_factory=dict)
    fallback: list[_Fact] = field(default_factory=list)
    default: list[_Fact] = field(default_factory=list)
    filters: list[_Fact] = field(default_factory=list)
    page_convs: list[_Fact] = field(default_factory=list)
    provider: _Fact | None = None
    # (reason, styles it applies to; None = every route)
    reasons: list[tuple[str, tuple | None]] = field(default_factory=list)
    issue: tuple | None = None
    suppress_certain: bool = False
    suppress_uncertain: bool = False

    def reasons_for(self, style: str) -> list[str]:
        return _dedup(r for r, st in self.reasons if st is None or style in st)


_MVC_STYLES = ("controller", "razorpage")


def _target_name(target) -> str:
    if isinstance(target, dict):
        return (target.get("name") if target.get("k") == "member" else target.get("id")) or ""
    return ""


def _option_events(pipe: Pipeline, member: str):
    """(value expr, runs, file, line) for every `<x>.member = value` inside a lambda argument of a
    service registration. runs is True / None (conditional or unparseable); False ones are dropped."""
    for c in pipe.calls:
        base = c.runs_in("Production")
        if base is False or c.kind != "services":
            continue
        for lam in _lambda_args(c.node):
            for kind, node, guards, _root in _lambda_events(lam):
                if kind == "assign" and _target_name(node.get("target")) == member:
                    runs = _both(base, _runs(guards))
                    if runs is not False:
                        yield node.get("value"), runs, c.file, node.get("line") or c.line


def _lambda_args(call: dict):
    for a in list(call.get("args") or []) + list((call.get("named") or {}).values()):
        if isinstance(a, dict) and a.get("k") == "lambda":
            yield a


def _suppress_state(pipe: Pipeline) -> tuple[bool, bool]:
    certain = uncertain = False
    for value, runs, _f, _l in _option_events(pipe, _SUPPRESS):
        if _is_true(value) and runs is True:
            certain = True
        elif _is_null(value) or (isinstance(value, dict) and value.get("k") == "lit" and value.get("v") is False):
            continue
        else:
            uncertain = True
    return certain, uncertain


def _tfm_major(tfm: str | None) -> int | None:
    m = re.fullmatch(r"net(\d+)(?:\.\d+)?", (tfm or "").strip().lower())
    return int(m.group(1)) if m else (0 if tfm else None)


def middleware_issue(pipe: Pipeline) -> tuple[str, str, int, bool] | None:
    """(message, file, line, suppressed) when UseAuthorization is missing or misordered in an app with
    explicit routing (Startup style, or minimal hosting below net7.0); None otherwise. Minimal hosting
    on net7.0+ adds the middleware itself."""
    if pipe.style == "startup":
        pass
    elif pipe.style == "minimal":
        major = _tfm_major(pipe.target_framework)
        if major is None or major >= 7:
            return None
    else:
        return None
    if not any(c.kind == "endpoints" or c.name == "UseEndpoints" for c in pipe.calls if c.runs_in("Production") is not False):
        return None
    if any(c.name == "UseAuthorization" for c in pipe.uncertain()):
        return None
    suppressed = _suppress_state(pipe)[0]
    auth = pipe.named("UseAuthorization", kinds=("app",))
    anchor = next(iter(pipe.named("UseEndpoints", "UseRouting")), None) or next(iter(pipe.calls), None)
    if not auth:
        if anchor is None:
            return None
        return ("UseAuthorization is not called; endpoint authorization metadata is not enforced",
                anchor.file, anchor.line, suppressed)
    first = auth[0]
    routing = pipe.named("UseRouting", kinds=("app",))
    if routing and first.order < routing[0].order:
        return ("UseAuthorization is called before UseRouting, so it cannot see endpoint authorization metadata",
                first.file, first.line, suppressed)
    authn = pipe.named("UseAuthentication", kinds=("app",))
    if authn and first.order < authn[0].order:
        return ("UseAuthorization is called before UseAuthentication, so the caller is not authenticated "
                "when policies run", first.file, first.line, suppressed)
    return None


def _settings(model: ProjectModel, pipe: Pipeline) -> _Settings:
    cache = model.cache.setdefault("auth_core_settings", {})
    if id(pipe) not in cache:
        cache[id(pipe)] = _build_settings(model, pipe)
    return cache[id(pipe)]


def _build_settings(model: ProjectModel, pipe: Pipeline) -> _Settings:
    S = _Settings()
    S.issue = middleware_issue(pipe)
    S.suppress_certain, S.suppress_uncertain = _suppress_state(pipe)
    defs: dict[str, list[tuple]] = {}

    def policy_fact(e, base, runs_inner, file, line, bucket):
        runs = _both(base, runs_inner)
        if runs is False:
            return
        bucket.append(_Fact({"pol": None if _is_null(e) else _policy_expr(model, e), "null": _is_null(e)},
                            runs is True, file, line))

    for c in pipe.calls:
        base = c.runs_in("Production")
        if base is False:
            continue
        # Unresolved registrations that could change authorization.
        if (not c.resolved and c.kind in ("services", "app") and c.name not in _NON_AUTHZ_EXTENSIONS
                and c.name not in _ANALYSED):
            S.reasons.append((f"{c.name} at {c.file}:{c.line} is not resolved and may change authorization", None))
        if c.kind != "services":
            continue
        node = c.node
        fn = node.get("fn") or {}
        targs = [_simple(t) for t in fn.get("targs") or []]
        idx = next((i for i, x in enumerate(c.chain) if x is node), 0)
        prior = {call_name(x) for x in c.chain[:idx]}
        auth_ctx = (c.name in ("AddAuthorization", "AddAuthorizationCore", "AddAuthorizationBuilder")
                    or (c.name in ("Configure", "PostConfigure", "ConfigureOptions") and "AuthorizationOptions" in targs))
        builder_ctx = "AddAuthorizationBuilder" in prior
        file, line = c.file, node.get("line") or c.line

        # A custom policy provider decides every named policy.
        if c.name.startswith(("Add", "TryAdd", "Replace")) and "IAuthorizationPolicyProvider" in (
                " ".join(targs) + " " + " ".join(str(v) for n in walk(node.get("args")) for v in n.values()
                                                 if isinstance(v, str))):
            if S.provider is None:
                S.provider = _Fact({}, base is True, file, line)

        # AuthorizationBuilder chain: AddPolicy("n", ...), SetFallbackPolicy(p), ...
        if builder_ctx and c.name in _POLICY_DEFS | {"SetDefaultPolicy", "SetFallbackPolicy"}:
            args = node.get("args") or []
            if c.name in _POLICY_DEFS:
                pname = _const(model, args[0]) if args else None
                pexpr = args[1] if len(args) > 1 else None
                defs.setdefault(pname or "", []).append((pexpr, base, file, line))
                bucket = S.default if c.name == "AddDefaultPolicy" else S.fallback if c.name == "AddFallbackPolicy" else None
                if bucket is not None:
                    policy_fact(pexpr, base, True, file, line, bucket)
            elif args:
                policy_fact(args[-1], base, True, file, line,
                            S.default if c.name == "SetDefaultPolicy" else S.fallback)

        opaque = None
        for lam in _lambda_args(node):
            params = lam.get("params") or []
            p = params[0] if params and isinstance(params[0], str) else None
            for kind, ev, guards, root in _lambda_events(lam):
                runs_inner = _runs(guards)
                if runs_inner is False:
                    continue
                if kind == "assign":
                    tn = _target_name(ev.get("target"))
                    if tn in ("FallbackPolicy", "DefaultPolicy"):
                        policy_fact(ev.get("value"), base, runs_inner, file, ev.get("line") or line,
                                    S.fallback if tn == "FallbackPolicy" else S.default)
                    continue
                name = call_name(ev) or ""
                recv = receiver_text((ev.get("fn") or {}).get("obj")) if (ev.get("fn") or {}).get("k") == "member" else ""
                eline = ev.get("line") or line
                runs = _both(base, runs_inner)
                if auth_ctx and name in _POLICY_DEFS and isinstance(root, dict) and root.get("id") == p:
                    args = ev.get("args") or []
                    pname = _const(model, args[0]) if args else None
                    pexpr = args[1] if len(args) > 1 else None
                    defs.setdefault(pname or "", []).append((pexpr, runs, file, eline))
                elif recv.endswith("Filters") and name in ("Add", "AddService", "AddFilter"):
                    S.filters.append(_Fact({"call": ev}, runs is True, file, eline))
                elif recv.endswith("Conventions"):
                    S.page_convs.append(_Fact({"call": ev, "name": name}, runs is True, file, eline))
                if (c.name in _OPTION_CALLS and p
                        and any(isinstance(a, dict) and a.get("k") == "name" and a.get("id") == p
                                for a in ev.get("args") or [])):
                    opaque = name
            # The options object handed to another method: what it does is not analysed.
        if c.name in _OPTION_CALLS and (opaque or any(isinstance(a, dict) and a.get("k") in ("name", "member")
                                                     for a in node.get("args") or [])):
            what = opaque or next(receiver_text(a) or "a method group" for a in node.get("args") or []
                                  if isinstance(a, dict) and a.get("k") in ("name", "member"))
            S.reasons.append((f"{c.name} options are configured by {what} at {file}:{line}, which is not analysed", None))

    # Policy definitions: the last certain one wins; an uncertain or unreadable one makes the name unknown.
    for pname, lst in defs.items():
        if not pname:
            S.reasons.append(("a policy is defined with a name that is not a literal", None))
            continue
        for pexpr, runs, file, line in lst:
            if runs is not True:
                S.policy_unknown[pname] = f"policy \"{pname}\" is defined under a condition that could not be evaluated"
        certain = [x for x in lst if x[1] is True]
        if not certain:
            continue
        pexpr, _r, file, line = certain[-1]
        pol = _policy_expr(model, pexpr)
        S.pols[pname] = pol
        S.policies[pname] = PolicyInfo(pname, file, line, _dedup(pol.roles), pol.never_denies, list(pol.unknown))

    # Conventions this module cannot read (reasons), for the routes they could affect.
    for f in S.page_convs:
        name = f.data["name"]
        if name in _ROUTE_CONVENTIONS or name.startswith(("Authorize", "AllowAnonymousTo")):
            continue
        S.reasons.append((f"Conventions.{name} at {f.file}:{f.line} may change authorization and is not analysed",
                          _MVC_STYLES))
    return S


# -- policy / default / fallback verdicts -----------------------------------------------

PROT, NEVER, UNK = "prot", "never", "unk"


def _pol_verdict(pol: _Pol) -> str:
    if pol.can_deny:
        return PROT
    return NEVER if pol.never_denies else UNK


def _named(S: _Settings, name: str) -> tuple[str, _Pol | None, list[str]]:
    if S.provider is not None:
        return UNK, None, [f"a custom IAuthorizationPolicyProvider is registered at {S.provider.file}:{S.provider.line}; "
                           f"policy \"{name}\" cannot be resolved"]
    if name in S.policy_unknown:
        return UNK, None, [S.policy_unknown[name]]
    pol = S.pols.get(name)
    if pol is None:
        return UNK, None, [f"policy \"{name}\" is not defined in the solution"]
    v = _pol_verdict(pol)
    if v == UNK:
        return UNK, pol, [f"policy \"{name}\" cannot be analysed: " + "; ".join(pol.unknown)]
    return v, pol, []


def _global_policy(facts: list[_Fact], what: str) -> tuple[str, _Pol | None, _Fact | None, list[str]]:
    """Verdict of the DefaultPolicy / FallbackPolicy assignments: "none" when never set (or set to null)."""
    if not facts:
        return "none", None, None, []
    reasons: list[str] = []
    if any(not f.certain for f in facts):
        reasons.append(f"{what} is set under a condition that could not be evaluated")
    last = facts[-1]
    certain = [f for f in facts if f.certain]
    if certain:
        last = certain[-1]
    if last.certain and last.data["null"] and not reasons:
        return "none", None, last, []
    if reasons or not last.certain:
        return UNK, None, last, reasons or [f"{what} is set under a condition that could not be evaluated"]
    pol = last.data["pol"]
    v = _pol_verdict(pol)
    if v == UNK:
        return UNK, pol, last, [f"{what} cannot be analysed: " + "; ".join(pol.unknown)]
    return v, pol, last, []


# -- attributes -------------------------------------------------------------------------

@dataclass
class _Item:
    source: str
    file: str | None
    line: int | None
    step: int                       # 2 attributes / endpoint calls, 3 filters and page conventions
    anon: bool = False
    # IAuthorizeData
    policy: str | None = None
    policy_expr: str | None = None
    roles: list[str] = field(default_factory=list)
    inline: _Pol | None = None
    plain: bool = False
    verdict: tuple[str, str] | None = None     # a custom filter: (verdict, detail)
    unknown: list[str] = field(default_factory=list)
    conditional: bool = False
    names: list[str] = field(default_factory=list)   # several policy names (RequireAuthorization("a", "b"))
    notes: list[str] = field(default_factory=list)


def _base_keys(model: ProjectModel, t: TypeIR) -> set[str]:
    """Every base / interface name of a type (transitive through the solution), as `attr_key` and plain lowered names."""
    return {attr_key(b) for b in model.base_chain(t)} | _bases(model, t)


def _implements(model: ProjectModel, t: TypeIR, *keys: str) -> bool:
    return bool(_base_keys(model, t) & set(keys))


def _find_class(model: ProjectModel, name: str) -> TypeIR | None:
    for cand in (name, name + "Attribute"):
        hits = [t for t in model.find_types(cand) if t.kind == "class"]
        if hits:
            return hits[0]
    return None


def _filter_verdict(model: ProjectModel, t: TypeIR) -> tuple[str, str]:
    """Can an authorization filter type set context.Result (deny), never does, or passes the decision on."""
    chain = _chain_types(model, t)
    methods = [m for ct in chain for m in ct.methods if m.name.lower() in ("onauthorization", "onauthorizationasync")]
    tn = t.name.split(".")[-1]
    if not methods:
        return UNK, f"filter {tn} has no OnAuthorization method in the solution"
    for m in methods:
        for n in walk(m.body):
            if n.get("k") == "throw":
                return PROT, tn
            if n.get("k") == "assign" and _target_name(n.get("target")) == "Result":
                return PROT, tn
    for m in methods:
        p = m.params[0].name if m.params else None
        for n in walk(m.body):
            if n.get("k") == "call" and any(isinstance(a, dict) and a.get("k") == "name" and a.get("id") == p
                                            for a in n.get("args") or []):
                return UNK, f"filter {tn} hands its context to {call_name(n)}, which is not analysed"
    return NEVER, f"filter {tn} never sets context.Result"


def _derived_data(model: ProjectModel, t: TypeIR, a: Attr, item: _Item) -> None:
    """Policy / Roles a project attribute deriving from AuthorizeAttribute sets in its constructor."""
    for ct in _chain_types(model, t):
        for m in ct.methods:
            if m.name != ".ctor":
                continue
            for n in walk(m.body):
                if n.get("k") != "assign":
                    continue
                tn = _target_name(n.get("target"))
                if tn not in ("Policy", "Roles"):
                    continue
                val = n.get("value")
                s = _const(model, val)
                if s is None and isinstance(val, dict) and val.get("k") == "name":
                    names = [p.name for p in m.params]
                    if val.get("id") in names and names.index(val["id"]) < len(a.args):
                        s = _const(model, a.args[names.index(val["id"])])
                if s is None:
                    item.unknown.append(f"{t.name} sets {tn} to a value that is not a constant")
                elif tn == "Policy":
                    item.policy = s
                else:
                    item.roles += [r.strip() for r in s.split(",") if r.strip()]


def _attr_items(model: ProjectModel, attrs: list[Attr], source_for, file: str | None, step: int = 2) -> list[_Item]:
    out: list[_Item] = []
    for a in attrs:
        key = attr_key(a.name)
        src = source_for(attr_simple(a.name))
        line = a.line
        if key == "allowanonymous":
            out.append(_Item(src, file, line, step, anon=True))
            continue
        t = None if key == "authorize" else _find_class(model, key)
        if key == "authorize" or (t is not None and "authorize" in _base_keys(model, t)):
            item = _Item(src, file, line, step)
            pol = a.named.get("Policy") if key == "authorize" else None
            if key == "authorize":
                first = a.args[0] if a.args else None
                for k, v in a.named.items():
                    if k == "Roles":
                        s = _const(model, v)
                        # A role list that is not a constant still names roles ("?": protective, names unknown).
                        item.roles = [r.strip() for r in s.split(",") if r.strip()] if s is not None else ["?"]
                    elif k == "Policy":
                        pol = v
                if first is not None:
                    pol = first
                if pol is not None:
                    s = _const(model, pol)
                    if s is None:
                        item.unknown.append("the policy name is not a constant")
                    elif s.strip():
                        item.policy = s
            else:
                _derived_data(model, t, a, item)
                for k, v in a.named.items():
                    s = _const(model, v)
                    if k == "Roles" and s:
                        item.roles += [r.strip() for r in s.split(",") if r.strip()]
                    elif k == "Policy" and s:
                        item.policy = s
            item.plain = not item.policy and not item.roles
            out.append(item)
            continue
        if key in ("typefilter", "servicefilter"):
            tn = _typeof(a.args[0]) if a.args else None
            ft = _find_class(model, tn) if tn else None
            if ft is not None and _implements(model, ft, "iauthorizationfilter", "iasyncauthorizationfilter"):
                v, detail = _filter_verdict(model, ft)
                out.append(_Item(f"attribute:{attr_simple(a.name)}({tn})", file, line, step, verdict=(v, detail)))
            elif tn and _AUTHZ_NAMED.search(tn) and ft is None:
                out.append(_Item(src, file, line, step, unknown=[f"{tn} is not defined in the solution"]))
            continue
        if t is not None and _implements(model, t, "iauthorizationfilter", "iasyncauthorizationfilter"):
            v, detail = _filter_verdict(model, t)
            out.append(_Item(src, file, line, step, verdict=(v, detail)))
            continue
        if t is not None and "allowanonymous" in _base_keys(model, t):
            out.append(_Item(src, file, line, step, anon=True))
            continue
        if _AUTHZ_NAMED.search(key):
            why = ("is a custom attribute whose enforcement could not be traced" if t is not None
                   else "is not defined in the solution")
            out.append(_Item(src, file, line, step, unknown=[f"attribute {attr_simple(a.name)} {why}"]))
    return out


# -- convention calls (endpoint, group, Map call) ---------------------------------------

def _call_site(sites: dict, node: dict, file: str, line: int | None = None) -> tuple[str, int]:
    pc = sites.get(id(node))
    return (pc.file, node.get("line") or pc.line) if pc is not None else (file, node.get("line") or line or 0)


def _authz_from_args(model: ProjectModel, S: _Settings, link: dict, item: _Item) -> None:
    """RequireAuthorization(...) arguments: policy names, a policy builder lambda, a policy expression."""
    args = list(link.get("args") or []) + list((link.get("named") or {}).values())
    if not args:
        item.plain = True
        return
    for a in args:
        if isinstance(a, dict) and a.get("k") == "lambda":
            item.inline = _policy_expr(model, a)
        elif isinstance(a, dict) and a.get("k") == "new" and _simple(a.get("type")) == "AuthorizeAttribute":
            sub = _attr_items(model, [Attr("Authorize", a.get("args") or [], a.get("init_named") or {}, 0)],
                              lambda n: n, None)
            for s in sub:
                if s.policy:
                    item.names.append(s.policy)
                item.roles += s.roles
                item.unknown += s.unknown
                item.plain = item.plain or s.plain
        elif isinstance(a, dict) and a.get("k") == "new" and _simple(a.get("type")) == "AuthorizationPolicyBuilder" or (
                isinstance(a, dict) and a.get("k") == "call"):
            item.inline = _policy_expr(model, a)
        else:
            s = _const(model, a)
            if s is None:
                item.unknown.append("a RequireAuthorization argument is not a constant policy name")
            elif s.strip():
                item.names.append(s)
            else:
                item.plain = True
    if item.names:
        item.policy = item.names[0]


def _call_items(model: ProjectModel, S: _Settings, sites: dict, ref: CoreRouteRef, calls: list[dict],
                label: str, file: str, line: int, step: int = 2) -> tuple[list[_Item], list[str]]:
    """Items and route-level reasons for the fluent calls applied at one level (endpoint, group, Map call)."""
    items: list[_Item] = []
    reasons: list[str] = []
    for link in calls:
        name = call_name(link) or ""
        f, ln = _call_site(sites, link, file, line)
        src = f"{label} {name}"
        if name == "AllowAnonymous":
            items.append(_Item(src, f, ln, step, anon=True))
        elif name == "RequireAuthorization":
            it = _Item(src, f, ln, step)
            _authz_from_args(model, S, link, it)
            it.conditional = f"{name} applied conditionally" in ref.unknown
            items.append(it)
        elif name == "WithMetadata":
            for a in link.get("args") or []:
                if isinstance(a, dict) and a.get("k") == "new":
                    tn = attr_key(a.get("type") or "")
                    if tn == "allowanonymous":
                        items.append(_Item(src, f, ln, step, anon=True))
                    elif tn == "authorize":
                        it = _Item(src, f, ln, step)
                        for s in _attr_items(model, [Attr("Authorize", a.get("args") or [], {}, 0)], lambda n: n, None):
                            it.policy, it.roles, it.plain, it.unknown = s.policy, s.roles, s.plain, s.unknown
                        it.conditional = f"{name} applied conditionally" in ref.unknown
                        items.append(it)
        elif name in _ENDPOINT_FILTERS:
            reasons.append(f"{name} at {f}:{ln} may reject requests or change the endpoint metadata")
        elif name in ("Add", "Finally"):
            reasons.append(f"{name}(...) convention at {f}:{ln} may change endpoint metadata and is not analysed")
        elif name not in _BENIGN_CONVENTIONS and not (link.get("sym") or "").startswith("Microsoft."):
            reasons.append(f"{name} at {f}:{ln} is not analysed")
    return items, reasons


# -- Razor Pages conventions ------------------------------------------------------------

def _segs(path: str) -> list[str]:
    return [s.lower() for s in path.replace("\\", "/").strip("/").split("/") if s]


def _conv_matches(name: str, args: list[str], page: str, area: str | None) -> bool:
    is_area = "Area" in name
    if is_area:
        if not area or not args or args[0].lower() != area.lower():
            return False
        args = args[1:]
    elif area:
        return False
    if not args:
        return False
    target = args[0]
    if name.endswith("Folder"):
        folder, pg = _segs(target), _segs(page)[:-1]
        return pg[:len(folder)] == folder
    if name.endswith("Page"):
        return _segs(target) == _segs(page)
    return False


def _page_items(model: ProjectModel, S: _Settings, ref: CoreRouteRef) -> tuple[list[_Item], list[str]]:
    """Items from Authorize* / AllowAnonymousTo* conventions covering the page; reasons that make
    such a convention unreadable or uncertain (they block PROTECTED: it could be an anonymous opt-out)."""
    page = ref.route.meta.get("page") or ""
    area = ref.route.meta.get("area")
    items: list[_Item] = []
    block: list[str] = []
    for f in S.page_convs:
        name = f.data["name"]
        if not name.startswith(("Authorize", "AllowAnonymousTo")):
            continue
        link = f.data["call"]
        args = [_const(model, a) for a in link.get("args") or []]
        anon = name.startswith("AllowAnonymousTo")
        n_paths = 2 if "Area" in name else 1
        paths = args[:n_paths]
        if any(p is None for p in paths) or len(paths) < n_paths:
            block.append(f"{name} at {f.file}:{f.line} has a path that is not a constant")
            continue
        if not _conv_matches(name, paths, page, area):
            continue
        shown = ",".join(paths)
        src = f"convention:{name}({shown})"
        if anon:
            if f.certain:
                items.append(_Item(src, f.file, f.line, 3, anon=True))
            else:
                block.append(f"{name}({shown}) at {f.file}:{f.line} is under a condition that could not be evaluated")
            continue
        it = _Item(src, f.file, f.line, 3)
        policy = args[n_paths] if len(args) > n_paths else None
        if policy:
            it.policy = policy
        elif len(link.get("args") or []) > n_paths:
            it.unknown.append(f"{name} policy is not a constant")
        else:
            it.plain = True
        it.conditional = not f.certain
        items.append(it)
    return items, block


# -- global filters ----------------------------------------------------------------------

def _filter_items(model: ProjectModel, S: _Settings, ref: CoreRouteRef) -> list[_Item]:
    items: list[_Item] = []
    for f in S.filters:
        link = f.data["call"]
        args = link.get("args") or []
        targs = (link.get("fn") or {}).get("targs") or []
        tn = _simple(targs[0]) if targs else None
        arg = args[0] if args else None
        if tn is None and isinstance(arg, dict):
            tn = _simple(arg.get("type")) if arg.get("k") == "new" else _typeof(arg)
        if not tn:
            continue
        ctor_args = arg.get("args") or [] if isinstance(arg, dict) and arg.get("k") == "new" else []
        t = _find_class(model, tn)
        src = f"filter:{tn}"
        if tn == "AuthorizeFilter" or (t is not None and "authorizefilter" in _bases(model, t)):
            it = _Item(src, f.file, f.line, 3, conditional=not f.certain)
            if not ctor_args:
                it.plain = True
            else:
                a = ctor_args[0]
                s = _const(model, a)
                if s is not None:
                    it.policy = s
                elif isinstance(a, dict) and (a.get("k") == "call" or (a.get("k") == "new"
                                              and _simple(a.get("type")) == "AuthorizationPolicyBuilder")):
                    it.inline = _policy_expr(model, a)
                else:
                    it.unknown.append("the AuthorizeFilter policy is not analysed")
            items.append(it)
        elif t is not None and _implements(model, t, "iauthorizationfilter", "iasyncauthorizationfilter"):
            v, detail = _filter_verdict(model, t)
            items.append(_Item(src, f.file, f.line, 3, verdict=(v, detail), conditional=not f.certain))
        elif _AUTHZ_NAMED.search(tn):
            why = "is not defined in the solution" if t is None else "is not a filter this module can analyse"
            items.append(_Item(src, f.file, f.line, 3, unknown=[f"global filter {tn} {why}"]))
    return items


# -- per route ----------------------------------------------------------------------------

def _eval_item(S: _Settings, it: _Item) -> tuple[str, list[str], list[str], list[str], list[str]]:
    """(verdict, policies, roles, notes, reasons) of one piece of authorization metadata."""
    if it.unknown:
        return UNK, [], list(it.roles), [], list(it.unknown)
    policies: list[str] = []
    roles = [r for r in it.roles if r != "?"]
    notes: list[str] = []
    verdicts: list[str] = []
    reasons: list[str] = []
    if it.verdict is not None:
        v, detail = it.verdict
        if v == NEVER:
            notes.append(f"{detail} (can never deny)")
        elif v == UNK:
            reasons.append(detail)
        return v, [], [], notes, reasons
    if it.roles:
        verdicts.append(PROT)
    names = it.names or ([it.policy] if it.policy else [])
    for n in names:
        policies.append(n)
        v, pol, rs = _named(S, n)
        verdicts.append(v)
        reasons += rs
        if pol is not None and v == PROT:
            roles += pol.roles
        elif v == NEVER:
            notes.append(f"policy \"{n}\" never denies: {pol.why()}")
    if it.inline is not None:
        v = _pol_verdict(it.inline)
        verdicts.append(v)
        roles += it.inline.roles
        if v == NEVER:
            notes.append(f"inline policy never denies: {it.inline.why()}")
        elif v == UNK:
            reasons.append("an inline policy cannot be analysed: " + "; ".join(it.inline.unknown))
    if it.plain or not (names or it.roles or it.inline is not None):
        v, pol, fact, rs = _global_policy(S.default, "DefaultPolicy")
        if v == "none":
            v = PROT
        verdicts.append(v)
        reasons += rs
        if v == NEVER:
            notes.append(f"DefaultPolicy never denies: {pol.why()}")
    if PROT in verdicts:
        return PROT, policies, _dedup(roles), notes, []
    if UNK in verdicts:
        return UNK, policies, _dedup(roles), notes, _dedup(reasons)
    return NEVER, policies, _dedup(roles), notes, []


def _attr_file(ref: CoreRouteRef, ct: TypeIR, a: Attr) -> str:
    for half in ref.partials if ct is ref.type else []:
        if any(x is a for x in half.attributes):
            return half.file
    return ct.file


def _route_items(model: ProjectModel, S: _Settings, pipe: Pipeline, ref: CoreRouteRef,
                 notes: list[str]) -> tuple[list[_Item], list[str], list[str]]:
    """(items in specificity order, route-level reasons, reasons that block PROTECTED)."""
    items: list[_Item] = []
    reasons: list[str] = []
    block: list[str] = []
    sites = {id(c.node): c for c in pipe.calls}
    route = ref.route
    mfile = getattr(route, "source_file", None) or route.file

    if ref.method is not None:
        if ref.style == "razorpage":
            for a in ref.method.attributes:
                k = attr_key(a.name)
                if k == "authorize" or _AUTHZ_NAMED.search(k) or k == "allowanonymous":
                    notes.append(f"[{attr_simple(a.name)}] on handler method {ref.method.name} is ignored by Razor Pages")
        else:
            items += _attr_items(model, ref.method.attributes, lambda n: f"attribute:{n}", mfile)
    kind = route.meta.get("kind")
    if ref.type is not None and (ref.style in ("controller", "razorpage") or (ref.style == "endpoint" and kind in ("hub", "grpc"))):
        for i, ct in enumerate(_chain_types(model, ref.type)):
            label = (lambda n: f"attribute:{n}") if i == 0 else (lambda n, ct=ct: f"base:{ct.name.split('.')[-1]}")
            # Attributes carry no file of their own: the declaring half is found by identity.
            items += _attr_items(model, ct.attributes, label, _attr_file(ref, ct, ct.attributes[0]) if ct.attributes else ct.file)
    its, rs = _call_items(model, S, sites, ref, ref.endpoint_calls, "endpoint:", mfile, route.line)
    items += _relabel(its, "endpoint")
    reasons += rs
    for g in reversed(ref.groups):
        its, rs = _call_items(model, S, sites, ref, g.calls, "group", g.file, g.line)
        for it in its:
            it.source = f"group:{g.prefix or '(inherited)'} {it.source.split(' ', 1)[1]}"
        items += its
        reasons += rs
    map_name = {"razorpage": "MapRazorPages()"}.get(ref.style, "MapControllers()")
    its, rs = _call_items(model, S, sites, ref, ref.convention_calls, map_name, mfile, route.line)
    for it in its:
        it.source = f"{map_name}.{it.source.split(' ', 1)[1]}"
    items += its
    reasons += rs
    if ref.style in _MVC_STYLES:
        items += _filter_items(model, S, ref)
    if ref.style == "razorpage":
        its, blk = _page_items(model, S, ref)
        items += its
        block += blk
    return items, reasons, block


def _relabel(items: list[_Item], label: str) -> list[_Item]:
    for it in items:
        it.source = f"{label}:{it.source.split(' ', 1)[1]}"
    return items


def resolve(model: ProjectModel, ref: CoreRouteRef, pipe: Pipeline) -> CoreAuth:
    S = _settings(model, pipe)
    route = ref.route
    if route.meta.get("middleware"):
        return CoreAuth(UNPROTECTED, "middleware (not endpoint-routed; authorization does not apply)",
                        file=route.file, line=route.line)
    notes: list[str] = []
    items, route_reasons, block = _route_items(model, S, pipe, ref, notes)
    cond = [r for r in ref.unknown if r.endswith("applied conditionally")]

    # 1. anonymous beats every other mechanism.
    for it in items:
        if it.anon:
            if f"{re.split(r'[ .]', it.source)[-1]} applied conditionally" in ref.unknown:
                notes.append(f"{it.source} is applied conditionally")
            return CoreAuth(ANONYMOUS, it.source, file=it.file, line=it.line, notes=notes)

    evals = [(it, _eval_item(S, it)) for it in items]
    pnames = _dedup(p for _, e in evals for p in e[1])
    roles = _dedup(r for _, e in evals for r in e[2])
    for _, e in evals:
        notes += e[3]
    notes = _dedup(notes)
    has_meta = any(it.step == 2 for it, _ in evals) or any(it.step == 3 and not it.anon for it, _ in evals)

    def prot(step: int):
        return next(((it, e) for it, e in evals if it.step == step and e[0] == PROT and not it.conditional), None)

    p2, p3 = prot(2), prot(3)
    downgraded = False
    chosen = None
    if p2 is not None:
        chosen = p2
        if S.issue is not None and S.suppress_certain:
            downgraded = True
        elif S.issue is not None and S.suppress_uncertain:
            return CoreAuth(UNKNOWN, "none", policies=pnames, roles=roles,
                            reasons=["SuppressCheckForUnhandledSecurityMetadata is set under a condition that could not "
                                     f"be evaluated, and {S.issue[0]}"], notes=notes)
        if p3 is not None and downgraded:
            chosen, downgraded = p3, False
    elif p3 is not None:
        chosen = p3
    if chosen is not None and not downgraded:
        it, e = chosen
        if block:
            return CoreAuth(UNKNOWN, "none", policies=pnames, roles=roles, reasons=block, notes=notes)
        return CoreAuth(PROTECTED, it.source, roles, pnames, it.file, it.line, notes=notes)
    if downgraded:
        it, _e = chosen
        notes.append(f"{it.source} is not enforced: {S.issue[0]} and SuppressCheckForUnhandledSecurityMetadata "
                     "is true")
        return CoreAuth(UNPROTECTED, "none", roles, pnames, it.file, it.line, notes=notes)

    # Nothing definite protects the route.
    reasons = list(ref.unknown)
    never = next(((it, e) for it, e in evals if e[0] == NEVER), None)
    unk = [(it, e) for it, e in evals if e[0] == UNK]
    cond_prot = [(it, e) for it, e in evals if e[0] == PROT and it.conditional]
    for it, e in unk:
        reasons += e[4]
    if cond_prot:
        reasons.append(f"{cond_prot[0][0].source} is applied conditionally")
    if unk or cond_prot:
        return CoreAuth(UNKNOWN, "none", roles, pnames, reasons=_dedup(reasons), notes=notes)

    fb_note = None
    if not has_meta:
        v, pol, fact, rs = _global_policy(S.fallback, "FallbackPolicy")
        if v == PROT:
            if S.issue is not None and S.suppress_certain:
                notes.append("fallback policy is not enforced: " + S.issue[0] + " and "
                             "SuppressCheckForUnhandledSecurityMetadata is true")
                return CoreAuth(UNPROTECTED, "none", file=fact.file, line=fact.line, notes=notes)
            if S.issue is not None and S.suppress_uncertain:
                return CoreAuth(UNKNOWN, "none", reasons=["SuppressCheckForUnhandledSecurityMetadata is set under a "
                                                          "condition that could not be evaluated, and " + S.issue[0]],
                                notes=notes)
            if block:
                return CoreAuth(UNKNOWN, "none", reasons=block, notes=notes)
            if ref.caller_unknown:
                notes.append("registered by a method with no traced caller; a convention applied by the caller "
                             "would not be seen")
            if ref.unknown:
                notes.append("conventions that could not be traced may apply to this route: " + "; ".join(ref.unknown))
            return CoreAuth(PROTECTED, "fallback policy", roles, pnames, fact.file, fact.line, notes=notes)
        if v == NEVER:
            fb_note = f"fallback policy never denies: {pol.why()}"
            notes.append(fb_note)
        elif v == UNK:
            reasons += rs
    reasons += route_reasons
    if ref.caller_unknown:
        reasons.append("the method registering this route has no traced caller")
    reasons += S.reasons_for(ref.style)
    if reasons:
        return CoreAuth(UNKNOWN, "none", roles, pnames, reasons=_dedup(reasons), notes=notes)
    if never is not None:
        it, e = never
        why = e[3][0] if e[3] else "never denies"
        return CoreAuth(UNPROTECTED, f"{it.source}: {why}", roles, pnames, it.file, it.line, notes=notes)
    if fb_note:
        return CoreAuth(UNPROTECTED, "fallback policy (never denies)", roles, pnames, notes=notes)
    return CoreAuth(UNPROTECTED, "none", roles, pnames, notes=notes)


def policies(model: ProjectModel, pipe: Pipeline) -> dict[str, PolicyInfo]:
    """Authorization policies registered in Production (AddPolicy), by name."""
    return dict(_settings(model, pipe).policies)
