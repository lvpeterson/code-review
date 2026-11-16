"""ASP.NET Core pipeline facts: the ordered, environment-tagged service registrations,
middleware and endpoint calls of an app's Program.cs / Startup code.

Entry points per netcore project: the top-level `<Main>$`; else a `Startup` class
(`ConfigureServices` then `Configure`, every partial half); else a static `Main`.
Calls to solution methods are followed inline at the call site. Lambdas passed as
arguments are not separate calls -- rules read them from `PipeCall.node`.

The IR drops generic arguments, so `UseStartup<T>()` cannot name T: the class named
`Startup` is used, else a type that declares both `ConfigureServices` and `Configure`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ir import MethodIR, TypeIR, call_chain, call_name, is_top_level, literal_str, receiver_text
from .project import Project, ProjectModel

# ASP.NET Core / Extensions method names treated as resolved when the helper gave no `sym`
# (degraded mode, or a call the semantic model could not bind).
_FRAMEWORK_CALLS = frozenset("""
AddControllers AddControllersWithViews AddMvc AddRazorPages AddRazorPagesOptions AddAuthentication
AddAuthorization AddAuthorizationBuilder AddCookie AddPolicy SetFallbackPolicy SetDefaultPolicy AddCors
AddSession AddAntiforgery AddRateLimiter AddHealthChecks AddSignalR AddGrpc AddEndpointsApiExplorer
AddHttpClient AddDataProtection Configure UseRouting UseAuthentication UseAuthorization UseEndpoints
UseHttpsRedirection UseHsts UseStaticFiles UseCors UseSession UseExceptionHandler
UseDeveloperExceptionPage UseRateLimiter UseAntiforgery Map MapGet MapPost MapPut MapPatch MapDelete
MapMethods MapGroup MapControllers MapControllerRoute MapDefaultControllerRoute MapAreaControllerRoute
MapRazorPages MapHub MapGrpcService MapHealthChecks MapFallback MapFallbackToFile MapFallbackToPage
MapFallbackToController MapRazorComponents MapBlazorHub MapOpenApi RequireAuthorization AllowAnonymous
Build Run RunAsync
""".split())

_MAX_DEPTH = 8
_FACTORIES = frozenset({"CreateBuilder", "CreateSlimBuilder", "CreateEmptyBuilder"})
_ENV_CALLS = {"isdevelopment": "Development", "isproduction": "Production", "isstaging": "Staging"}
# Parameter / local type -> builder kind.
_TYPE_KINDS = {
    "iservicecollection": "services", "servicecollection": "services",
    "iapplicationbuilder": "app", "webapplication": "app", "ihost": "app", "iwebhost": "app",
    "iendpointroutebuilder": "endpoints", "routegroupbuilder": "endpoints",
    "iendpointconventionbuilder": "endpoints", "controlleractionendpointconventionbuilder": "endpoints",
}


@dataclass
class PipeCall:
    name: str            # method name, e.g. "UseAuthorization"
    kind: str            # "services" | "app" | "endpoints" | "other"
    node: dict           # the call expr
    chain: list[dict]    # the full fluent chain this call sits in (call_chain order)
    file: str
    line: int
    env: str | None      # None = always; "Development"; "!Development"; other env names as written
    resolved: bool       # sym present, or name in _FRAMEWORK_CALLS, or a followed solution method
    order: int           # execution order within the pipeline


@dataclass
class Pipeline:
    project: Project | None
    style: str           # "minimal" | "startup" | "none"
    calls: list[PipeCall] = field(default_factory=list)
    target_framework: str | None = None

    def named(self, *names: str, kinds: tuple[str, ...] = (), include_dev: bool = False) -> list[PipeCall]:
        """Calls in execution order, filtered by method name and kind. Calls that only
        run in Development are left out unless include_dev."""
        want = set(names)
        return [c for c in self.calls
                if (not want or c.name in want) and (not kinds or c.kind in kinds)
                and (include_dev or c.env != "Development")]

    def unresolved(self) -> list[PipeCall]:
        return [c for c in self.calls if not c.resolved]


# -- environment conditions -------------------------------------------------

def _negate(env: str | None) -> str | None:
    if env is None:
        return None
    return env[1:] if env.startswith("!") else "!" + env


def _cond_env(cond) -> tuple[str | None, str | None]:
    """(env when cond is true, env when false) for an `if` condition; None = unknown."""
    if not isinstance(cond, dict):
        return None, None
    k = cond.get("k")
    if k == "call":
        nm = (call_name(cond) or "").lower()
        if nm in _ENV_CALLS:
            e = _ENV_CALLS[nm]
            return e, _negate(e)
        if nm == "isenvironment":
            args = cond.get("args") or []
            lit = literal_str(args[0]) if args else None
            if lit:
                return lit, _negate(lit)
        return None, None
    if k == "unary" and cond.get("op") == "!":
        t, f = _cond_env(cond.get("e"))
        return f, t
    if k == "bin":
        op = cond.get("op")
        if op in ("&&", "and", "andalso"):
            lt, _ = _cond_env(cond.get("l"))
            rt, _ = _cond_env(cond.get("r"))
            return lt or rt, None
        if op in ("||", "or", "orelse"):
            _, lf = _cond_env(cond.get("l"))
            _, rf = _cond_env(cond.get("r"))
            return None, lf or rf
        if op in ("==", "!="):
            # `x.EnvironmentName == "Name"`
            for a, b in ((cond.get("l"), cond.get("r")), (cond.get("r"), cond.get("l"))):
                if isinstance(a, dict) and a.get("k") == "member" and a.get("name") == "EnvironmentName":
                    lit = literal_str(b)
                    if lit:
                        return (lit, _negate(lit)) if op == "==" else (_negate(lit), lit)
    return None, None


# -- kinds ------------------------------------------------------------------

def _sym_kind(sym: str | None) -> str | None:
    if not sym:
        return None
    owner = sym.rsplit(".", 1)[0]
    last = owner.rsplit(".", 1)[-1]
    if owner.startswith("Microsoft.Extensions.DependencyInjection.") or last == "IServiceCollection":
        return "services"
    if owner.startswith(("Microsoft.AspNetCore.Builder.", "Microsoft.AspNetCore.Routing.")):
        if ("EndpointRouteBuilder" in last or "RouteGroup" in last
                or ("Endpoint" in last and last.endswith("Extensions") and "ApplicationBuilder" not in last)):
            return "endpoints"
        if owner.startswith("Microsoft.AspNetCore.Builder."):
            return "app"
        return None
    if last in ("IApplicationBuilder", "WebApplication"):
        return "app"
    return None


def _type_kind(t: str | None) -> str | None:
    if not t:
        return None
    return _TYPE_KINDS.get(t.split("<")[0].split(".")[-1].strip().lower())


@dataclass
class _Ctx:
    """State of one pipeline build."""
    calls: list[PipeCall] = field(default_factory=list)
    order: int = 0
    # Solution methods by simple name.
    methods: dict[str, list[tuple[TypeIR, MethodIR]]] = field(default_factory=dict)


def _expr_kind(e, scope: dict) -> str | None:
    """Builder kind of an expression: a known name, a `.Services` member, a chain's result."""
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "name":
        return scope.get(e.get("id"))
    if k == "member":
        return "services" if e.get("name") == "Services" else None
    if k == "call":
        root, calls = call_chain(e)
        if calls:
            return _call_kind(calls[-1], root, calls, scope)
    return None


def _call_kind(call: dict, root, calls: list[dict], scope: dict) -> str:
    # Builder factories are not part of any pipeline stage, with or without a symbol.
    if call_name(call) in _FACTORIES:
        return "other"
    k = _sym_kind(call.get("sym"))
    if k:
        return k
    nm = call_name(call) or ""
    if not call.get("sym") and nm.startswith("Map"):
        return "endpoints"
    # Chain root: `x.Services` / `services` / a known local or parameter.
    text = receiver_text(root) if root is not None else ""
    if text.endswith(".Services") or text.lower() == "services":
        return "services"
    rk = _expr_kind(root, scope) if root is not None else None
    if rk in ("services", "app", "endpoints"):
        return rk
    # A later link of a chain whose earlier link has a known kind (`AddAuthentication().AddCookie()`).
    for prev in calls[: calls.index(call)][::-1]:
        pk = _sym_kind(prev.get("sym"))
        if pk:
            return pk
    if nm == "Build" and rk == "builder":
        return "app"
    return "other"


# -- following solution methods ---------------------------------------------

def _is_ext(m: MethodIR) -> bool:
    return bool(m.params) and "this" in [x.lower() for x in m.params[0].modifiers]


def _is_member_call(call: dict) -> bool:
    fn = call.get("fn")
    return isinstance(fn, dict) and fn.get("k") == "member"


def _find_target(ctx: _Ctx, call: dict) -> tuple[TypeIR, MethodIR] | None:
    """The solution method a call goes to, or None for a framework / external call."""
    nm = call_name(call)
    cands = ctx.methods.get(nm or "")
    if not cands:
        return None
    sym = call.get("sym")
    nargs = len(call.get("args") or [])
    if sym:
        owner = sym.rsplit(".", 1)[0] if "." in sym else None
        hits = [(t, m) for t, m in cands if owner is not None and t.full_name == owner]
        if not hits:
            return None
    else:
        # No symbol: a unique method by name, never a name the framework also uses.
        if nm in _FRAMEWORK_CALLS or len(cands) != 1:
            return None
        hits = cands
        t, m = hits[0]
        # A plain method must be called bare, via this, or by type name; an extension on any receiver.
        if _is_member_call(call) and not _is_ext(m):
            if receiver_text(call["fn"].get("obj")) not in ("this", t.name, t.full_name):
                return None
    # Overloads: prefer the one whose arity fits (an extension's `this` is the receiver).
    def fits(m: MethodIR) -> bool:
        n = len(m.params) - (1 if _is_ext(m) and _is_member_call(call) else 0)
        return n >= nargs or any("params" in [x.lower() for x in p.modifiers] for p in m.params)
    return next((h for h in hits if fits(h[1])), hits[0])


def _scope_for(m: MethodIR, recv_kind: str | None, arg_kinds: list[str | None], ext: bool) -> dict:
    """Builder kinds of a followed method's parameters: by declared type, else from the call site."""
    scope: dict[str, str] = {}
    for i, p in enumerate(m.params):
        k = _type_kind(p.type)
        if i == 0 and ext:
            k = k or recv_kind
        else:
            ai = i - (1 if ext else 0)
            if k is None and 0 <= ai < len(arg_kinds):
                k = arg_kinds[ai]
        if k:
            scope[p.name] = k
    return scope


# -- walking ----------------------------------------------------------------

def _stmts(ctx: _Ctx, stmts, scope: dict, env: str | None, file: str, stack: tuple, depth: int) -> None:
    for s in stmts or []:
        _stmt(ctx, s, scope, env, file, stack, depth)


def _stmt(ctx: _Ctx, s, scope: dict, env: str | None, file: str, stack: tuple, depth: int) -> None:
    if not isinstance(s, dict):
        return
    k = s.get("k")
    if k == "expr":
        _expr(ctx, s.get("expr"), scope, env, file, stack, depth)
    elif k == "local":
        init = s.get("init")
        kind = _expr(ctx, init, scope, env, file, stack, depth)
        nm = s.get("name")
        if nm:
            if kind == "other":
                kind = None
            kind = kind or _type_kind(s.get("type_full")) or _type_kind(s.get("type"))
            if not kind and isinstance(init, dict) and call_name(init) in _FACTORIES:
                kind = "builder"
            if kind:
                scope[nm] = kind
            else:
                scope.pop(nm, None)
    elif k == "return":
        _expr(ctx, s.get("value"), scope, env, file, stack, depth)
    elif k == "if":
        t_env, f_env = _cond_env(s.get("cond"))
        _stmts(ctx, s.get("then"), scope, t_env or env, file, stack, depth)
        _stmts(ctx, s.get("else"), scope, f_env or env, file, stack, depth)
    elif k == "loop":
        _stmts(ctx, s.get("body"), scope, env, file, stack, depth)
    elif k == "using":
        _stmts(ctx, s.get("resource"), scope, env, file, stack, depth)
        _stmts(ctx, s.get("body"), scope, env, file, stack, depth)
    elif k == "try":
        _stmts(ctx, s.get("body"), scope, env, file, stack, depth)
        for c in s.get("catches") or []:
            _stmts(ctx, c.get("body"), scope, env, file, stack, depth)
        _stmts(ctx, s.get("finally"), scope, env, file, stack, depth)


def _expr(ctx: _Ctx, e, scope: dict, env: str | None, file: str, stack: tuple, depth: int) -> str | None:
    """Record the calls of one expression statement or initializer; returns the builder
    kind of its value (for `var app = builder.Build()`)."""
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "assign":
        kind = _expr(ctx, e.get("value"), scope, env, file, stack, depth)
        tgt = e.get("target")
        if kind and isinstance(tgt, dict) and tgt.get("k") == "name":
            scope[tgt.get("id")] = kind
        return kind
    if k != "call":
        return None
    root, calls = call_chain(e)
    # What each link is called on: the chain root first, then the previous link's result.
    recv_kind = _expr_kind(root, scope) if root is not None else None
    if root is not None and root.get("k") == "member" and root.get("name") == "Services":
        recv_kind = "services"
    kind = None
    for call in calls:
        kind = _call_kind(call, root, calls, scope)
        nm = call_name(call) or ""
        target = _find_target(ctx, call)
        if target is not None and target[1] in stack:
            continue  # cycle guard: re-entering a method being followed adds no new fact
        ctx.calls.append(PipeCall(
            name=nm, kind=kind, node=call, chain=calls, file=file, line=call.get("line", 0), env=env,
            resolved=bool(call.get("sym")) or nm in _FRAMEWORK_CALLS or target is not None,
            order=ctx.order))
        ctx.order += 1
        if target is not None and depth < _MAX_DEPTH:
            t, m = target
            ext = _is_ext(m) and _is_member_call(call)
            arg_kinds = [_expr_kind(a, scope) for a in call.get("args") or []]
            _stmts(ctx, m.body, _scope_for(m, recv_kind, arg_kinds, ext), env, t.file, stack + (m,), depth + 1)
        recv_kind = kind
    # A `Build()` result is the app, whatever the builder was called.
    if calls and call_name(calls[-1]) == "Build" and kind == "other":
        return "app"
    return kind


# -- entry points -----------------------------------------------------------

def _entry_methods(types: list[TypeIR]) -> tuple[str, list[tuple[TypeIR, MethodIR]]]:
    for t in types:
        for m in t.methods:
            if is_top_level(m):
                return "minimal", [(t, m)]
    startup = [t for t in types if t.name == "Startup"]
    if not startup:
        # `UseStartup<T>()`: T is not in the IR; take a type that looks like a startup class.
        startup = [t for t in types if {"ConfigureServices", "Configure"} <= {m.name for m in t.methods}]
        first = sorted({t.name for t in startup})[:1]
        startup = [t for t in startup if t.name in first]
    out = [(t, m) for want in ("ConfigureServices", "Configure") for t in startup
           for m in t.methods if m.name == want]
    if out:
        return "startup", out
    for t in types:
        for m in t.methods:
            if m.name == "Main" and "static" in [x.lower() for x in m.modifiers]:
                return "minimal", [(t, m)]
    return "none", []


def _build(model: ProjectModel, proj: Project | None) -> Pipeline:
    tfm = None
    if proj is not None:
        tfm = proj.target_framework or (proj.target_frameworks[0] if proj.target_frameworks else None)
    ctx = _Ctx()
    types: list[TypeIR] = []
    for rel, f in model.files.items():
        if proj is not None and model.project_of(rel) is not proj:
            continue
        for t in f.types:
            types.append(t)
            for m in t.methods:
                ctx.methods.setdefault(m.name, []).append((t, m))
    style, entries = _entry_methods(types)
    for t, m in entries:
        scope = {p.name: k for p in m.params if (k := _type_kind(p.type))}
        _stmts(ctx, m.body, scope, None, t.file, (m,), 1)
    return Pipeline(proj, style, ctx.calls, tfm)


def pipeline_for(model: ProjectModel, proj: Project | None) -> Pipeline:
    """Pipeline facts of one project (None = every file of the model); cached on the model."""
    cache = model.cache.setdefault("pipelines", {})
    key = id(proj) if proj is not None else None
    if key not in cache:
        cache[key] = _build(model, proj)
    return cache[key]
