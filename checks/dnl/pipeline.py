"""ASP.NET Core pipeline facts: the ordered, environment-tagged service registrations,
middleware and endpoint calls of an app's Program.cs / Startup code.

Entry points per netcore project: the top-level `<Main>$`; else a `Startup` class
(`ConfigureServices` then `Configure`, every partial half); else a static `Main`.
Calls to solution methods are followed inline at the call site (PipeCall.target, and
PipeCall.via on the calls inside). Lambdas passed as arguments are not separate calls --
rules read them from `PipeCall.node` -- except the body of a `UseEndpoints` lambda, whose
parameter is an endpoint builder and whose calls are walked in place.

`UseStartup<T>()` names the startup class through the IR's `targs`; without it the class
named `Startup` is used, else a type that declares both `ConfigureServices` and `Configure`
(a note is recorded on `Pipeline.notes` when that leaves several candidates).

Environment conditions: every enclosing `if` becomes a guard (predicate + branch taken);
`PipeCall.runs_in(env)` evaluates them three-valued, so an unparseable environment check
gives None ("cannot tell"), never a silent "always".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .ir import MethodIR, TypeIR, call_chain, call_name, is_top_level, literal_str, receiver_text, walk
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
    # Environment conditions this call sits under: (predicate, branch taken) pairs, outermost first.
    guards: tuple = ()
    # Solution calls followed to reach this one (id() of each call node, outermost first), so the
    # same method followed from two sites yields distinct (via, node) keys.
    via: tuple = ()
    # (type, method) this call was followed into; None for framework calls and calls not followed.
    target: tuple | None = None

    def runs_in(self, env_name: str) -> bool | None:
        """True when the call runs in that environment, False when it does not, None when
        the enclosing conditions cannot tell (an environment check that could not be parsed)."""
        res: bool | None = True
        for pred, taken in self.guards:
            v = _eval(pred, env_name.lower())
            if v is not None and not taken:
                v = not v
            if v is False:
                return False
            if v is None:
                res = None
        return res


@dataclass
class Pipeline:
    project: Project | None
    style: str           # "minimal" | "startup" | "none"
    calls: list[PipeCall] = field(default_factory=list)
    target_framework: str | None = None
    notes: list[str] = field(default_factory=list)
    # The entry methods the walk started from (type, method), in walk order.
    entries: list = field(default_factory=list)

    def named(self, *names: str, kinds: tuple[str, ...] = (), include_dev: bool = False) -> list[PipeCall]:
        """Calls in execution order, filtered by method name and kind. Unless include_dev,
        only calls that certainly run in Production are returned (see uncertain())."""
        want = set(names)
        return [c for c in self.calls
                if (not want or c.name in want) and (not kinds or c.kind in kinds)
                and (include_dev or c.runs_in("Production") is True)]

    def uncertain(self) -> list[PipeCall]:
        """Calls under an environment condition that could not be parsed."""
        return [c for c in self.calls if c.runs_in("Production") is None]

    def unresolved(self) -> list[PipeCall]:
        return [c for c in self.calls if not c.resolved]


# -- environment conditions -------------------------------------------------
# A predicate is ("env", lowered name) | ("not", p) | ("and", p, q) | ("or", p, q) | ("unknown",).

_UNKNOWN = ("unknown",)
_ENV_MEMBERS = {"development", "staging", "production"}


def _eval(p, env: str) -> bool | None:
    k = p[0]
    if k == "env":
        return p[1] == env
    if k == "not":
        v = _eval(p[1], env)
        return None if v is None else not v
    if k in ("and", "or"):
        vs = [_eval(x, env) for x in p[1:]]
        stop = k == "or"
        if stop in vs:
            return stop
        return None if None in vs else not stop
    return None


def _env_name(e) -> str | None:
    """An environment name: a string literal or `Environments.X` (any qualifier), lowered."""
    lit = literal_str(e)
    if lit:
        return lit.lower()
    if isinstance(e, dict) and e.get("k") == "member" and (e.get("name") or "").lower() in _ENV_MEMBERS:
        return e["name"].lower()
    return None


def _is_env_name_expr(e) -> bool:
    return isinstance(e, dict) and e.get("k") == "member" and e.get("name") == "EnvironmentName"


def _env_node(n: dict) -> bool:
    """True for a node that reads the hosting environment."""
    k = n.get("k")
    if k == "call":
        return (call_name(n) or "").lower() in ("isdevelopment", "isproduction", "isstaging", "isenvironment")
    if k == "member":
        obj = n.get("obj")
        return n.get("name") in ("EnvironmentName", "Environment") or (
            isinstance(obj, dict) and obj.get("k") == "name" and obj.get("id") == "Environments")
    return False


def _closure_scope(scope: dict, lam: dict) -> dict:
    """The caller's scope as a local function sees it: a name the function binds itself
    (parameter or local) hides the caller's environment fact about that name, so it is
    unknown rather than the caller's value."""
    names = {x for x in lam.get("params") or [] if isinstance(x, str)}
    names |= {n.get("name") for n in walk(lam.get("body")) if n.get("k") == "local" and n.get("name")}
    out = dict(scope)
    for n in names:
        if (_ENV_LOCAL + n) in out or (_TAINT + n) in out:
            out.pop(_ENV_LOCAL + n, None)
            out[_TAINT + n] = True
    return out


def _callee_body(ctx: _Ctx, scope: dict, call: dict) -> tuple:
    """(body, scope to read it in) of the solution method or local function a call goes to;
    the body is a stmt list, or the expression of an expression-bodied lambda. (None, {}) for
    framework / external calls. A local function sees the caller's locals; a method does not."""
    fn = call.get("fn") or {}
    if fn.get("k") == "name":
        lam = scope.get(_LOCAL_FN + (fn.get("id") or ""))
        if isinstance(lam, dict):
            return lam.get("body"), _closure_scope(scope, lam)
    t = _find_target(ctx, call)
    return (t[1].body, {}) if t is not None else (None, {})


def _single_return(body):
    """The returned expression of a body that is one expression or one `return`; else None."""
    if isinstance(body, dict):
        return body
    if isinstance(body, list) and len(body) == 1 and isinstance(body[0], dict) and body[0].get("k") == "return":
        return body[0].get("value")
    return None


def _mentions_env(e, scope: dict, ctx: _Ctx, depth: int = 0) -> bool:
    """True when e reads the environment, directly, through a flag local, or through a
    solution method / local function that does."""
    locs = _env_locals(scope)
    for n in walk(e):
        if _env_node(n) or (n.get("k") == "name" and n.get("id") in locs):
            return True
        if n.get("k") == "call" and depth < 4:
            body, sub = _callee_body(ctx, scope, n)
            if body is not None and _mentions_env(body, sub, ctx, depth + 1):
                return True
    return False


def _pred(e, scope: dict, ctx: _Ctx, depth: int = 0):
    """Predicate of an environment condition; None when it reads no environment at all.
    Operands of a mixed condition that are not environment checks count as unknown."""
    if not isinstance(e, dict) or not _mentions_env(e, scope, ctx, depth):
        return None
    locs = _env_locals(scope)
    k = e.get("k")
    if k == "name":
        return locs.get(e.get("id"), _UNKNOWN)
    if k == "unary" and e.get("op") == "!":
        return ("not", _pred(e.get("e"), scope, ctx, depth) or _UNKNOWN)
    if k == "call":
        nm = (call_name(e) or "").lower()
        if nm in _ENV_CALLS:
            return ("env", _ENV_CALLS[nm].lower())
        args = e.get("args") or []
        if nm == "isenvironment":
            n = _env_name(args[0]) if args else None
            return ("env", n) if n else _UNKNOWN
        if nm == "equals":
            # string.Equals(x.EnvironmentName, "X"[, cmp]) or x.EnvironmentName.Equals("X"[, cmp])
            fn = e.get("fn") or {}
            ops = list(args[:2])
            if fn.get("k") == "member" and _is_env_name_expr(fn.get("obj")):
                ops = [fn["obj"]] + list(args[:1])
            if len(ops) == 2:
                for a, b in ((ops[0], ops[1]), (ops[1], ops[0])):
                    n = _env_name(b)
                    if _is_env_name_expr(a) and n:
                        return ("env", n)
        # A solution method / local function: its single returned expression, else unknown.
        body, sub = _callee_body(ctx, scope, e) if depth < 4 else (None, {})
        expr = _single_return(body) if body is not None else None
        if expr is not None:
            return _pred(expr, sub, ctx, depth + 1) or _UNKNOWN
        return _UNKNOWN
    if k == "bin":
        op = e.get("op")
        if op in ("&&", "and", "andalso", "||", "or", "orelse"):
            kind = "and" if op in ("&&", "and", "andalso") else "or"
            return (kind, _pred(e.get("l"), scope, ctx, depth) or _UNKNOWN,
                    _pred(e.get("r"), scope, ctx, depth) or _UNKNOWN)
        if op in ("==", "!="):
            for a, b in ((e.get("l"), e.get("r")), (e.get("r"), e.get("l"))):
                n = _env_name(b)
                if _is_env_name_expr(a) and n:
                    p = ("env", n)
                    return p if op == "==" else ("not", p)
    return _UNKNOWN


def _show(p) -> str:
    """Human-readable form of a predicate for PipeCall.env."""
    k = p[0]
    if k == "env":
        return next((v for v in _ENV_CALLS.values() if v.lower() == p[1]), p[1])
    if k == "not":
        return "!" + _show(p[1]) if p[1][0] == "env" else f"!({_show(p[1])})"
    if k in ("and", "or"):
        return "(" + (" && " if k == "and" else " || ").join(_show(x) for x in p[1:]) + ")"
    return "?"


def _display_env(guards: tuple) -> str | None:
    """`Development`, `!Development`, or the guards joined with ` & ` (None = unconditional)."""
    if not guards:
        return None
    return " & ".join(_show(p if taken else ("not", p)) for p, taken in guards)


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
    # id() of the solution call nodes being followed right now (becomes PipeCall.via).
    via: list[int] = field(default_factory=list)


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
    # Links after an endpoint link (`MapGroup(..).RequireAuthorization().MapGet(..)`) stay endpoint calls.
    idx = calls.index(call)
    if idx and _call_kind(calls[idx - 1], root, calls, scope) == "endpoints":
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

_ENV_LOCAL = "$env:"  # scope key prefixes; `$` cannot start a C# identifier
_TAINT = "$flag:"
_LOCAL_FN = "$fn:"


def _env_locals(scope: dict) -> dict:
    """Names whose value depends on the environment: single-assignment env-bool locals map
    to their predicate; flag locals assigned under a guard (or re-assigned) map to unknown."""
    out: dict = {}
    for k, v in scope.items():
        if k.startswith(_ENV_LOCAL):
            out[k[len(_ENV_LOCAL):]] = v
        elif k.startswith(_TAINT):
            out[k[len(_TAINT):]] = _UNKNOWN
    return out


def _declare_local(ctx: _Ctx, scope: dict, name: str, init) -> None:
    """`var dev = env.IsDevelopment();` makes a later `if (dev)` an environment guard."""
    scope.pop(_TAINT + name, None)
    pred = _pred(init, scope, ctx) if isinstance(init, dict) else None
    if pred:
        scope[_ENV_LOCAL + name] = pred
    else:
        scope.pop(_ENV_LOCAL + name, None)
    if isinstance(init, dict) and init.get("k") == "lambda":
        scope[_LOCAL_FN + name] = init
    else:
        scope.pop(_LOCAL_FN + name, None)


def _assign_local(ctx: _Ctx, scope: dict, name: str, value, guards: tuple) -> None:
    """A later assignment: a flag set under an environment guard, from an environment
    expression, or re-assigned after being an env-bool local no longer has a single value
    to read, so conditions on it are unknown."""
    if (guards or (isinstance(value, dict) and _mentions_env(value, scope, ctx))
            or (_ENV_LOCAL + name) in scope):
        scope.pop(_ENV_LOCAL + name, None)
        scope[_TAINT + name] = True


def _exits(stmts) -> bool:
    """True when a statement list cannot fall through (ends in return / throw / break / continue)."""
    if not stmts:
        return False
    last = stmts[-1]
    if not isinstance(last, dict):
        return False
    k = last.get("k")
    if k in ("return", "throw"):
        return True
    if k == "other":
        return (last.get("text") or "").strip().rstrip(";").strip() in ("break", "continue")
    if k == "if":
        return _exits(last.get("then")) and _exits(last.get("else"))
    return False


def _stmts(ctx: _Ctx, stmts, scope: dict, guards: tuple, file: str, stack: tuple, depth: int) -> None:
    # Local functions may be used before their declaration.
    for s in stmts or []:
        if isinstance(s, dict) and s.get("k") == "local" and isinstance((s.get("init") or {}).get("k"), str)                 and s["init"]["k"] == "lambda" and s.get("name"):
            scope[_LOCAL_FN + s["name"]] = s["init"]
    for s in stmts or []:
        guards = _stmt(ctx, s, scope, guards, file, stack, depth)
        if guards is None:
            return  # the rest of the list is unreachable


def _stmt(ctx: _Ctx, s, scope: dict, guards: tuple, file: str, stack: tuple, depth: int) -> tuple | None:
    """Walk one statement; returns the guards in force for the statements after it, or
    None when nothing after it can run."""
    if not isinstance(s, dict):
        return guards
    k = s.get("k")
    if k == "expr":
        _expr(ctx, s.get("expr"), scope, guards, file, stack, depth)
    elif k == "assign":
        _expr(ctx, s, scope, guards, file, stack, depth)
    elif k == "local":
        init = s.get("init")
        kind = _expr(ctx, init, scope, guards, file, stack, depth)
        nm = s.get("name")
        if nm:
            _declare_local(ctx, scope, nm, init)
            if kind == "other":
                kind = None
            kind = kind or _type_kind(s.get("type_full")) or _type_kind(s.get("type"))
            if not kind and isinstance(init, dict) and call_name(init) in _FACTORIES:
                kind = "builder"
            if kind:
                scope[nm] = kind
            else:
                scope.pop(nm, None)
    elif k in ("return", "throw"):
        _expr(ctx, s.get("value"), scope, guards, file, stack, depth)
        return None
    elif k == "other":
        if _exits([s]):
            return None
    elif k == "if":
        pred = _pred(s.get("cond"), scope, ctx)
        # Nested conditions compose: every enclosing guard stays in force.
        t_g = guards + ((pred, True),) if pred else guards
        e_g = guards + ((pred, False),) if pred else guards
        _stmts(ctx, s.get("then"), scope, t_g, file, stack, depth)
        _stmts(ctx, s.get("else"), scope, e_g, file, stack, depth)
        # An early exit leaves the rest of the list under the other branch's guard.
        t_exit, e_exit = _exits(s.get("then")), _exits(s.get("else"))
        if t_exit and e_exit:
            return None
        if t_exit:
            return e_g
        if e_exit:
            return t_g
    elif k == "loop":
        _stmts(ctx, s.get("body"), scope, guards, file, stack, depth)
    elif k == "using":
        _stmts(ctx, s.get("resource"), scope, guards, file, stack, depth)
        _stmts(ctx, s.get("body"), scope, guards, file, stack, depth)
    elif k == "try":
        _stmts(ctx, s.get("body"), scope, guards, file, stack, depth)
        for c in s.get("catches") or []:
            _stmts(ctx, c.get("body"), scope, guards, file, stack, depth)
        _stmts(ctx, s.get("finally"), scope, guards, file, stack, depth)
    return guards


def _endpoints_lambda(ctx: _Ctx, call: dict, scope: dict, guards: tuple, file: str, stack: tuple, depth: int) -> None:
    """`app.UseEndpoints(e => { e.MapGet(..); })`: the lambda's parameter is an endpoint builder and
    its body runs under the call's own conditions, so the calls inside are part of the pipeline."""
    for a in call.get("args") or []:
        if not (isinstance(a, dict) and a.get("k") == "lambda"):
            continue
        params = a.get("params") or []
        inner = dict(scope)
        if params and isinstance(params[0], str):
            inner[params[0]] = "endpoints"
        body = a.get("body")
        if isinstance(body, list):
            _stmts(ctx, body, inner, guards, file, stack, depth)
        else:
            _expr(ctx, body, inner, guards, file, stack, depth)


def _expr(ctx: _Ctx, e, scope: dict, guards: tuple, file: str, stack: tuple, depth: int) -> str | None:
    """Record the calls of one expression statement or initializer; returns the builder
    kind of its value (for `var app = builder.Build()`)."""
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "assign":
        kind = _expr(ctx, e.get("value"), scope, guards, file, stack, depth)
        tgt = e.get("target")
        if isinstance(tgt, dict) and tgt.get("k") == "name":
            _assign_local(ctx, scope, tgt.get("id"), e.get("value"), guards)
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
        followed = target is not None and depth < _MAX_DEPTH
        ctx.calls.append(PipeCall(
            name=nm, kind=kind, node=call, chain=calls, file=file, line=call.get("line", 0), env=_display_env(guards),
            resolved=bool(call.get("sym")) or nm in _FRAMEWORK_CALLS or target is not None,
            order=ctx.order, guards=guards, via=tuple(ctx.via), target=target if followed else None))
        ctx.order += 1
        if followed:
            t, m = target
            ext = _is_ext(m) and _is_member_call(call)
            arg_kinds = [_expr_kind(a, scope) for a in call.get("args") or []]
            ctx.via.append(id(call))
            _stmts(ctx, m.body, _scope_for(m, recv_kind, arg_kinds, ext), guards, t.file, stack + (m,), depth + 1)
            ctx.via.pop()
        elif nm == "UseEndpoints":
            _endpoints_lambda(ctx, call, scope, guards, file, stack, depth)
        recv_kind = kind
    # A `Build()` result is the app, whatever the builder was called.
    if calls and call_name(calls[-1]) == "Build" and kind == "other":
        return "app"
    return kind


# -- entry points -----------------------------------------------------------

def _simple_type(t: str) -> str:
    return t.split("<")[0].strip().split(".")[-1]


def _startup_targets(types: list[TypeIR]) -> list[str]:
    """Simple type names from every `UseStartup<T>()` call in the project."""
    out: list[str] = []
    for t in types:
        for m in t.methods:
            for n in walk(m.body):
                if n.get("k") == "call" and call_name(n) == "UseStartup":
                    fn = n.get("fn") or {}
                    out += [_simple_type(a) for a in (fn.get("targs") or [])[:1]]
    return out


def _entry_methods(types: list[TypeIR], notes: list[str]) -> tuple[str, list[tuple[TypeIR, MethodIR]]]:
    wanted = _startup_targets(types)
    startup = [t for t in types if t.name.split(".")[-1] in wanted] if wanted else []
    tops = [(t, m) for t in types for m in t.methods if is_top_level(m)]
    if not startup:
        if tops:
            return "minimal", tops
        startup = [t for t in types if t.name == "Startup"]
        if not startup:
            # No usable `UseStartup<T>()`: take the types that look like startup classes.
            startup = [t for t in types if {"ConfigureServices", "Configure"} <= {m.name for m in t.methods}]
            names = sorted({t.name for t in startup})
            if len(names) > 1:
                notes.append("several startup-like classes (" + ", ".join(names) + ") and no UseStartup<T>() "
                             f"to choose between them; used {names[0]}")
                startup = [t for t in startup if t.name == names[0]]
    out = [(t, m) for want in ("ConfigureServices", "Configure") for t in startup
           for m in t.methods if m.name == want]
    if out:
        # Top-level statements plus a resolved UseStartup<T>: the merge, top-level calls first.
        return "startup", (tops + out if wanted and startup and tops else out)
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
    notes: list[str] = []
    style, entries = _entry_methods(types, notes)
    for t, m in entries:
        scope = {p.name: k for p in m.params if (k := _type_kind(p.type))}
        _stmts(ctx, m.body, scope, (), t.file, (m,), 1)
    return Pipeline(proj, style, ctx.calls, tfm, notes, list(entries))


def pipeline_for(model: ProjectModel, proj: Project | None) -> Pipeline:
    """Pipeline facts of one project (None = every file of the model); cached on the model."""
    cache = model.cache.setdefault("pipelines", {})
    key = id(proj) if proj is not None else None
    if key not in cache:
        cache[key] = _build(model, proj)
    return cache[key]
