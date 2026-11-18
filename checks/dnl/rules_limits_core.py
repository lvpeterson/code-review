"""Resource-limit rules of the ASP.NET Core configuration pass: request-body size limits (DNL-RES-001, the id
the web.config rules already use), login / token / password-reset endpoints with no rate limiting
(DNL-RES-004) and a page-size parameter that reaches `Take` with no upper bound (DNL-RES-005).

Like the other rules_pipeline* modules it must not import rules_auth_core (static inventory test); shared
helpers live in auth_core.py and the sibling rule modules.

Known limits. RES-005 reads one handler body: a parameter handed to another method (`repo.List(pageSize)`)
is not followed, and a bound written there is not seen (not reported either way); a comparison against a
literal of 0 or 1 is a lower-bound check, not a cap, and a comparison only caps when its branch returns,
throws or assigns the value (any other mention is REVIEW). RES-004 counts a route-level `RequireRateLimiting`
/ `[EnableRateLimiting]` only when a limiter middleware certainly runs in Production (the policy is
unenforced without it).
"""
from __future__ import annotations

import re

from checks.dnl.cfgctx import Ctx
from checks.dnl.ir import attr_key, call_name, receiver_text, walk
from checks.dnl.options import UNKNOWN, lambda_args, opaque_reason, options_of, verdict
from checks.dnl.pipeline import Pipeline
from checks.dnl.routes_core import CoreRouteRef, _chain_types
from checks.dnl.rules_pipeline_auth import _env_state, _scope_of

_MIB = 1024 * 1024
_LIMIT = 100 * _MIB                     # a request body above this is reported
_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}

_MAXES = {"int.maxvalue": 2**31 - 1, "int32.maxvalue": 2**31 - 1, "long.maxvalue": 2**63 - 1,
          "int64.maxvalue": 2**63 - 1, "uint.maxvalue": 2**32 - 1, "uint32.maxvalue": 2**32 - 1,
          "ulong.maxvalue": 2**64 - 1, "uint64.maxvalue": 2**64 - 1, "short.maxvalue": 2**15 - 1,
          "ushort.maxvalue": 2**16 - 1, "int16.maxvalue": 2**15 - 1, "uint16.maxvalue": 2**16 - 1}
_OPS = {"*": lambda a, b: a * b, "+": lambda a, b: a + b, "-": lambda a, b: a - b,
        "/": lambda a, b: a // b if b else UNKNOWN, "<<": lambda a, b: a << b if 0 <= b < 64 else UNKNOWN}


def _num(e):
    """A compile-time number, None for a literal null, else UNKNOWN: literals, `long.MaxValue` style
    members, casts, and `* + - / <<` over those (`2000L * 1024 * 1024`)."""
    if not isinstance(e, dict):
        return UNKNOWN
    k = e.get("k")
    if k == "lit":
        v = e.get("v")
        if v is None and e.get("t") == "null":
            return None
        return v if isinstance(v, (int, float)) and not isinstance(v, bool) else UNKNOWN
    if k == "member":
        text = receiver_text(e).lower()
        return _MAXES.get(text[len("system."):] if text.startswith("system.") else text, UNKNOWN)
    if k == "cast":
        return _num(e.get("e"))
    if k == "bin" and e.get("op") in _OPS:
        a, b = _num(e.get("l")), _num(e.get("r"))
        if a is UNKNOWN or b is UNKNOWN or a is None or b is None:
            return UNKNOWN
        return _OPS[e["op"]](a, b)
    return UNKNOWN


def _size_kind(e) -> str:
    """"bad" (no limit, or above 100 MiB), "good" or "unknown" for a size value."""
    v = _num(e)
    if v is UNKNOWN:
        return "unknown"
    return "bad" if v is None or v > _LIMIT else "good"


def _size_text(e) -> str:
    v = _num(e)
    if v is None:
        return "null (no limit)"
    return f"{v} bytes ({v / _MIB:.0f} MiB)" if v is not UNKNOWN else "a value that is not a compile-time constant"


def _env_review(c) -> str | None:
    """None when a pipeline call certainly runs in Production, "skip" when it never does, "REVIEW" under an
    environment condition that could not be parsed."""
    run = c.runs_in("Production")
    return "skip" if run is False else None if run else "REVIEW"


# -- RES-001: request size limits ----------------------------------------------------------------------

# Option types the body-size rule reads -> the option path that holds the limit.
_KESTREL_PATH, _SERVER_PATH, _FORM_PATH = "limits.maxrequestbodysize", "maxrequestbodysize", "multipartbodylengthlimit"
_TYPE_PATHS = {"kestrelserveroptions": _KESTREL_PATH, "iisserveroptions": _SERVER_PATH,
               "httpsysoptions": _SERVER_PATH, "formoptions": _FORM_PATH}
_CALL_PATHS = {"configurekestrel": _KESTREL_PATH, "usekestrel": _KESTREL_PATH, "usehttpsys": _SERVER_PATH}
_LABEL = {_KESTREL_PATH: "MaxRequestBodySize", _SERVER_PATH: "MaxRequestBodySize",
          _FORM_PATH: "MultipartBodyLengthLimit"}


def _limit_path(n: dict) -> str | None:
    """The option path a call's lambda sets the body limit through, None for any other call."""
    name = (call_name(n) or "").lower()
    if name in _CALL_PATHS:
        return _CALL_PATHS[name]
    if name in ("configure", "postconfigure"):
        for t in (n.get("fn") or {}).get("targs") or []:
            p = _TYPE_PATHS.get(str(t).split("<")[0].split(".")[-1].lower())
            if p:
                return p
    return None


def _options_param_names(n: dict) -> set | None:
    """The options parameter of each lambda argument (the last one: `(ctx, o) => ...`), None without lambdas."""
    names = {p for lam in lambda_args(n) for p in (lam.get("params") or [])[-1:] if isinstance(p, str)}
    return names or None


def _code_limits(ctx: Ctx, pipe: Pipeline, seen: set) -> None:
    for c in pipe.calls:
        state = _env_review(c)
        if state == "skip":
            continue
        for n in walk(c.node):
            if n.get("k") != "call" or id(n) in seen:
                continue
            path = _limit_path(n)
            if path is None:
                continue
            seen.add(id(n))
            line = n.get("line") or c.line
            why = opaque_reason(n, _options_param_names(n))
            if why:
                ctx.add("DNL-RES-001", "low", "Request size limit could not be read",
                        f"The options of {call_name(n)} at {c.file}:{line} could not be read ({why}), so "
                        f"{_LABEL[path]} may be removed or very large there. Confirm it is 100 MiB or less.",
                        c.file, line, confidence="REVIEW")
            eff, uncertain = verdict(options_of(n), path, bad=lambda o: _size_kind(o.value) == "bad")
            if eff is None:
                continue
            kind = _size_kind(eff.value)
            if kind == "good":
                continue
            firm = kind == "bad" and not uncertain and state is None
            if kind == "bad":
                desc = (f"{_LABEL[path]} is {_size_text(eff.value)} in {call_name(n)}, above the 100 MiB limit, so a "
                        "single request can exhaust memory, disk or bandwidth. Set a limit that fits the largest "
                        "legitimate upload and stream larger files.")
                if uncertain:
                    desc += " The assignment sits under a condition inside the options lambda, so it may not apply."
                if state:
                    desc += " The call sits under an environment condition that could not be parsed."
            else:
                desc = (f"{_LABEL[path]} in {call_name(n)} is not a compile-time value, so the limit may be removed "
                        "or above 100 MiB. Confirm it is 100 MiB or less.")
            ctx.add("DNL-RES-001", "low", "Request size limit removed or very large", desc,
                    c.file, eff.line or line, confidence=None if firm else "REVIEW")


def _settings_limit(ctx: Ctx, pipe: Pipeline, seen: set) -> None:
    """`Kestrel:Limits:MaxRequestBodySize` in the effective Production settings of the pipeline's project."""
    scope = _scope_of(ctx, pipe)
    if scope is None:
        return
    e = ctx.settings.effective("Production", scope).get("kestrel:limits:maxrequestbodysize")
    if e is None or (e.file, e.line) in seen:
        return
    seen.add((e.file, e.line))
    v = e.value
    if isinstance(v, str) and re.fullmatch(r"\d+", v.strip()):
        v = int(v.strip())
    if v is None or (isinstance(v, (int, float)) and not isinstance(v, bool) and v > _LIMIT):
        what = "null (no limit)" if v is None else f"{v} bytes ({v / _MIB:.0f} MiB)"
        ctx.add("DNL-RES-001", "low", "Request size limit removed or very large",
                f"{e.key} is {what} in the Production configuration, above the 100 MiB limit, so a single request "
                "can exhaust memory, disk or bandwidth. Set a limit that fits the largest legitimate upload.",
                e.file, e.line)
    elif not isinstance(v, (int, float)) or isinstance(v, bool):
        ctx.add("DNL-RES-001", "low", "Request size limit could not be read",
                f"{e.key} is {v!r} in the Production configuration, which could not be read as a number; confirm "
                "the limit is 100 MiB or less.", e.file, e.line, confidence="REVIEW")


def _attr_groups(ctx: Ctx, ref: CoreRouteRef) -> list[list]:
    """Attribute lists of a route, most specific first: the action, then the class and its base classes (an
    action-level attribute overrides the class-level one, so the first list that names a wanted attribute wins)."""
    groups = [list(ref.method.attributes)] if ref.method is not None else []
    if ref.type is not None and ref.style in ("controller", "razorpage"):
        groups += [list(t.attributes) for t in _chain_types(ctx.model, ref.type)]
    return groups


def _fluent_calls(ref: CoreRouteRef) -> list[list[dict]]:
    """Fluent convention call lists of a route, most specific first: the endpoint, its groups (innermost
    first), then the conventions on MapControllers() / MapRazorPages()."""
    out = [list(ref.endpoint_calls)]
    out += [list(g.calls) for g in reversed(ref.groups)]
    out.append(list(ref.convention_calls))
    return [[c for c in lst if isinstance(c, dict)] for lst in out]


_DIRECTIVE = re.compile(r"(?<![A-Za-z0-9_])(DisableRequestSizeLimit|RequestSizeLimit|RequestFormLimits)"
                        r"(?:Attribute)?\b\s*(?:\(((?:[^()]|\([^()]*\))*)\))?")
_FORM_ARG = re.compile(r"MultipartBodyLengthLimit\s*=\s*([^,]+)")


def _fold(text: str):
    """The value of a constant expression written as text in a page directive, with the same folding as code
    (`100 * 1024 * 1024`, `2000L * 1024 * 1024`, `long.MaxValue`): a number, None for `null`, else UNKNOWN."""
    t = text.strip()
    if t == "null":
        return None
    t = re.sub(r"(?i)\b(?:system\.)?(\w+\.maxvalue)\b", lambda m: str(_MAXES.get(m.group(1).lower(), "x")), t)
    t = re.sub(r"(?<=\d)[lLuU]+\b", "", t).replace("_", "")
    if not t or not re.fullmatch(r"[\d\s*+\-/()<]+", t) or "<<<" in t:
        return UNKNOWN
    try:
        v = eval(t.replace("/", "//"), {"__builtins__": {}}, {})  # noqa: S307 -- digits and operators only
    except Exception:  # noqa: BLE001
        return UNKNOWN
    return v if isinstance(v, (int, float)) and abs(v) < 2**70 else UNKNOWN


def _directive_issues(text: str) -> list[tuple[str, bool]]:
    """[(what, certain)] for one `@attribute [...]` directive: the size attributes it carries, each once
    (`[DisableRequestSizeLimit()]` and `[DisableRequestSizeLimit]` are the same attribute)."""
    out: list[tuple[str, bool]] = []
    for m in _DIRECTIVE.finditer(text):
        name, args = m.group(1), m.group(2)
        if name == "DisableRequestSizeLimit":
            out.append(("@attribute [DisableRequestSizeLimit]", True))
            continue
        if name == "RequestFormLimits":
            fm = _FORM_ARG.search(args or "")
            val = _fold(fm.group(1)) if fm else 0
            label = "@attribute [RequestFormLimits(MultipartBodyLengthLimit = ...)]"
        else:
            val = _fold(args) if args and args.strip() else 0
            label = "@attribute [RequestSizeLimit(...)]"
        if val is UNKNOWN:
            out.append((label + " with a value that is not a compile-time constant", False))
        elif val is None or val > _LIMIT:
            out.append((label.replace("...", "null" if val is None else str(val)), True))
    return out


def _size_issues(ctx: Ctx, ref: CoreRouteRef) -> list[tuple[str, int, bool]]:
    """[(what, line, certain)] a route does to the request size limit: a `[DisableRequestSizeLimit]`,
    `[RequestSizeLimit(n)]` or `[RequestFormLimits(MultipartBodyLengthLimit = n)]` over 100 MiB, from the
    action or class (an `@attribute` directive of a page too), or `WithMetadata(new ...Attribute())`."""
    out: list[tuple[str, int, bool]] = []
    r = ref.route

    def sized(name: str, args: list, named: dict, line: int) -> None:
        if name == "disablerequestsizelimit":
            out.append(("[DisableRequestSizeLimit]", line, True))
        elif name == "requestsizelimit":
            kind = _size_kind(args[0] if args else named.get("bytes"))
            if kind != "good":
                out.append((f"[RequestSizeLimit({_size_text(args[0] if args else named.get('bytes'))})]", line,
                            kind == "bad"))
        elif name == "requestformlimits":
            val = next((v for k, v in named.items() if k.lower() == "multipartbodylengthlimit"), None)
            if val is not None and _size_kind(val) != "good":
                out.append((f"[RequestFormLimits(MultipartBodyLengthLimit = {_size_text(val)})]", line,
                            _size_kind(val) == "bad"))

    for family in (("disablerequestsizelimit", "requestsizelimit"), ("requestformlimits",)):
        for attrs in _attr_groups(ctx, ref):
            hit = [a for a in attrs if attr_key(a.name) in family]
            if hit:
                for a in hit:
                    sized(attr_key(a.name), list(a.args), dict(a.named), a.line or r.line)
                break
    for raw in r.meta.get("page_attributes") or []:
        out += [(w, r.line, c) for w, c in _directive_issues(str(raw))]
    for lst in _fluent_calls(ref):
        for c in lst:
            if call_name(c) != "WithMetadata":
                continue
            for a in c.get("args") or []:
                for x in walk(a):
                    if x.get("k") == "new":
                        name = attr_key((x.get("type") or "").split(".")[-1])
                        sized(name, list(x.get("args") or []), {}, x.get("line") or c.get("line") or r.line)
    return out


def _route_limits(ctx: Ctx) -> None:
    seen: set = set()
    for ref in ctx.refs:
        r = ref.route
        env = _env_state(r.meta.get("env"))
        if env == "skip":
            continue
        for what, line, certain in _size_issues(ctx, ref):
            key = (r.file, r.line, r.handler_name, r.path, what)
            if key in seen:
                continue
            seen.add(key)
            conf = None if certain and env == "firm" else "REVIEW"
            desc = (f"{r.handler_name} ({', '.join(r.methods)} {r.path}) sets {what}, so one request to it can be "
                    "larger than 100 MiB and exhaust memory, disk or bandwidth. Keep the limit at or below what "
                    "the largest legitimate upload needs and stream larger files.")
            if not certain:
                desc += " The limit is not a compile-time value."
            if env == "review":
                desc += " The route is mapped under an environment condition that is not plain Production."
            ctx.add("DNL-RES-001", "low", f"Request size limit removed or very large on {r.handler_name}", desc,
                    r.file, line, route=r, confidence=conf)


# -- RES-004: rate limiting on login / token / reset endpoints -----------------------------------------

_AUTH_ENDPOINT = re.compile(r"(?i)login|signin|token|authenticate|forgot|reset|password")
_TOKEN = re.compile(r"(?i)token")
_THIRD_PARTY = ("UseIpRateLimiting", "UseClientRateLimiting", "AddInMemoryRateLimiting", "UseRateLimitingMiddleware")
_LIMITERS = ("UseRateLimiter",) + _THIRD_PARTY
_RL = {"enableratelimiting": "enabled", "requireratelimiting": "enabled",
       "disableratelimiting": "disabled"}


def _auth_endpoint(ref: CoreRouteRef) -> bool:
    """A login / token / password-reset route: the name or path says so, and it takes a mutating verb (a
    token endpoint is reported for any verb)."""
    r = ref.route
    if r.meta.get("kind") in ("health", "openapi", "fallback", "hub"):
        return False
    text = f"{r.path} {r.handler_name}"
    if not _AUTH_ENDPOINT.search(text):
        return False
    verbs = {v.upper() for v in r.methods}
    return bool(_TOKEN.search(text) or verbs & _MUTATING or "ANY" in verbs)


def _rate_state(ctx: Ctx, ref: CoreRouteRef) -> str | None:
    """"enabled" | "disabled" | None for a route's own rate-limiting metadata. Within attributes the action
    beats the class, within fluent calls the endpoint beats its group beats the convention (the last call
    on one builder wins); a disable in either family wins over an enable."""
    states: list[str] = []
    for attrs in _attr_groups(ctx, ref):
        hit = [_RL[attr_key(a.name)] for a in attrs if attr_key(a.name) in _RL]
        if hit:
            states.append("disabled" if "disabled" in hit else "enabled")
            break
    for raw in ref.route.meta.get("page_attributes") or []:
        text = str(raw)
        if "DisableRateLimiting" in text:
            states.append("disabled")
        elif "EnableRateLimiting" in text:
            states.append("enabled")
    for lst in _fluent_calls(ref):
        names = [_RL[(call_name(c) or "").lower()] for c in lst if (call_name(c) or "").lower() in _RL]
        if names:
            states.append(names[-1])
            break
    return "disabled" if "disabled" in states else "enabled" if "enabled" in states else None


def _owns(ctx: Ctx, pipe: Pipeline, ref: CoreRouteRef) -> bool:
    return ref.project is pipe.project or (ref.project is None and len(ctx.pipes) == 1)


def _rate_limiting(ctx: Ctx) -> None:
    for pipe in ctx.pipes:
        routes = [ref for ref in ctx.refs if _owns(ctx, pipe, ref) and _auth_endpoint(ref)
                  and _env_state(ref.route.meta.get("env")) != "skip"]
        identity = ctx.prod_calls(pipe, "MapIdentityApi") + ctx.uncertain_calls(pipe, "MapIdentityApi")
        if not routes and not identity:
            continue
        firm_global = bool(pipe.named(*_LIMITERS))
        maybe_global = bool(ctx.uncertain_calls(pipe, *_LIMITERS))
        open_routes: list[CoreRouteRef] = []
        unenforced: list[CoreRouteRef] = []
        for ref in routes:
            r = ref.route
            state = _rate_state(ctx, ref)
            env = _env_state(r.meta.get("env"))
            if state == "disabled":
                ctx.add("DNL-RES-004", "low", f"Rate limiting disabled on {r.handler_name}",
                        f"{r.handler_name} ({', '.join(r.methods)} {r.path}) is a login, token or password-reset "
                        "endpoint marked with DisableRateLimiting, so it is exempt from the app's rate limiter and "
                        "open to credential stuffing and brute force." +
                        (" The route is mapped under an environment condition that is not plain Production."
                         if env == "review" else ""),
                        r.file, r.line, route=r, confidence=None if env == "firm" else "REVIEW")
            elif state is None or not firm_global:
                # A route-level policy is metadata only: without a limiter middleware that certainly runs in
                # Production (UseRateLimiter or a third-party one) nothing enforces it, so the route is open.
                open_routes.append(ref)
                if state == "enabled":
                    unenforced.append(ref)
        if firm_global:
            continue
        conf, note = ctx.absent_confidence(pipe)
        if maybe_global:
            conf = "REVIEW"
            note = (note + "; " if note else "") + "a rate limiter sits under an environment condition that could not be parsed"
        if open_routes:
            first = open_routes[0]
            r = first.route
            names = ", ".join(f"{x.route.handler_name} ({', '.join(x.route.methods)} {x.route.path})"
                              for x in open_routes[:5])
            more = f" and {len(open_routes) - 5} more" if len(open_routes) > 5 else ""
            if _env_state(r.meta.get("env")) == "review":
                conf = "REVIEW"
            desc = (f"The Production pipeline has no rate limiting (no UseRateLimiter, no third-party limiter, no "
                    f"RequireRateLimiting / [EnableRateLimiting] on the route or its group) while it serves "
                    f"login, token or password-reset endpoints: {names}{more}. They are open to credential "
                    "stuffing, password guessing and reset-mail floods.")
            if unenforced:
                desc += (" A rate-limiting policy is named on "
                         + ", ".join(f"{x.route.handler_name} ({x.route.path})" for x in unenforced[:5])
                         + ", but UseRateLimiter is not in the Production pipeline, so the policy is unenforced.")
            elif pipe.named("AddRateLimiter") and not pipe.named("UseRateLimiter"):
                desc += " AddRateLimiter registers policies, but without UseRateLimiter nothing enforces them."
            if note:
                desc += f" Not certain: {note}."
            ctx.add("DNL-RES-004", "low", "No rate limiting on login, token or password-reset endpoints", desc,
                    r.file, r.line, route=r, confidence=conf)
        if identity:
            # MapIdentityApi registers /login, /refresh, /forgotPassword and /resetPassword endpoints that the
            # route discovery cannot list; whether a group limiter covers them is not traced: always REVIEW.
            c = identity[0]
            ctx.add("DNL-RES-004", "low", "No rate limiting on the Identity API endpoints",
                    "MapIdentityApi registers the /login, /refresh, /forgotPassword and /resetPassword endpoints, "
                    "and the Production pipeline has no rate limiting (no UseRateLimiter, no third-party limiter). "
                    "Confirm a limiter covers them." + (f" Not certain: {note}." if note else ""),
                    c.file, c.line, confidence="REVIEW")


# -- RES-005: page size reaches Take with no bound ----------------------------------------------------

_PAGE_PARAM = re.compile(r"(?i)^(page_?size|limit|take|count|per_?page|top|max_?results)$")
_INT_TYPES = {"int", "int32", "long", "int64", "short", "int16", "uint", "uint32", "ulong", "uint64",
              "ushort", "uint16"}
_CMP = {"<", ">", "<=", ">="}
_BOUND_CALLS = {"min", "clamp"}


def _integer(type_text: str | None) -> bool:
    t = (type_text or "").strip().replace(" ", "").lower()
    m = re.fullmatch(r"(?:system\.)?nullable<(.+)>", t)
    t = (m.group(1) if m else t).rstrip("?")
    return (t[len("system."):] if t.startswith("system.") else t) in _INT_TYPES


def _mentions(e, names: set) -> bool:
    return any(n.get("k") == "name" and n.get("id") in names for n in walk(e))


def _lower_check(other) -> bool:
    """A literal of 0 or 1 (or less): comparing against it checks for a positive size, not a cap."""
    return isinstance(other, dict) and other.get("k") == "lit" and isinstance(other.get("v"), (int, float)) \
        and not isinstance(other.get("v"), bool) and other["v"] <= 1


def _cmp_nodes(e, names: set) -> list[dict]:
    """Comparisons in an expression that read the parameter (or a carrier local) against anything but a 0 / 1
    literal (those check for a positive size, not a cap)."""
    out = []
    for n in walk(e):
        if n.get("k") == "bin" and n.get("op") in _CMP:
            left, right = n.get("l"), n.get("r")
            if (_mentions(left, names) and not _lower_check(right)) or (_mentions(right, names) and not _lower_check(left)):
                out.append(n)
    return out


def _bound_calls(e, names: set) -> list[dict]:
    """`Math.Min` / `Math.Clamp` / `Clamp` calls over the parameter (or a carrier local) inside an expression."""
    out = []
    for n in walk(e):
        if n.get("k") == "call" and (call_name(n) or "").lower() in _BOUND_CALLS:
            fn = n.get("fn")
            if (any(_mentions(a, names) for a in n.get("args") or [])
                    or (isinstance(fn, dict) and fn.get("k") == "member" and _mentions(fn.get("obj"), names))):
                out.append(n)
    return out


def _acts(stmts, names: set) -> bool:
    """A branch that leaves the handler (return / throw) or assigns the parameter or a carrier (a clamp)."""
    for n in walk(stmts):
        if n.get("k") in ("return", "throw"):
            return True
        if (n.get("k") == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "name"
                and n["target"].get("id") in names):
            return True
    return False


def _bound_state(body: list, names: set, takes: list[dict]) -> str | None:
    """"bound" when the handler certainly caps the value, "weak" when a comparison or Min / Clamp mentions it
    but nothing shows that it limits what reaches Take (REVIEW), None when nothing does. A cap is: a
    comparison in an `if` whose branch returns, throws or assigns the value; a ternary comparison or a
    Min / Clamp whose result is used (inside a Take argument, or assigned to what Take reads)."""
    reach = {n.get("id") for t in takes for a in t.get("args") or [] for n in walk(a) if n.get("k") == "name"}
    strong = False
    for n in walk(body):
        if n.get("k") == "if" and _cmp_nodes(n.get("cond"), names):
            if _acts(n.get("then"), names) or _acts(n.get("else"), names):
                strong = True
    contexts: list[tuple[object, bool]] = [(a, True) for t in takes for a in t.get("args") or []]
    for n in walk(body):
        if n.get("k") == "local" and n.get("name") in names:
            contexts.append((n.get("init"), n.get("name") in reach))
        elif (n.get("k") == "assign" and n.get("op") == "=" and isinstance(n.get("target"), dict)
              and n["target"].get("k") == "name" and n["target"].get("id") in names):
            contexts.append((n.get("value"), n["target"]["id"] in reach))
    for val, reaches in contexts:
        for n in walk(val):
            if n.get("k") == "cond" and reaches and _cmp_nodes(n, names):
                strong = True
        if reaches and _bound_calls(val, names):
            strong = True
    if strong:
        return "bound"
    return "weak" if _cmp_nodes(body, names) or _bound_calls(body, names) else None


def _page_findings(ref: CoreRouteRef) -> list[tuple[str, int, bool]]:
    """[(parameter, line of the Take call, weak)] for page-size parameters reaching Take with no certain
    bound; `weak` when some comparison or Min / Clamp mentions the value but does not visibly cap it."""
    m = ref.method
    if m is None:
        return []
    out = []
    for p in m.params:
        if not (_PAGE_PARAM.match(p.name) and _integer(p.type)):
            continue
        if any(attr_key(a.name) == "range" for a in p.attributes):
            continue
        names = {p.name}
        for n in walk(m.body):          # one local (or earlier-declared variable) carrying the parameter
            if n.get("k") == "local" and _mentions(n.get("init"), {p.name}):
                names.add(n.get("name") or "")
            elif (n.get("k") == "assign" and n.get("op") == "=" and isinstance(n.get("target"), dict)
                  and n["target"].get("k") == "name" and n["target"].get("id") != p.name
                  and _mentions(n.get("value"), {p.name})):
                names.add(n["target"]["id"])
        takes = [n for n in walk(m.body) if call_name(n) == "Take"
                 and any(_mentions(a, names) for a in n.get("args") or [])]
        if not takes:
            continue
        state = _bound_state(m.body, names, takes)
        if state != "bound":
            out.append((p.name, takes[0].get("line") or m.line, state == "weak"))
    return out


def _page_sizes(ctx: Ctx) -> None:
    seen: set = set()
    for ref in ctx.refs:
        r = ref.route
        env = _env_state(r.meta.get("env"))
        if env == "skip":
            continue
        for pname, line, weak in _page_findings(ref):
            key = (r.file, r.line, r.handler_name, r.path, pname)
            if key in seen:
                continue
            seen.add(key)
            desc = (f"{r.handler_name} ({', '.join(r.methods)} {r.path}) passes the client-supplied \"{pname}\" to "
                    f"Take at line {line} with no upper bound, so one request can ask for the whole table. Clamp it "
                    "(Math.Min / Math.Clamp), reject large values, or add [Range(1, N)].")
            if weak:
                desc += (" A comparison or Min / Clamp mentions it, but nothing shows that it limits the value "
                         "that reaches Take (the branch neither returns, throws nor assigns it); confirm it does.")
            if env == "review":
                desc += " The route is mapped under an environment condition that is not plain Production."
            ctx.add("DNL-RES-005", "low", f"Unbounded page size on {r.handler_name}", desc, r.file, r.line,
                    route=r, confidence=None if env == "firm" and not weak else "REVIEW")


def check(ctx: Ctx) -> None:
    seen: set = set()
    seen_cfg: set = set()
    for pipe in ctx.pipes:
        _code_limits(ctx, pipe, seen)
        if ctx.settings is not None:
            _settings_limit(ctx, pipe, seen_cfg)
    _route_limits(ctx)
    _rate_limiting(ctx)
    _page_sizes(ctx)
