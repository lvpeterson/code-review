"""Business-flow and API-consumption rules: DNL-DES-001 (sensitive flow without throttling),
DNL-CONSUME-001 (outbound call to a hard-coded http:// URL) and DNL-CONSUME-002 (an outbound
response used without validation).

DES-001 looks at every action whose name says it is a login, password reset / change, registration
or payment-style flow and accepts a POST-like verb. A protection counts only when it is certain to
apply to a normal request:

  * an attribute on the action, its controller or a base controller whose name says throttle / rate
    limit / CAPTCHA / lockout -- and, when the attribute type is in the project, one that does
    something (a filter-like type with a non-trivial body, not disabled with `Enabled = false`);
  * a call evaluated on every run of the action (`flowutil.uncond_nodes`: not under `if (debug)`,
    `if (false)` or any other conditional branch) to `Membership.ValidateUser`,
    `PasswordSignIn(Async)` with a literal `shouldLockout: true` (named or 4th argument),
    `CheckPasswordSignInAsync(.., lockoutOnFailure: true)`, `AccessFailed(Async)`, a CAPTCHA or
    throttle call -- directly or in a project method it calls unconditionally (two levels; every
    candidate implementation must protect);
  * a filter or message handler registered globally (`GlobalFilters.Filters.Add`, `config.Filters.Add`,
    `config.MessageHandlers.Add`, an OWIN `Use...Throttl...`) by a method that startup
    (`Application_Start`, OWIN `Configuration`) reaches unconditionally.

A throttle attribute on a different action, a lockout call in a conditional branch, `shouldLockout:
false` or a hand-rolled counter does not count; the finding is REVIEW and says so.

CONSUME-001 resolves the URL through locals, const / static fields and properties, `new Uri(..)`,
concatenation, interpolation and `String.Format`, and reports a literal that starts with `http://`
passed to an HttpClient / WebClient / RestClient / WebRequest call or base address. `localhost`,
`127.0.0.1` and `[::1]` are skipped as development endpoints. It also reads web.config
`<system.serviceModel><client><endpoint address="http://...">`.

CONSUME-002 reads the taint engine's `external` flows (outbound response bodies, deserialized) that
reach a SQL / LINQ / command / LDAP / XPath / path / redirect sink.
"""
from __future__ import annotations

import re

from checks.dnl import taint_solver
from checks.dnl.findings import dnl_finding
from urllib.parse import urlsplit

from checks.dnl import auth
from checks.dnl.flowutil import (Ctx, attrs_of, login_by_context, normal_branch, stmt_nodes, terminates, tokens,
                                 uncond_nodes, uncond_stmts, walk_u)
from checks.dnl.rules_logging import _failing_branch, is_cred_call
from checks.dnl.ir import Attr, TypeIR, call_name, literal_str, receiver_text, walk
from checks.dnl.typestate import iter_bodies, simple
from checks.dnl.webconfig import LINE, ORIGIN, effective
from core.models import Finding

# -- startup / global registration ----------------------------------------------------

_STARTUP_NAMES = {"application_start", "configuration", "configure", "prestart", "poststart", "start", "init"}


def _group_targets(ctx: Ctx, t: TypeIR, arg) -> list:
    """Project methods named by a method-group argument (`GlobalConfiguration.Configure(WebApiConfig.Register)`)."""
    if not isinstance(arg, dict) or arg.get("k") not in ("member", "name"):
        return []
    name = (arg.get("name") if arg["k"] == "member" else arg.get("id")) or ""
    if arg["k"] == "member":
        owners = ctx.model.find_types(receiver_text(arg.get("obj")).split(".")[-1]) if arg.get("obj") else []
    else:
        owners = [t]
    return [(d, m) for d in owners for m in d.methods if m.name.lower() == name.lower() and m.body]


def startup_nodes(ctx: Ctx) -> list[tuple[TypeIR, object, dict]]:
    """(type, method, node) for every expression run unconditionally by a method that startup reaches
    unconditionally (`Application_Start`, OWIN `Startup.Configuration`, `PreStart`), four levels deep."""
    cached = ctx.model.cache.get("dnl_startup_nodes")
    if cached is not None:
        return cached
    todo: list[tuple[TypeIR, object, int]] = []
    for t in ctx.model.types():
        short = t.name.split(".")[-1].lower()
        for m in t.methods:
            low = m.name.lower()
            if low == "application_start" or (low in _STARTUP_NAMES and (
                    "startup" in short or "global" in short or "application" in short or "activator" in short)):
                todo.append((t, m, 0))
    seen: set = set()
    out: list = []
    while todo:
        t, m, depth = todo.pop()
        if id(m) in seen or not m.body:
            continue
        seen.add(id(m))
        for n in uncond_nodes(m.body):
            out.append((t, m, n))
            if n.get("k") == "call" and depth < 4:
                for ty, tm in ctx.targets(t, m, n):
                    todo.append((ty, tm, depth + 1))
                for a in n.get("args") or []:
                    for ty, tm in _group_targets(ctx, t, a):
                        todo.append((ty, tm, depth + 1))
    ctx.model.cache["dnl_startup_nodes"] = out
    return out


_FLOW_ATTR = re.compile(r"(?i)throttl|rate_?limit|captcha|lockout|bruteforce|maxrequests|requestlimit")
# A base that makes the type run in the pipeline (a plain `Attribute` base does nothing by itself).
_FILTERISH = re.compile(r"(?i)filter|handler|middleware")


def _is_noop(m) -> bool:
    """A method body with no statement other than calls on `base`."""
    for s in m.body or []:
        e = s.get("expr") if s.get("k") == "expr" else None
        if isinstance(e, dict) and e.get("k") == "call" and receiver_text((e.get("fn") or {}).get("obj")).lower() in (
                "base", "mybase"):
            continue
        return False
    return True


def effective_type(model, name: str) -> bool:
    """A flow-protection type does something. An external (library) type is trusted; a project type must
    be filter-like and have a method whose body is more than calls on `base`."""
    simple_name = name.split("<")[0].split("(")[0].strip().split(".")[-1]
    cands = [t for n in (simple_name, simple_name + "Attribute") for t in model.find_types(n)]
    if not cands:
        return True
    for t in cands:
        chain = [t] + [bt for b in model.base_chain(t) for bt in model.find_types(b)]
        bases = [b for c in chain for b in c.bases]
        if not any(_FILTERISH.search(b) for b in bases):
            continue
        if any(m.body and m.name != ".ctor" and not _is_noop(m) for c in chain for m in c.methods):
            return True
    return False


def _attr_disabled(a: Attr) -> bool:
    for k, v in (a.named or {}).items():
        if str(k).lower() in ("enabled", "enable", "isenabled"):
            val = v.get("v") if isinstance(v, dict) else v
            if val is False:
                return True
    return False


def attr_protects(model, a: Attr) -> bool:
    return bool(_FLOW_ATTR.search(a.name)) and not _attr_disabled(a) and effective_type(model, a.name)


def startup_auth_filters(ctx: Ctx) -> list:
    """GlobalFilter tuples (kind, type, file, line) for auth attributes added to a filter collection by a
    method that startup reaches unconditionally. Unlike `auth.global_filters` (any `Filters.Add` in the
    solution) this ignores registrations under a condition or in methods nothing calls."""
    cached = ctx.model.cache.get("dnl_startup_auth")
    if cached is not None:
        return cached
    out = []
    for t, m, n in startup_nodes(ctx):
        if n.get("k") != "call" or (call_name(n) or "").lower() not in ("add", "insert"):
            continue
        fn = n.get("fn") or {}
        recv = receiver_text(fn.get("obj")).lower() if fn.get("k") == "member" else ""
        args = n.get("args") or []
        if not recv.endswith("filters") or not args or (args[-1] or {}).get("k") != "new":
            continue
        name = (args[-1].get("type") or "").split("<")[0].split(".")[-1]
        if auth.is_auth_attr(ctx.model, name):
            webapi = "config." in recv or "globalconfiguration" in recv or t.name.split(".")[-1].lower() == "webapiconfig"
            out.append(("webapi" if webapi else "mvc", name, t.file, n.get("line") or m.line))
    ctx.model.cache["dnl_startup_auth"] = out
    return out


def global_protection(ctx: Ctx) -> str | None:
    """Name of a throttle / CAPTCHA filter, handler or middleware registered globally at startup."""
    cached = ctx.model.cache.get("dnl_global_flow")
    if cached is not None:
        return cached or None
    found = ""
    for t, m, n in startup_nodes(ctx):
        if n.get("k") != "call":
            continue
        nm = (call_name(n) or "").lower()
        fn = n.get("fn") or {}
        recv = receiver_text(fn.get("obj")).lower() if fn.get("k") == "member" else ""
        names: list[str] = []
        if nm in ("add", "insert") and recv.endswith(("filters", "messagehandlers")):
            for a in n.get("args") or []:
                if isinstance(a, dict) and a.get("k") == "new":
                    names.append(a.get("type") or "")
                elif isinstance(a, dict) and a.get("k") == "name":
                    # `var f = new ThrottleFilter(); filters.Add(f);`
                    init = next((x.get("init") for x in walk(m.body) if x.get("k") == "local"
                                 and (x.get("name") or "").lower() == (a.get("id") or "").lower()), None)
                    names.append((init or {}).get("type") or a.get("id") or "")
        elif nm.startswith("use") and (_FLOW_ATTR.search(nm) or any(
                _FLOW_ATTR.search(x.get("type") or x.get("id") or x.get("name") or "")
                for a in n.get("args") or [] for x in walk(a) if x.get("k") in ("new", "name", "member"))):
            names.append(call_name(n) or "")
        for nme in names:
            if _FLOW_ATTR.search(nme) and effective_type(ctx.model, nme):
                found = nme
                break
        if found:
            break
    ctx.model.cache["dnl_global_flow"] = found
    return found or None


# -- DES-001 --------------------------------------------------------------------------

_SINGLE = {"login", "logon", "authenticate", "register", "signup", "checkout", "payment", "pay", "transfer",
           "purchase", "withdraw", "otp", "signin", "forgot", "charge", "twofactor", "resetpassword"}
_BIGRAM = {("log", "in"), ("log", "on"), ("sign", "in"), ("sign", "up"), ("create", "account"),
           ("verify", "code"), ("verify", "otp"), ("send", "code"), ("two", "factor"), ("pay", "now")}
_PW_VERB = {"reset", "forgot", "recover", "change", "set", "update"}
_EXCLUDE = {"logout", "logoff", "signout", "status", "view", "model", "page"}
_READ_ONLY = {"GET", "HEAD", "OPTIONS"}


def sensitive_kind(name: str) -> str | None:
    tk = tokens(name)
    if not tk or set(tk) & _EXCLUDE or name.startswith(("get_", "set_")) or name in (".ctor", ".cctor"):
        return None
    for tok in tk:
        if tok in _SINGLE:
            return tok
    for a, b in zip(tk, tk[1:]):
        if (a, b) in _BIGRAM:
            return a + b
    if "password" in tk and set(tk) & _PW_VERB:
        return "password reset or change"
    return None


def _lit_true(e) -> bool:
    return isinstance(e, dict) and e.get("k") == "lit" and e.get("v") is True


def _call_protects(n: dict) -> str | None:
    """What a call node does that counts as a flow protection, else None."""
    if n.get("k") != "call":
        return None
    nm = (call_name(n) or "").lower()
    fn = n.get("fn") or {}
    recv = receiver_text(fn.get("obj")).lower() if fn.get("k") == "member" else ""
    args, named = n.get("args") or [], {str(k).lower(): v for k, v in (n.get("named") or {}).items()}
    if nm in ("passwordsignin", "passwordsigninasync"):
        arg = named["shouldlockout"] if "shouldlockout" in named else args[3] if len(args) >= 4 else None
        return "PasswordSignIn with shouldLockout: true" if _lit_true(arg) else None
    if nm == "checkpasswordsigninasync":
        arg = named["lockoutonfailure"] if "lockoutonfailure" in named else args[2] if len(args) >= 3 else None
        return "CheckPasswordSignInAsync with lockoutOnFailure: true" if _lit_true(arg) else None
    if nm in ("accessfailed", "accessfailedasync"):
        return "AccessFailed lockout counter"
    sym = n.get("sym") or fn.get("sym") or ""
    if nm == "validateuser" and ("membership" in recv or sym.startswith("System.Web.Security.Membership")):
        return "Membership.ValidateUser (provider lockout)"
    return None


def _soft_call(n: dict) -> str | None:
    """A call that looks like a CAPTCHA check or a throttle by name. By itself it proves nothing
    (`ThrottleLog.Record(ip)` only records): it counts when its result gates the flow (`_gating_ids`)."""
    if n.get("k") != "call":
        return None
    nm = (call_name(n) or "").lower()
    fn = n.get("fn") or {}
    recv = receiver_text(fn.get("obj")).lower() if fn.get("k") == "member" else ""
    if "captcha" in nm or "captcha" in recv:
        return "CAPTCHA validation"
    if re.search(r"(?i)throttl|ratelimit|rate_limit", nm + " " + recv):
        return "rate-limit call"
    return None


_ATTEMPT_TOKENS = {"create", "charge", "pay", "payment", "transfer", "register", "reset", "change", "update", "save",
                   "send", "withdraw", "purchase", "submit", "checkout", "signin", "login", "logon", "authenticate"}


def _attempt_call(n: dict) -> bool:
    """The credential attempt / sensitive operation a gate has to come before."""
    if n.get("k") != "call":
        return False
    return is_cred_call(n) or _call_protects(n) is not None or bool(set(tokens(call_name(n) or "")) & _ATTEMPT_TOKENS)


def _validity_gate_between(stmts, lo: int, hi: int) -> bool:
    """`if (!ModelState.IsValid) return ...;` among stmts[lo:hi]."""
    for s in stmts[lo:hi]:
        if s.get("k") == "if" and normal_branch(s.get("cond")) == "else" \
                and "modelstate" in str(s.get("cond")).lower() and terminates(s.get("then")):
            return True
    return False


def _gating_ids(body) -> dict:
    """ids of the CAPTCHA / throttle-named calls that really gate the flow. A call gates only when
      * it is in the condition of an unconditionally reached `if` (directly, or through a local it was
        assigned to) whose branch taken when the check FAILS (negated check, `== false`, `!ok`, else-branch
        of a positive check) ends the flow -- return / throw / Response.End / an ending redirect -- or adds a
        model error that an `if (!ModelState.IsValid) return` gate then acts on; and
      * that `if` comes BEFORE the credential attempt or sensitive operation in statement order."""
    stmts = uncond_stmts(body)
    attempt = next((i for i, s in enumerate(stmts) if any(_attempt_call(n) for n in stmt_nodes(s))), len(stmts))
    held: dict = {}
    for s in stmts:
        if s.get("k") in ("local", "assign"):
            if s["k"] == "local":
                tgt, val = (s.get("name") or "").lower(), s.get("init")
            else:
                t_ = s.get("target") or {}
                tgt, val = ((t_.get("id") or "").lower() if t_.get("k") == "name" else ""), s.get("value")
            calls = {id(x): _soft_call(x) for x in walk_u(val) if _soft_call(x)}
            if tgt and calls:
                held.setdefault(tgt, {}).update(calls)
    ids: dict = {}
    for i, s in enumerate(stmts):
        if s.get("k") != "if" or i >= attempt:
            continue
        fb = _failing_branch(s.get("cond"), set(held), lambda n: _soft_call(n) is not None)
        if fb is None:
            continue
        branch = s.get("then") if fb == "then" else s.get("else")
        adds_error = any(n.get("k") == "call" and (call_name(n) or "").lower() == "addmodelerror"
                         for n in walk(branch) if isinstance(n, dict))
        if not (terminates(branch) or (adds_error and _validity_gate_between(stmts, i + 1, attempt))):
            continue
        # The whole condition: in `!ModelState.IsValid || !Captcha.Validate(r)` the check sits on the
        # short-circuit side, yet every request that gets past this `if` has passed it.
        for x in walk(s.get("cond")):
            if not isinstance(x, dict):
                continue
            if _soft_call(x):
                ids[id(x)] = _soft_call(x)
            elif x.get("k") == "name" and (x.get("id") or "").lower() in held:
                ids.update(held[(x.get("id") or "").lower()])
    return ids


def body_protection(ctx: Ctx, t: TypeIR, m, depth: int = 2) -> str | None:
    """A protection run on every normal call of method `m`, directly or through project calls."""
    gating = _gating_ids(m.body)
    if gating:                                   # every gate is unconditional and precedes the attempt
        return next(iter(gating.values()))
    for n in uncond_nodes(m.body):
        got = _call_protects(n)
        if got:
            return got
    if depth == 0:
        return None
    for n in uncond_nodes(m.body):
        if n.get("k") != "call":
            continue
        tg = ctx.targets(t, m, n)
        if not tg:
            continue
        outs = [body_protection(ctx, ty, tm, depth - 1) for ty, tm in tg if tm is not m]
        if outs and all(outs):
            return outs[0]
    return None


def check_des001(ctx: Ctx) -> list[Finding]:
    glob = global_protection(ctx)
    out: list[Finding] = []
    seen: set = set()
    for ref in ctx.refs:
        r, t = ref.route, ref.type
        kind = r.meta.get("kind")
        if t is None or kind == "wcf":
            continue
        methods = [ref.method] if ref.method is not None else [m for m in t.methods if m.body]
        for m in methods:
            flow = sensitive_kind(m.name) or ("login" if login_by_context(t, m) else None)
            if flow is None or not m.body:
                continue
            verbs = {v.upper() for v in (r.methods or [])}
            if ref.method is not None and verbs and verbs <= _READ_ONLY:
                continue
            key = (t.file, m.line)
            if key in seen:
                continue
            seen.add(key)
            if glob or any(attr_protects(ctx.model, a) for a in attrs_of(ctx.model, t, m)) \
                    or body_protection(ctx, t, m):
                continue
            out.append(dnl_finding(
                "DNL-DES-001", "low", f"Sensitive flow without throttling: {t.name.split('.')[-1]}.{m.name}",
                f"{m.name} ({flow}) has no lockout, CAPTCHA or rate limit that is certain to apply: none on the "
                f"action, its controller or a base controller, none registered globally at startup, and no "
                f"lockout call (Membership.ValidateUser, PasswordSignIn with shouldLockout: true, "
                f"AccessFailed) that every request reaches. Unlimited attempts allow credential stuffing, "
                f"enumeration or abuse; hand-rolled counters are not recognised, so verify "
                f"({t.file}:{m.line}) (in {t.name}.{m.name}).",
                t.file, m.line, route=r, api_surface=bool(r.meta.get("api_surface")), confidence="REVIEW"))
    # OWIN token endpoint: not a routed action, no filter runs for it, only a lockout in the body counts.
    for t in ctx.model.types():
        for m in t.methods:
            if m.name.lower() != "grantresourceownercredentials" or not m.body or (t.file, m.line) in seen:
                continue
            seen.add((t.file, m.line))
            if body_protection(ctx, t, m):
                continue
            out.append(ctx.finding(
                t, m.name, "DNL-DES-001", "low", f"Sensitive flow without throttling: {t.name.split('.')[-1]}.{m.name}",
                "The OAuth token endpoint (GrantResourceOwnerCredentials) has no lockout call (AccessFailed, "
                "PasswordSignIn with shouldLockout: true, Membership.ValidateUser) that every request reaches; "
                "Web API filters and rate limits do not run for it, so unlimited password guesses are possible",
                m.line, confidence="REVIEW"))
    return out


# -- CONSUME-001 ----------------------------------------------------------------------

_HTTP = re.compile(r"(?i)^\s*http://")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


class _Local:
    """Loopback test on the parsed host (`http://localhost:80@evil.com` has host evil.com)."""

    @staticmethod
    def match(url: str) -> bool:
        try:
            host = urlsplit(url.strip()).hostname
        except ValueError:
            return False
        return (host or "").lower() in _LOCAL_HOSTS


_LOCAL = _Local()
_CLIENT_CALLS = {"getasync", "getstringasync", "getbytearrayasync", "getstreamasync", "postasync", "putasync",
                 "deleteasync", "patchasync", "downloadstring", "downloaddata", "downloadfile",
                 "downloadstringasync", "downloadstringtaskasync", "downloaddatataskasync", "uploadstring",
                 "uploaddata", "uploadfile", "uploadvalues", "openread", "openwrite", "postasjsonasync",
                 "putasjsonasync", "postasxmlasync", "putasxmlasync", "sendasync"}
_REQ_FACTORY = {"create", "createhttp"}
_REQ_TYPES = {"webrequest", "httpwebrequest", "ftpwebrequest"}
_NEW_URL = {"restclient": 0, "httprequestmessage": 1, "webclient": None, "httpclient": None, "restrequest": 0}
_BASE_MEMBERS = {"baseaddress", "baseurl", "requesturi"}
_FORMATS = {"format", "concat"}


def _field_sources(model, t: TypeIR, name: str, obj_text: str = "") -> list:
    """Initializer / getter expressions of the field or property `name` (in `t`, or in the type
    `obj_text` names)."""
    owners = [t] if not obj_text else model.find_types(obj_text.split(".")[-1])
    out = []
    for d in owners:
        for f in d.fields:
            if f.name.lower() == name.lower() and f.init is not None:
                out.append(f.init)
        for p in d.properties:
            if p.name.lower() == name.lower():
                if p.init is not None:
                    out.append(p.init)
                out.extend(s.get("value") for s in (p.get or []) if isinstance(s, dict) and s.get("k") == "return")
    return out


def url_prefixes(ctx: Ctx, t: TypeIR, m, e, depth: int = 4) -> list[str]:
    """Literal prefixes the URL expression may start with (empty when it is built from unknowns)."""
    if depth == 0 or not isinstance(e, dict):
        return []
    s = literal_str(e)
    if s is not None:
        return [s]
    k = e.get("k")
    if k == "bin" and e.get("op") in ("+", "&", "concat"):
        return url_prefixes(ctx, t, m, e.get("l"), depth - 1)
    if k == "interp":
        parts = e.get("parts") or []
        return url_prefixes(ctx, t, m, parts[0], depth - 1) if parts else []
    if k == "cond":
        return url_prefixes(ctx, t, m, e.get("t"), depth - 1) + url_prefixes(ctx, t, m, e.get("f"), depth - 1)
    if k == "cast":
        return url_prefixes(ctx, t, m, e.get("e"), depth - 1)
    if k == "new" and simple(e.get("type")) in ("uri", "uribuilder") and e.get("args"):
        return url_prefixes(ctx, t, m, e["args"][0], depth - 1)
    if k == "new" and simple(e.get("type")) == "httprequestmessage" and len(e.get("args") or []) > 1:
        return url_prefixes(ctx, t, m, e["args"][1], depth - 1)
    if k == "call":
        nm = (call_name(e) or "").lower()
        if nm in _FORMATS and e.get("args"):
            return url_prefixes(ctx, t, m, e["args"][0], depth - 1)
        return []
    if k == "name":
        nm = (e.get("id") or "").lower()
        vals = []
        for n in walk(m.body) if m is not None else []:
            if n.get("k") == "local" and (n.get("name") or "").lower() == nm and n.get("init") is not None:
                vals.append(n["init"])
            elif n.get("k") == "assign" and (n.get("target") or {}).get("k") == "name" \
                    and (n["target"].get("id") or "").lower() == nm and n.get("op") in ("=", None):
                vals.append(n.get("value"))
        if not vals:
            vals = _field_sources(ctx.model, t, e.get("id") or "")
        return [p for v in vals for p in url_prefixes(ctx, t, m, v, depth - 1)]
    if k == "member":
        obj = e.get("obj")
        text = receiver_text(obj)
        if obj is None or text.lower() in ("this", "me"):
            vals = _field_sources(ctx.model, t, e.get("name") or "")
        else:
            vals = _field_sources(ctx.model, t, e.get("name") or "", text)
        return [p for v in vals for p in url_prefixes(ctx, t, m, v, depth - 1)]
    return []


def _insecure(prefixes: list[str]) -> str | None:
    return next((p for p in prefixes if _HTTP.match(p) and not _LOCAL.match(p)), None)


def _init_items(n: dict):
    """(member name, value expr) pairs of a `new T { A = x }` initializer."""
    for it in n.get("init") or []:
        if isinstance(it, dict):
            tgt = it.get("target") or {}
            nm = tgt.get("name") or tgt.get("id") or it.get("name")
            val = it.get("value") if "value" in it else it.get("init")
            if nm:
                yield str(nm).lower(), val


def check_consume001_code(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()

    def report(t, label, line, how, url):
        key = (t.file, line)
        if key in seen:
            return
        seen.add(key)
        out.append(ctx.finding(
            t, label, "DNL-CONSUME-001", "low", "Outbound call to a hard-coded http:// URL",
            f"{how} uses the plain-HTTP URL '{url}', so the request and the response cross the network "
            "unencrypted and can be read or altered in transit; use https:// (localhost and loopback "
            "addresses are skipped)", line, confidence="REVIEW"))

    for t in ctx.model.types():
        if t.kind == "enum":
            continue
        for label, m, body, _scope in iter_bodies(t):
            for n in walk(body):
                k = n.get("k")
                line = n.get("line") or 0
                if k == "call":
                    nm = (call_name(n) or "").lower()
                    fn = n.get("fn") or {}
                    recv = fn.get("obj") if fn.get("k") == "member" else None
                    rtail = receiver_text(recv).split(".")[-1].lower() if recv is not None else ""
                    if nm in _CLIENT_CALLS or (nm in _REQ_FACTORY and rtail in _REQ_TYPES):
                        args = n.get("args") or []
                        if args:
                            url = _insecure(url_prefixes(ctx, t, m, args[0]))
                            if url:
                                report(t, label, line, f"{call_name(n)}(..)", url)
                elif k == "new":
                    ty = simple(n.get("type_full") or n.get("type"))
                    if ty in _NEW_URL:
                        idx = _NEW_URL[ty]
                        args = n.get("args") or []
                        if idx is not None and len(args) > idx:
                            url = _insecure(url_prefixes(ctx, t, m, args[idx]))
                            if url:
                                report(t, label, line, f"new {n.get('type')}(..)", url)
                        for nme, val in _init_items(n):
                            if nme in _BASE_MEMBERS:
                                url = _insecure(url_prefixes(ctx, t, m, val))
                                if url:
                                    report(t, label, line, f"{n.get('type')}.{nme}", url)
                elif k == "assign":
                    tgt = n.get("target") or {}
                    nme = (tgt.get("name") or "").lower() if tgt.get("k") == "member" else ""
                    if nme in _BASE_MEMBERS:
                        url = _insecure(url_prefixes(ctx, t, m, n.get("value")))
                        if url:
                            report(t, label, line, receiver_text(tgt) or nme, url)
    return out


def check_consume001_config(configs) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    for cfg in configs or []:
        if cfg.root is None:
            continue
        for _label, root in effective(cfg):
            eps = [ep for sm in root.iter("system.serviceModel") for cl in sm.iter("client")
                   for ep in cl.findall("endpoint")]
            for ep in eps:
                addr = ep.get("address") or ""
                if _HTTP.match(addr) and not _LOCAL.match(addr):
                    file, line = ep.get(ORIGIN) or cfg.rel, int(ep.get(LINE) or 0)
                    if (file, line) in seen:
                        continue
                    seen.add((file, line))
                    out.append(dnl_finding(
                        "DNL-CONSUME-001", "low", "Service client endpoint uses http://",
                        f"The client endpoint '{ep.get('name') or ep.get('contract') or ''}' calls "
                        f"'{addr}' over plain HTTP, so requests and responses cross the network unencrypted "
                        f"and can be read or altered in transit ({file}:{line}).",
                        file, line, confidence="REVIEW"))
    return out


# -- CONSUME-002 ----------------------------------------------------------------------

_SINK_KINDS = {"sql": "a SQL statement", "linq": "a dynamic LINQ expression", "cmd": "an OS command",
               "ldap": "an LDAP query", "xpath": "an XPath query", "path": "a file path",
               "redirect": "a redirect target"}


def check_consume002(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    for h in taint_solver.external_hits(ctx.model):
        if h.kind not in _SINK_KINDS:
            continue
        src = next((o for o in sorted(h.taint.origins, key=lambda o: (o.file, o.line, o.detail))
                    if o.kind == "external"), None)
        r = ctx.routes.route(h.file, h.line)
        where = f"{src.detail} ({src.file}:{src.line})" if src else "an outbound response"
        out.append(dnl_finding(
            "DNL-CONSUME-002", "low", "Outbound API response used without validation",
            f"Data from {where} reaches {_SINK_KINDS[h.kind]} ({h.sink}, {h.file}:{h.line}) in {h.method} with no "
            "validation, so a compromised or malicious upstream service can inject into this application; "
            "validate and encode what an external API returns as carefully as request input.",
            h.file, h.line, route=r, api_surface=bool(r.meta.get("api_surface")) if r else False,
            confidence="REVIEW"))
    return out


def check(model, refs=(), configs=()) -> list[Finding]:
    ctx = Ctx(model, refs)
    out: list[Finding] = []
    if model.files:
        out += check_des001(ctx) + check_consume001_code(ctx) + check_consume002(ctx)
    return out + check_consume001_config(configs)
