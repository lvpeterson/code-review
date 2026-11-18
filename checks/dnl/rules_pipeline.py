"""Aggregator of the ASP.NET Core configuration rules: builds the shared context once, then runs each
rule group in a fixed order. A group that crashes adds a model note (its findings are missing) and
never hides the others. Later tasks add their group to _GROUPS.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl import rules_limits_core, rules_pipeline_auth, rules_secrets_core
from checks.dnl.auth_core import _NON_AUTHZ_EXTENSIONS, _sensitive
from checks.dnl.cfgctx import Ctx, build_ctx
from checks.dnl.ir import attr_key, call_chain, call_name, const_str, literal_str, receiver_text, walk
from checks.dnl.options import always_true, const, opt, options_of, param_escapes, verdict, walk_conditional
from checks.dnl.pipeline import PipeCall, Pipeline
from checks.dnl.project import ProjectModel
from checks.dnl.routes_core import CoreRouteRef, _chain_types
from core.models import Finding


def _scope_of(ctx: Ctx, pipe: Pipeline) -> str | None:
    """The settings scope of a pipeline's project: its directory relative to the model root ("" = the
    root), or None when no appsettings file sits there (effective() must never get an unknown scope)."""
    if pipe.project is None or ctx.settings is None:
        return None
    rel = ctx.model.rel(pipe.project.dir)
    scope = "" if rel in (".", "") else rel
    return scope if scope in ctx.settings.scopes() else None


def _certain_and_uncertain(ctx: Ctx, pipe: Pipeline, *names: str) -> list[tuple[PipeCall, str | None]]:
    """[(call, confidence)] for calls of those names: firm (None) when they certainly run in Production,
    REVIEW when they sit under an environment condition that could not be parsed."""
    return ([(c, None) for c in ctx.prod_calls(pipe, *names)]
            + [(c, "REVIEW") for c in ctx.uncertain_calls(pipe, *names)])


# -- errors and exception pages (DNL-CFG-008, DNL-CFG-009, DNL-ERR-002) --------------------------------

# Calls whose options carry `DetailedErrors` (Blazor circuits send exception detail to the browser).
_DETAILED_ERROR_CALLS = ("AddRazorComponents", "AddServerSideBlazor", "AddCircuitOptions",
                         "AddInteractiveServerComponents")
# Calls that provide an error page or response for unhandled exceptions and empty error statuses.
_HANDLER_CALLS = ("UseExceptionHandler", "UseProblemDetails")
_LEAK_MEMBERS = ("Message", "StackTrace")
_EXC_MEMBERS = ("Error", "Exception")      # IExceptionHandlerFeature.Error, ProblemDetailsContext.Exception
_RESPONSE_SINKS = ("WriteAsync", "WriteAsJsonAsync")
_FIELD_SINKS = ("Detail", "Title")


def _is_handler(name: str) -> bool:
    return name in _HANDLER_CALLS or name.startswith("UseStatusCodePages")


def _is_exc(e, tainted: set) -> bool:
    """True for the exception object itself: `x.Error`, `x.Exception`, its InnerException, or a local that
    holds it (or text built from it)."""
    if not isinstance(e, dict):
        return False
    if e.get("k") == "name":
        return e.get("id") in tainted
    if e.get("k") == "member":
        name = e.get("name")
        return name in _EXC_MEMBERS or (name == "InnerException" and _is_exc(e.get("obj"), tainted))
    return False


def _leaks(e, tainted: set, bare: bool = True) -> bool:
    """True when the expression carries exception detail: `.Error.Message`, `.StackTrace`, `.ToString()`, or
    (when `bare`) the exception or a tainted local itself. A call or member on the exception that is none of
    those (`ex.GetType().Name`) leaks nothing, and a comparison (`f.Error != null`) does not read it out."""
    if isinstance(e, list):
        return any(_leaks(x, tainted, bare) for x in e)
    if not isinstance(e, dict):
        return False
    k = e.get("k")
    if k == "name":
        return bare and e.get("id") in tainted
    if k == "member":
        if e.get("name") in _LEAK_MEMBERS and _is_exc(e.get("obj"), tainted):
            return True
        if _is_exc(e, tainted):
            return bare
        return _leaks(e.get("obj"), tainted, False)
    if k == "call":
        fn = e.get("fn") if isinstance(e.get("fn"), dict) else {}
        if fn.get("k") == "member":
            if fn.get("name") == "ToString" and _is_exc(fn.get("obj"), tainted):
                return True
            if _leaks(fn.get("obj"), tainted, False):
                return True
        parts = list(e.get("args") or []) + list((e.get("named") or {}).values())
        return any(_leaks(a, tainted, True) for a in parts)
    if k == "bin" and e.get("op") in ("==", "!=", "is", "isnot", "<>", "="):
        return _leaks(e.get("l"), tainted, False) or _leaks(e.get("r"), tainted, False)
    if k == "cond":
        return _leaks([e.get("t"), e.get("f")], tainted, True)
    if k == "lambda":
        return False
    return any(_leaks(v, tainted, True) for v in e.values() if isinstance(v, (dict, list)))


def _tainted_locals(body) -> set:
    """Locals of a handler body that hold exception detail, to a fixed point (`var ex = f.Error;
    var t = $"..{ex.Message}"`). Same body only; nothing crosses a method call."""
    pairs = []
    for n in walk(body):
        if n.get("k") == "local" and n.get("name") and n.get("init") is not None:
            pairs.append((n["name"], n["init"]))
        elif n.get("k") == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "name":
            pairs.append((n["target"].get("id"), n.get("value")))
    tainted: set = set()
    changed = True
    while changed:
        changed = False
        for name, init in pairs:
            if name and name not in tainted and _leaks(init, tainted):
                tainted.add(name)
                changed = True
    return tainted


def _is_sink_call(n: dict) -> bool:
    fn = n.get("fn") if isinstance(n.get("fn"), dict) else {}
    recv = receiver_text(fn.get("obj")) if fn.get("k") == "member" else ""
    name = call_name(n)
    if name in _RESPONSE_SINKS or recv.split(".")[0] in ("Results", "TypedResults"):
        return True
    return name == "Add" and recv.endswith("Extensions")


def _leak_sinks(args) -> list[int]:
    """Lines inside the handler lambdas where exception detail reaches the response: a WriteAsync /
    WriteAsJsonAsync / Results.* call, an `Extensions[..]` store, or a `Detail` / `Title` assignment or
    initializer entry."""
    tainted = _tainted_locals(args)
    lines: list[int] = []
    for n in walk(args):
        k = n.get("k")
        hit = False
        if k == "call" and _is_sink_call(n):
            hit = _leaks(list(n.get("args") or []) + list((n.get("named") or {}).values()), tainted)
        elif k == "assign" and n.get("op") == "=" and isinstance(n.get("target"), dict):
            t = n["target"]
            sink = ((t.get("k") == "index" and isinstance(t.get("obj"), dict) and t["obj"].get("name") == "Extensions")
                    or (t.get("k") == "member" and t.get("name") in _FIELD_SINKS))
            hit = sink and _leaks(n.get("value"), tainted)
        elif k == "new":
            hit = any(isinstance(x, dict) and x.get("name") in _FIELD_SINKS and _leaks(x.get("value"), tainted)
                      for x in n.get("init") or [])
        if hit:
            lines.append(n.get("line") or 0)
    return lines


def _handler_args(c: PipeCall) -> list:
    """The lambda and initializer arguments of a call that can install an exception response."""
    args = list(c.node.get("args") or []) + list((c.node.get("named") or {}).values())
    return [a for a in args if isinstance(a, dict) and a.get("k") in ("lambda", "new")]


def _installs_handler(c: PipeCall) -> tuple[bool, bool]:
    """(installs, conditional): UseExceptionHandler, AddProblemDetails, or `Configure<ProblemDetailsOptions>`
    setting the customizer. A customizer set only under a condition inside the lambda (an if, or after a
    guarded return) is still scanned for leaks but is `conditional`: it may never be installed."""
    if c.name in ("UseExceptionHandler", "AddProblemDetails"):
        o, uncertain = verdict(options_of(c.node), "CustomizeProblemDetails")
        return True, bool(o is not None and uncertain)
    if c.name == "Configure" and c.kind == "services":
        o, uncertain = verdict(options_of(c.node), "CustomizeProblemDetails")
        return o is not None, uncertain
    return False, False


def _developer_page(ctx: Ctx, pipe: Pipeline, add) -> None:
    for c, conf in _certain_and_uncertain(ctx, pipe, "UseDeveloperExceptionPage"):
        desc = ("The developer exception page returns stack traces, source lines, headers and route data to "
                "the client; it must run only in Development.")
        if conf:
            desc += " It sits under an environment condition that could not be parsed; confirm it is limited to Development."
        add("DNL-CFG-008", "medium", "Developer exception page can run in Production", desc, c.file, c.line, conf)


def _detailed_errors(ctx: Ctx, pipe: Pipeline, add) -> None:
    title = "Detailed error pages can run in Production"
    scope = _scope_of(ctx, pipe)
    if scope is not None:
        e = ctx.settings.effective("Production", scope).get("detailederrors")
        # null or false is safe; true (or the text "true") is a finding; anything else cannot be read.
        if e is not None and e.value is not None and e.value is not False and str(e.value).strip().lower() != "false":
            firm = e.value is True or str(e.value).strip().lower() == "true"
            desc = ("DetailedErrors is on in the Production configuration, so Blazor sends exception detail "
                    "to the browser.")
            if not firm:
                desc += f" The value {e.value!r} could not be read as a boolean; confirm it is false."
            add("DNL-CFG-008", "medium", title, desc, e.file, e.line, None if firm else "REVIEW")
    for c, conf in _certain_and_uncertain(ctx, pipe, *_DETAILED_ERROR_CALLS):
        # A conditional assignment may not run: a conditional good value never clears a bad one, and a
        # bad value that is conditional is only REVIEW.
        o, uncertain = verdict(options_of(c.node), "DetailedErrors", bad=lambda x: const(x.value) is not False)
        if o is None:
            continue
        v = const(o.value)
        if v is False:
            continue
        if v is True and not uncertain:
            desc = "DetailedErrors = true sends exception detail to the browser; limit it to Development."
        elif v is True:
            conf = "REVIEW"
            desc = ("DetailedErrors = true is set, but some assignment to it sits under a condition, so it may "
                    "not take effect in Production; confirm it is limited to Development.")
        else:
            conf = "REVIEW"
            desc = ("DetailedErrors is not a compile-time value, so it may be true in Production; confirm it is "
                    "limited to Development.")
        if c.runs_in("Production") is None:
            desc += " The call sits under an environment condition that could not be parsed."
        add("DNL-CFG-008", "medium", title, desc, c.file, o.line, conf)


def _web_pipeline(pipe: Pipeline) -> bool:
    """True for a pipeline that serves HTTP: a Web SDK project, or one that registers middleware or endpoints
    (a worker host has neither, so a missing error page is no finding there)."""
    if pipe.project is not None and (pipe.project.sdk or "").lower().endswith(".web"):
        return True
    return any(c.kind in ("app", "endpoints") and c.name not in ("Build", "Run", "RunAsync") for c in pipe.calls)


def _first_site(pipe: Pipeline) -> tuple[str, int]:
    """(file, line) to anchor a finding about the pipeline as a whole: its first middleware or endpoint
    call, else the entry method it was built from."""
    first = next((c for c in pipe.calls if c.kind in ("app", "endpoints")), None)
    if first is not None:
        return first.file, first.line
    return (pipe.entries[0][0].file, pipe.entries[0][1].line) if pipe.entries else ("", 0)


def _missing_handler(ctx: Ctx, pipe: Pipeline, add) -> None:
    if pipe.style == "none" or not _web_pipeline(pipe):
        return
    if any(_is_handler(c.name) for c in pipe.named(kinds=("app",))):
        return
    if pipe.named("UseDeveloperExceptionPage"):
        return  # a developer page that certainly runs is the handler; DNL-CFG-008 reports it
    file, line = _first_site(pipe)
    _conf, note = ctx.absent_confidence(pipe)
    desc = ("The Production pipeline has no UseExceptionHandler, UseStatusCodePages* or problem-details "
            "handler, so an unhandled exception gives a bare 500 response. A reverse proxy, a global exception "
            "filter or a host-level handler may provide the error page; confirm it.")
    if note:
        desc += f" Pipeline notes: {note}."
    add("DNL-CFG-009", "low", "No exception handler in the Production pipeline", desc, file, line, "REVIEW")


def _handler_leaks(ctx: Ctx, pipe: Pipeline, add) -> None:
    calls = _certain_and_uncertain(ctx, pipe, "UseExceptionHandler", "AddProblemDetails", "Configure")
    for c, conf in calls:
        installs, maybe = _installs_handler(c)
        if not installs:
            continue
        for line in _leak_sinks(_handler_args(c)):
            desc = ("The exception handler writes exception detail (Message, StackTrace or ToString) into the "
                    "response, which discloses internals to the client. Return a generic message and a trace "
                    "id, and log the detail.")
            if conf:
                desc += " The handler sits under an environment condition that could not be parsed."
            if maybe:
                conf = "REVIEW"
                desc += " The customizer is set under a condition inside the options lambda, so it may not be installed."
            add("DNL-ERR-002", "medium", "Exception handler returns exception detail", desc, c.file, line, conf)


def _errors(ctx: Ctx) -> None:
    seen: set = set()

    def add(cid, sev, title, desc, file, line, conf):
        # A helper method followed from two call sites yields the same fact twice.
        key = (cid, file, line, conf)
        if key not in seen:
            seen.add(key)
            ctx.add(cid, sev, title, desc, file, line, confidence=conf)

    for pipe in ctx.pipes:
        _developer_page(ctx, pipe, add)
        _detailed_errors(ctx, pipe, add)
        _missing_handler(ctx, pipe, add)
        _handler_leaks(ctx, pipe, add)


# -- transport (DNL-CFG-010, DNL-CFG-011, DNL-CFG-013, DNL-CFG-014) -------------------------------------

_HSTS_HEADER = "strict-transport-security"
_LISTEN_CALLS = ("Listen", "ListenAnyIP", "ListenLocalhost")
_HTTPS_CALLS = ("UseHttps", "ConfigureHttpsDefaults")
_LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]")
_PROXY_NOTE = " A TLS-terminating reverse proxy or load balancer in front of the app may provide this; confirm it."


def _has_string(node, wanted: str) -> bool:
    """True when a string literal equal to `wanted` (ignoring case) sits anywhere inside the node."""
    return any((literal_str(n) or "").strip().lower() == wanted for n in walk(node))


def _sets_hsts_header(pipe: Pipeline) -> bool:
    """A Strict-Transport-Security header literal in a call that certainly runs in Production: an inline
    `app.Use(...)` writing `Headers["Strict-Transport-Security"]` or `Headers.Append(...)`."""
    return any(_has_string(c.node, _HSTS_HEADER) for c in pipe.named())


def _redirects_to_https(pipe: Pipeline) -> bool:
    """UseHttpsRedirection, or its older equivalents: a rewrite rule `AddRedirectToHttps*` or a
    `RequireHttpsAttribute` filter, in a call that certainly runs in Production."""
    if pipe.named("UseHttpsRedirection"):
        return True
    for c in pipe.named():
        for n in walk(c.node):
            if (call_name(n) or "").startswith("AddRedirectToHttps"):
                return True
            if n.get("k") == "new" and (n.get("type") or "").split(".")[-1].startswith("RequireHttps"):
                return True
    return False


def _middleware_names(ctx: Ctx, pipe: Pipeline) -> list[str]:
    """`UseMiddleware<T>()` calls (certain or under an unparsed guard): a custom middleware can write any
    header, and its body is not read here."""
    out = []
    for c, _conf in _certain_and_uncertain(ctx, pipe, "UseMiddleware"):
        fn = c.node.get("fn") if isinstance(c.node.get("fn"), dict) else {}
        targs = [str(t) for t in fn.get("targs") or []]
        out.append(f"{', '.join(targs) or 'UseMiddleware'} at {c.file}:{c.line}")
    return out


def _https_redirection_and_hsts(ctx: Ctx, pipe: Pipeline, add) -> None:
    if pipe.style == "none" or not _web_pipeline(pipe):
        return
    file, line = _first_site(pipe)
    conf, note = ctx.absent_confidence(pipe)
    tail = f" Pipeline notes: {note}." if note else ""
    if not _redirects_to_https(pipe):
        add("DNL-CFG-010", "low", "No HTTPS redirection in the Production pipeline",
            "The Production pipeline never calls UseHttpsRedirection, so plain-HTTP requests are served "
            "instead of being sent to HTTPS." + _PROXY_NOTE + tail, file, line, conf)
    if not pipe.named("UseHsts") and not _sets_hsts_header(pipe):
        hsts_conf, hsts_tail = conf, tail
        mw = _middleware_names(ctx, pipe)
        if mw:
            hsts_conf = "REVIEW"
            hsts_tail += f" Custom middleware ({'; '.join(mw)}) could set the header; its body was not read."
        add("DNL-CFG-011", "low", "No HSTS in the Production pipeline",
            "The Production pipeline never calls UseHsts and sets no Strict-Transport-Security header "
            "(AddHsts alone only configures the options), so browsers are not told to insist on HTTPS."
            + _PROXY_NOTE + hsts_tail, file, line, hsts_conf)


def _url_parts(text: str) -> tuple[str, str] | None:
    """(scheme, host) of an http(s) URL, lower-cased; None for anything else (a unix socket, a bare port)."""
    m = re.match(r"^\s*(https?)://(\[[^\]]*\]|[^:/\s]*)", text, re.I)
    return (m.group(1).lower(), m.group(2).lower()) if m else None


def _url_sites(text: str) -> tuple[bool, bool]:
    """(has an https URL, has a non-loopback http URL) for a `;`-separated URL list."""
    https = http = False
    for part in text.split(";"):
        u = _url_parts(part)
        if u is None:
            continue
        if u[0] == "https":
            https = True
        elif u[1] not in _LOOPBACK_HOSTS:
            http = True
    return https, http


def _kestrel_code(pipe: Pipeline) -> tuple[bool, list[str], bool, list[tuple[str, int, str | None]]]:
    """(https certainly present, where an https listener may or may not run, something unreadable,
    [(file, line, confidence)] of HTTP-only listeners) from ConfigureKestrel / UseKestrel option lambdas
    and UseUrls calls that can run in Production.

    Conditions are read at two levels. A call under an environment guard in the pipeline is judged by
    `runs_in("Production")` (False: skipped; None: uncertain). Inside a lambda body the pipeline models no
    guards, so `walk_conditional` marks anything below an if / else / switch / loop / ternary / catch as
    conditional: an HTTPS listener or UseHttps there never clears the finding (it goes to `maybe_https`,
    which turns CFG-013 into REVIEW), and an HTTP-only listener there is REVIEW unless an unconditional
    one is also present. Only an unconditional HTTPS listener in a call that certainly runs clears it."""
    https = unreadable = False
    maybe_https: list[str] = []
    sites: list[tuple[str, int, str | None]] = []
    seen: set = set()
    for c in pipe.calls:
        run = c.runs_in("Production")
        if run is False:
            continue
        conf = None if run else "REVIEW"
        for n in walk(c.node):
            if n.get("k") != "call" or id(n) in seen:
                continue
            seen.add(id(n))
            name = call_name(n)
            line = n.get("line") or c.line
            args = list(n.get("args") or []) + list((n.get("named") or {}).values())
            if name in ("ConfigureKestrel", "UseKestrel"):
                lams = [a for a in args if isinstance(a, dict) and a.get("k") == "lambda"]
                if args and not lams:
                    unreadable = True      # a method group or options object: its listeners are not read
                for lam in lams:
                    inner = [(x, cd) for x, cd in walk_conditional(lam) if x.get("k") == "call"]
                    for x, cd in inner:
                        if call_name(x) in _HTTPS_CALLS:
                            if run and not cd:
                                https = True
                            else:
                                maybe_https.append(f"{c.file}:{x.get('line') or line}")
                    # A Listen* call that carries its own UseHttps is the HTTPS listener, not an HTTP one.
                    listens = [(x, cd) for x, cd in inner if call_name(x) in _LISTEN_CALLS
                               and not any(call_name(y) in _HTTPS_CALLS for y in walk(x))]
                    if listens:
                        # Report the first listener that certainly runs; when every one is conditional the
                        # first of them is reported as REVIEW.
                        x, cd = next(((x, cd) for x, cd in listens if not cd), listens[0])
                        sites.append((c.file, x.get("line") or line, "REVIEW" if cd else conf))
            elif name == "UseUrls":
                for a in args:
                    text = const_str(a)
                    if text is None:
                        unreadable = True
                        continue
                    h, p = _url_sites(text)
                    if h:
                        if run:
                            https = True
                        else:
                            maybe_https.append(f"{c.file}:{line}")
                    if p:
                        sites.append((c.file, line, conf))
    return https, maybe_https, unreadable, sites


def _kestrel_settings(ctx: Ctx, pipe: Pipeline) -> tuple[bool, list]:
    """(https present, [Entry] of non-loopback http URLs) in the Production `Urls` and
    `Kestrel:Endpoints:*:Url` settings of the pipeline's project."""
    scope = _scope_of(ctx, pipe)
    if scope is None:
        return False, []
    https = False
    bad = []
    for key, e in ctx.settings.effective("Production", scope).items():
        parts = key.split(":")
        # A certificate configured for an endpoint, or a default certificate, means TLS is served.
        if ((len(parts) >= 4 and parts[:2] == ["kestrel", "endpoints"] and parts[3] == "certificate")
                or parts[:2] == ["kestrel", "certificates"]):
            https = True
        is_url = key == "urls" or (len(parts) == 4 and parts[:2] == ["kestrel", "endpoints"] and parts[3] == "url")
        if is_url and isinstance(e.value, str):
            h, p = _url_sites(e.value)
            https = https or h
            if p:
                bad.append(e)
    return https, bad


def _http_only(ctx: Ctx, pipe: Pipeline, add) -> None:
    code_https, maybe_https, unreadable, sites = _kestrel_code(pipe)
    cfg_https, bad = _kestrel_settings(ctx, pipe)
    if code_https or cfg_https:
        return
    desc = ("The app listens on plain HTTP only: no HTTPS endpoint is configured in code or in the Production "
            "settings, so traffic and cookies cross the network unencrypted." + _PROXY_NOTE)
    if maybe_https:
        # An HTTPS listener under an unparsed guard downgrades the finding; it never clears it.
        unreadable = True
        desc += (f" An HTTPS listener at {', '.join(maybe_https)} sits under an environment condition that "
                 "could not be parsed; confirm it runs in Production.")
    elif unreadable:
        desc += " Some listener configuration is not a compile-time value, so an HTTPS endpoint may exist; confirm it."
    for file, line, conf in sites:
        add("DNL-CFG-013", "low", "Listens on HTTP only", desc, file, line, "REVIEW" if unreadable else conf)
    for e in bad:
        add("DNL-CFG-013", "low", "Listens on HTTP only", desc + f" Setting {e.key} is {e.value!r}.",
            e.file, e.line, "REVIEW" if unreadable else None)


def _allowed_hosts(ctx: Ctx, pipe: Pipeline, add) -> None:
    scope = _scope_of(ctx, pipe)
    if scope is None:
        return
    e = ctx.settings.effective("Production", scope).get("allowedhosts")
    if e is None or not isinstance(e.value, str):
        return
    if any(seg.strip() == "*" for seg in e.value.split(";")):
        add("DNL-CFG-014", "low", "AllowedHosts accepts any host",
            f"AllowedHosts is {e.value!r} in the Production configuration, so host filtering is off and the "
            "app answers requests for any Host header (host header injection, cache poisoning). List the "
            "real host names; a gateway that already validates the Host header may make this acceptable.",
            e.file, e.line, None)


def _transport(ctx: Ctx) -> None:
    seen: set = set()

    def add(cid, sev, title, desc, file, line, conf):
        key = (cid, file, line, conf)
        if key not in seen:
            seen.add(key)
            ctx.add(cid, sev, title, desc, file, line, confidence=conf)

    for pipe in ctx.pipes:
        _https_redirection_and_hsts(ctx, pipe, add)
        _http_only(ctx, pipe, add)
        _allowed_hosts(ctx, pipe, add)


# -- CORS (DNL-CFG-007, DNL-CFG-015) ---------------------------------------------------------------------

_MUTATING = {"POST", "PUT", "DELETE", "PATCH"}

# Methods of CorsPolicyBuilder; any other call on the builder (an extension method) could do anything.
_CORS_BUILDER = frozenset("""allowanyorigin allowanyheader allowanymethod allowcredentials disallowcredentials
withorigins withheaders withmethods withexposedheaders setisoriginallowed
setisoriginallowedtoallowwildcardsubdomains setpreflightmaxage build""".split())
_POLICY_DEFS = ("AddPolicy", "AddDefaultPolicy")
_DEFAULT_POLICY = ""        # the name key of the default policy (AddDefaultPolicy, [EnableCors], UseCors())
_CREDENTIALS_NOTE = (" The framework throws at runtime when AllowAnyOrigin() is combined with AllowCredentials(), "
                     "so the app either fails or the policy is built another way; fix it either way.")


@dataclass
class _Policy:
    name: str | None            # None: the name is not a compile-time string
    file: str
    line: int                   # the AddPolicy / UseCors / RequireCors call
    guard: str | None = None    # REVIEW when the call sits under an unparsed environment condition
    bad: list = field(default_factory=list)       # [(what, line, conditional)] wildcard origins
    maybe: list = field(default_factory=list)     # [(why, line)] values that could not be read
    creds: bool = False         # AllowCredentials() runs unconditionally
    creds_cond: bool = False    # AllowCredentials() appears, but only under a condition


def _chain_root(call: dict):
    root, _ = call_chain(call)
    return root


def _origin_args(call: dict) -> tuple[list[str], bool]:
    """([string literals], every argument readable) for WithOrigins(...): literals and arrays of literals."""
    out: list[str] = []
    readable = True
    for a in call.get("args") or []:
        s = literal_str(a)
        if s is not None:
            out.append(s)
            continue
        inner = [literal_str(n) for n in walk(a)]
        if (isinstance(a, dict) and a.get("k") in ("new", "array", "collection") and
                all(n.get("k") in ("new", "array", "collection", "lit") or n is a for n in walk(a))
                and any(x is not None for x in inner)):
            out += [x for x in inner if x is not None]
        else:
            readable = False
    return out, readable


def _read_policy(pol: _Policy, arg, base_cond: bool) -> None:
    """Fill a policy from its builder argument: a lambda `b => b.AllowAnyOrigin()...` (statements, ifs and
    early exits included), or an inline `new CorsPolicyBuilder()...Build()` chain. Anything else, a builder
    handed to a helper, or an unknown builder method leaves a `maybe` entry."""
    steps: list[tuple[dict, bool]] = []
    if isinstance(arg, dict) and arg.get("k") == "lambda":
        params = [p for p in arg.get("params") or [] if isinstance(p, str)]
        param = params[0] if params else None
        if param is None:
            pol.maybe.append(("the policy builder lambda has no parameter", pol.line))
            return
        roots: set = set()
        for n, cd in walk_conditional(arg, base_cond):
            if n.get("k") == "call":
                r = _chain_root(n)
                if isinstance(r, dict) and r.get("k") == "name" and r.get("id") == param:
                    steps.append((n, cd))
                    roots.add(id(r))
        if param_escapes(arg.get("body"), param, roots):
            pol.maybe.append(("the policy builder is used outside a call chain (passed to a helper or "
                              "assigned), so its policy is built where this code cannot see", pol.line))
    else:
        root, calls = call_chain(arg) if isinstance(arg, dict) else (None, [])
        if isinstance(root, dict) and root.get("k") == "new" and (root.get("type") or "").endswith("CorsPolicyBuilder"):
            steps = [(c, base_cond) for c in calls]
        else:
            pol.maybe.append(("the policy is not a lambda over the builder (a method group, a variable or a "
                              "helper call)", pol.line))
            return
    for n, cd in steps:
        name = (call_name(n) or "").lower()
        line = n.get("line") or pol.line
        if name not in _CORS_BUILDER:
            pol.maybe.append((f"{call_name(n)}() is not a CorsPolicyBuilder method and may set any origin", line))
        elif name == "allowanyorigin":
            pol.bad.append(("AllowAnyOrigin()", line, cd))
        elif name == "withorigins":
            origins, readable = _origin_args(n)
            if "*" in origins:
                pol.bad.append(('WithOrigins("*")', line, cd))
            elif not readable:
                pol.maybe.append(("WithOrigins(...) takes origins that are not literals (configuration or a "
                                  "variable); confirm none of them is *", line))
        elif name == "setisoriginallowed":
            fn = (n.get("args") or [None])[0]
            if always_true(fn):
                pol.bad.append(("SetIsOriginAllowed(always true)", line, cd))
            elif not (isinstance(fn, dict) and fn.get("k") == "lambda"):
                pol.maybe.append(("SetIsOriginAllowed takes a callback that is not a lambda", line))
        elif name == "allowcredentials":
            if cd:
                pol.creds_cond = True
            else:
                pol.creds = True
        elif name == "disallowcredentials":
            if cd:
                pol.creds_cond = True
            else:
                pol.creds = pol.creds_cond = False


def _policy_verdict(pol: _Policy) -> tuple[str, str, str | None, str, int] | None:
    """(severity, title, confidence, description, line) of a policy's CFG-007 finding, or None when it is
    clean. A wildcard that always runs is firm; one only under a condition, or a value that could not be
    read, is REVIEW; a conditional good origin never clears a wildcard."""
    firm = [b for b in pol.bad if not b[2]]
    cond = [b for b in pol.bad if b[2]]
    label = f"policy {pol.name!r}" if pol.name else "the default policy" if pol.name == _DEFAULT_POLICY else "a policy"
    if firm or cond:
        what = ", ".join(dict.fromkeys(b[0] for b in (firm or cond)))
        line = (firm or cond)[0][1]
        high = pol.creds or (not firm and pol.creds_cond)
        desc = (f"CORS {label} accepts requests from any origin ({what})"
                + (" with credentials allowed, so any site can make authenticated cross-origin calls and read the "
                   "responses." if high else ", so any site can read its responses cross-origin."))
        if high and any(b[0] == "AllowAnyOrigin()" for b in (firm or cond)):
            desc += _CREDENTIALS_NOTE
        if not firm:
            desc += " The wildcard sits under a condition inside the policy lambda, so it may not apply; confirm."
        elif pol.creds_cond and not pol.creds:
            desc += " AllowCredentials() sits under a condition inside the policy lambda."
        title = "CORS policy allows any origin" + (" with credentials" if high else "")
        return ("high" if high else "medium", title, None if firm else "REVIEW", desc, line)
    if pol.maybe:
        why, line = pol.maybe[0]
        return ("medium", "CORS policy could not be read",
                "REVIEW", f"CORS {label} could not be read: {why}. Confirm it does not allow any origin.", line)
    return None


def _cors_option_policies(c: PipeCall, conf: str | None) -> tuple[list[_Policy], list[tuple[str, int]]]:
    """([policy], [(reason, line)] not readable) from the options lambda of an AddCors / Configure<CorsOptions>
    call. A non-lambda argument (a method group) or an options object used outside AddPolicy / AddDefaultPolicy
    makes the whole set unreadable."""
    pols: list[_Policy] = []
    opaque: list[tuple[str, int]] = []
    args = list(c.node.get("args") or []) + list((c.node.get("named") or {}).values())
    for a in args:
        if not isinstance(a, dict):
            continue
        if a.get("k") != "lambda":
            opaque.append(("the CORS options are not a lambda (a method group or a variable)", c.line))
            continue
        params = [p for p in a.get("params") or [] if isinstance(p, str)]
        param = params[0] if params else None
        if param is None:
            continue
        ok: set = set()
        for n, cd in walk_conditional(a):
            if n.get("k") != "call" or call_name(n) not in _POLICY_DEFS:
                if (n.get("k") == "member" and n.get("name") == "DefaultPolicyName"
                        and isinstance(n.get("obj"), dict) and n["obj"].get("id") == param):
                    ok.add(id(n["obj"]))
                continue
            fn = n.get("fn") if isinstance(n.get("fn"), dict) else {}
            if not (isinstance(fn.get("obj"), dict) and fn["obj"].get("k") == "name" and fn["obj"].get("id") == param):
                continue
            ok.add(id(fn["obj"]))
            cargs = n.get("args") or []
            line = n.get("line") or c.line
            if call_name(n) == "AddDefaultPolicy":
                name, builder = _DEFAULT_POLICY, cargs[0] if cargs else None
            else:
                name, builder = (const_str(cargs[0]) if cargs else None), cargs[1] if len(cargs) > 1 else None
            pol = _Policy(name, c.file, line, conf)
            _read_policy(pol, builder, cd)
            pols.append(pol)
        if param_escapes(a.get("body"), param, ok):
            opaque.append(("the CORS options object is used outside AddPolicy / AddDefaultPolicy (passed to a "
                           "helper), so some policies are built where this code cannot see", c.line))
    return pols, opaque


def _cors_attr_names(attrs: list) -> list[str | None] | None:
    """Policy names of the [EnableCors] attributes in a list: [name] ("" = default, None = not a literal);
    None when the list has none; [] when [DisableCors] is there."""
    en = [a for a in attrs if attr_key(a.name) == "enablecors"]
    if any(attr_key(a.name) == "disablecors" for a in attrs) and not en:
        return []
    if not en:
        return None
    return [(const_str(a.args[0]) if a.args else _DEFAULT_POLICY) for a in en]


def _page_cors_names(raw: str) -> list[str | None]:
    """Policy names of an `@attribute [EnableCors("n")]` directive text ([] for none or a DisableCors)."""
    if re.search(r"DisableCors", raw):
        return []
    m = re.search(r"EnableCors(?:Attribute)?\s*(?:\(([^)]*)\))?", raw)
    if not m:
        return []
    inner = (m.group(1) or "").strip()
    if not inner:
        return [_DEFAULT_POLICY]
    q = re.fullmatch(r'"([^"]*)"', inner)
    return [q.group(1) if q else None]


def _route_cors_names(ctx: Ctx, ref: CoreRouteRef) -> list[tuple[str | None, str, int]]:
    """[(policy name, how, line)] a route is bound to: [EnableCors] on the action, else on its class chain
    (the nearest type carrying one), a page's `@attribute` directive, and RequireCors on its endpoint,
    group or convention calls. A [DisableCors] on the action (or class) switches the attribute off."""
    out: list[tuple[str | None, str, int]] = []
    from_attr: list[str | None] | None = None
    if ref.method is not None:
        from_attr = _cors_attr_names(ref.method.attributes)
    if from_attr is None and ref.type is not None and ref.style in ("controller", "razorpage"):
        for t in _chain_types(ctx.model, ref.type):
            from_attr = _cors_attr_names(t.attributes)
            if from_attr is not None:
                break
    for nm in from_attr or []:
        out.append((nm, "[EnableCors]", ref.route.line))
    for raw in ref.route.meta.get("page_attributes") or []:
        for nm in _page_cors_names(str(raw)):
            out.append((nm, "@attribute [EnableCors]", ref.route.line))
    return out


def _require_cors_calls(ref: CoreRouteRef) -> list[dict]:
    calls = list(ref.endpoint_calls) + list(ref.convention_calls)
    for g in ref.groups:
        calls += g.calls
    return [c for c in calls if isinstance(c, dict) and call_name(c) == "RequireCors"]


def _cors(ctx: Ctx) -> None:
    seen: set = set()
    policies: dict[str | None, list[_Policy]] = {}
    opaque = False                  # a CORS options set that could not be read in full
    reported_undefined: set = set()

    def add007(pol: _Policy, v) -> None:
        sev, title, conf, desc, line = v
        if pol.guard:
            conf = "REVIEW"
            desc += " The call sits under an environment condition that could not be parsed."
        key = ("DNL-CFG-007", pol.file, line, title)
        if key not in seen:
            seen.add(key)
            ctx.add("DNL-CFG-007", sev, title, desc, pol.file, line, confidence=conf)

    def review(file: str, line: int, desc: str, title: str = "CORS policy could not be read") -> None:
        key = ("DNL-CFG-007", file, line, title)
        if key not in seen:
            seen.add(key)
            ctx.add("DNL-CFG-007", "medium", title, desc, file, line, confidence="REVIEW")

    named_uses: list[tuple[str | None, str, int]] = []      # (name, file, line) of UseCors / RequireCors names

    def use(c_node: dict, file: str, line: int, guard: str | None) -> None:
        """A UseCors / RequireCors call: a name to resolve later, or an inline policy to read now."""
        args = c_node.get("args") or []
        if args and isinstance(args[0], dict) and args[0].get("k") == "lambda":
            pol = _Policy(None, file, c_node.get("line") or line, guard)
            _read_policy(pol, args[0], False)
            v = _policy_verdict(pol)
            if v is not None and id(c_node) not in seen:
                seen.add(id(c_node))
                add007(pol, v)
        elif args:
            named_uses.append((const_str(args[0]), file, c_node.get("line") or line))

    for pipe in ctx.pipes:
        for c, conf in _certain_and_uncertain(ctx, pipe, "AddCors", "Configure"):
            if c.name == "Configure" and not any("CorsOptions" in str(t) for t in
                                                  (c.node.get("fn") or {}).get("targs") or []):
                continue
            pols, opq = _cors_option_policies(c, conf)
            for why, line in opq:
                opaque = True
                review(c.file, line, f"CORS options at {c.file}:{c.line} could not be read: {why}. Confirm no "
                                     "policy allows any origin.")
            for pol in pols:
                policies.setdefault(pol.name, []).append(pol)
                v = _policy_verdict(pol)
                if v is not None:
                    add007(pol, v)
        for c, conf in _certain_and_uncertain(ctx, pipe, "UseCors"):
            use(c.node, c.file, c.line, conf)

    wild = {n for n, ps in policies.items() if any(p.bad for p in ps)}
    unnamed = None in policies

    def problem(name: str | None) -> str | None:
        """Why a used policy name cannot be trusted: None when it is positively matched by a readable
        definition (a wild one is reported at its definition), the default policy, or when an unreadable
        options set was already reported. Otherwise "undefined", "unnamed" (a policy whose own name is not
        a literal might define it) or "unreadable" (the definition could not be read)."""
        if opaque or name == _DEFAULT_POLICY:
            return None
        if name is None:
            return None if policies else "undefined"
        if name in policies:
            defs = policies[name]
            return "unreadable" if any(p.maybe for p in defs) and not any(p.bad for p in defs) else None
        return "unnamed" if unnamed else "undefined"

    def report_problem(name, kind, file, line, where, track=True):
        text = repr(name) if name is not None else "a policy whose name is not a literal"
        why = {"undefined": "no AddPolicy / AddDefaultPolicy defines it in code",
               "unnamed": "no policy with that literal name is defined, and a policy whose name is not a literal "
                          "(a name that is not a compile-time string) might define it",
               "unreadable": "its definition could not be read"}[kind]
        review(file, line, f"{where} uses {text}, but {why}, so its origins cannot be read. Confirm it does not "
                           "allow any origin.", "CORS policy is used but not defined")
        if track:
            reported_undefined.add(name)

    for ref in ctx.refs:        # RequireCors on endpoints and groups: names to resolve, inline policies to read
        for node in _require_cors_calls(ref):
            if id(node) not in seen:
                use(node, ref.route.file, node.get("line") or ref.route.line, None)
                seen.add(id(node))
    # (an inline policy is reported by `use`; a shared group call is visited once)

    for name, file, line in named_uses:
        kind = problem(name)
        if kind:
            report_problem(name, kind, file, line, "UseCors / RequireCors")
    for ref in ctx.refs:        # [EnableCors("x")] on any route: the policy must be defined and readable
        for name, how, line in _route_cors_names(ctx, ref):
            kind = problem(name)
            if kind:
                report_problem(name, kind, ref.route.file, line, how, track=False)

    # Route-bound: CFG-015 on a sensitive or mutating handler that opts into CORS.
    for ref in ctx.refs:
        names = _route_cors_names(ctx, ref)
        for node in _require_cors_calls(ref):
            args = node.get("args") or []
            if args and isinstance(args[0], dict) and args[0].get("k") == "lambda":
                continue            # an inline policy is read, and reported by CFG-007 when it is wild
            names.append((const_str(args[0]) if args else _DEFAULT_POLICY, "RequireCors",
                          node.get("line") or ref.route.line))
        r = ref.route
        if not names or not (_MUTATING & {v.upper() for v in r.methods} or _sensitive(ref)):
            continue
        for name, how, _line in names:
            if name in wild or name in reported_undefined:
                continue            # CFG-007 already reports the policy
            kind = problem(name)
            why = ("; the named policy is not defined in code" if kind in ("undefined", "unnamed") else
                   "; the named policy could not be read" if kind == "unreadable" else
                   "; its policy name is not a literal" if name is None else "")
            key = ("DNL-CFG-015", r.file, r.line, name, how)
            if key in seen:
                continue
            seen.add(key)
            ctx.add("DNL-CFG-015", "low", f"CORS enabled on sensitive handler {r.handler_name}",
                    f"{r.handler_name} ({', '.join(r.methods)} {r.path}) opts into cross-origin access via {how}"
                    f"{' ' + repr(name) if name else ''}{why}. A browser on an allowed origin can call it with the "
                    "user's cookies when the policy allows credentials; confirm the allowed origins are exactly "
                    "the front ends that need it.",
                    r.file, r.line, route=ref.route, confidence="REVIEW")


# -- inventory (DNL-INV-003, DNL-INV-004) ----------------------------------------------------------------

# Calls that serve an API description or its UI (Swagger / OpenAPI / ReDoc / Scalar / NSwag).
_OPENAPI_CALLS = ("UseSwagger", "UseSwaggerUI", "UseReDoc", "MapOpenApi", "MapScalarApiReference",
                  "MapSwagger", "UseOpenApi")
_VERSION_RE = re.compile(r"^\s*(\d+)(?:\.(\d+))?(?:-[\w.]+)?\s*$")
_DATE_VERSION_RE = re.compile(r"^\s*(\d{4})-(\d{2})-(\d{2})(?:-[\w.]+)?\s*$")
_PATH_VERSION_RE = re.compile(r"^v(\d+)(?:\.(\d+))?$", re.I)


def _openapi(ctx: Ctx) -> None:
    seen: set = set()
    for pipe in ctx.pipes:
        for c, conf in _certain_and_uncertain(ctx, pipe, *_OPENAPI_CALLS):
            key = (c.file, c.line, c.name)
            if key in seen:
                continue
            seen.add(key)
            desc = (f"{c.name}() publishes the API description or its interactive UI in the Production pipeline, "
                    "which hands an attacker the full endpoint list, parameters and models. Serve it only in "
                    "Development (`if (app.Environment.IsDevelopment())`) or put it behind authentication.")
            if any(call_name(x) == "RequireAuthorization" for x in c.chain):
                desc += (" It also carries RequireAuthorization, which limits who can read it (reported for "
                         "information; confirm the policy is not satisfied by any signed-in user).")
            if conf:
                desc += " The call sits under an environment condition that could not be parsed; confirm it is limited to Development."
            ctx.add("DNL-INV-003", "low", f"{c.name} serves the API description in Production", desc, c.file, c.line,
                    confidence=conf)


def _int_lits(args) -> list[int] | None:
    """The integer values of the first two arguments when both are int literals, else None."""
    vals = [a.get("v") for a in args[:2] if isinstance(a, dict) and a.get("k") == "lit"
            and isinstance(a.get("v"), int) and not isinstance(a.get("v"), bool)]
    return vals if len(args) >= 2 and len(vals) == 2 else None


def _version_key(expr) -> tuple | None:
    """(major, minor) -- or (year, month, day) for a date version -- from a version literal (`"1.0"`, `1.0`,
    `1`) or `new ApiVersion(1, 0)`; None when it is not a compile-time value."""
    if not isinstance(expr, dict):
        return None
    if expr.get("k") == "new" and (expr.get("type") or "").split(".")[-1] == "ApiVersion":
        args = expr.get("args") or []
        return _args_version(args)
    text = literal_str(expr)
    if text is None and expr.get("k") == "lit" and isinstance(expr.get("v"), (int, float)) \
            and not isinstance(expr.get("v"), bool):
        text = repr(expr["v"])
    if text is None:
        return None
    m = _DATE_VERSION_RE.match(text)
    if m:
        return tuple(int(x) for x in m.groups())
    m = _VERSION_RE.match(text)
    return (int(m.group(1)), int(m.group(2) or 0)) if m else None


def _args_version(args) -> tuple | None:
    """A version from constructor / attribute arguments: `(1, 0)` or a single literal (a status text after
    it, `("1.0", "beta")`, is ignored)."""
    nums = _int_lits(args)
    if nums is not None:
        return (nums[0], nums[1])
    return _version_key(args[0]) if args else None


def _version_text(key: tuple) -> str:
    return f"{key[0]:04d}-{key[1]:02d}-{key[2]:02d}" if len(key) == 3 else f"{key[0]}.{key[1]}"


def _path_version(path: str) -> tuple | None:
    """The `v<N>[.<M>]` prefix of a route path: the first segment, or the one after a leading `api` segment
    (`/api/v1/orders`, `/v1/orders` -> (1, 0)); `/api/orders/v1` is not a version prefix."""
    segs = path.strip("/").split("/")
    if segs and segs[0].lower() == "api":
        segs = segs[1:]
    m = _PATH_VERSION_RE.match(segs[0]) if segs else None
    return (int(m.group(1)), int(m.group(2) or 0)) if m else None


@dataclass
class _Deprecation:
    file: str
    line: int
    key: tuple | None            # None: the version argument is not a literal
    types: list[str]             # controller type names from Controller<T>() / Controller(typeof(T)) in the chain
    certain: bool                # the call runs in Production for certain


def _deprecation_calls(ctx: Ctx) -> list[_Deprecation]:
    """Every HasDeprecatedApiVersion call reachable from a pipeline (conventions inside AddApiVersioning
    lambdas, version sets, followed helpers), with the controller types its chain names and whether it
    certainly runs in Production. A call seen from two sites is certain if either site is."""
    found: dict[int, _Deprecation] = {}
    for pipe in ctx.pipes:
        for c in pipe.calls:
            sure = c.runs_in("Production") is True
            for n in walk(c.node):
                if n.get("k") != "call" or call_name(n) != "HasDeprecatedApiVersion":
                    continue
                types: list[str] = []
                for link in call_chain(n)[1]:
                    if call_name(link) != "Controller":
                        continue
                    types += [str(t) for t in (link.get("fn") or {}).get("targs") or []]
                    for arg in link.get("args") or []:
                        m = re.fullmatch(r"\s*typeof\s*\(\s*([\w.]+)\s*\)\s*",
                                         arg.get("text") or "" if isinstance(arg, dict) else "")
                        if m:
                            types.append(m.group(1))
                prev = found.get(id(n))
                if prev is None:
                    found[id(n)] = _Deprecation(c.file, n.get("line") or c.line, _args_version(n.get("args") or []),
                                                types, sure)
                elif sure:
                    prev.certain = True
    return list(found.values())


def _tied(d: _Deprecation, ref: CoreRouteRef) -> bool:
    """True when the call's chain names this route's controller type (simple name, or the qualified name
    when the call qualifies it)."""
    if ref.type is None:
        return False
    for t in d.types:
        t = t.split("<")[0]
        if "." in t:
            if ref.type.full_name.lower().endswith(t.lower()):
                return True
        elif t.lower() == ref.type.name.split(".")[-1].lower():
            return True
    return False


def _route_api_attrs(ctx: Ctx, ref: CoreRouteRef) -> list:
    """The [ApiVersion] attributes that apply to a route: its action's, and those of its controller and the
    controller's base classes (ApiVersionAttribute is inherited and combines)."""
    attrs = []
    if ref.method is not None:
        attrs += [a for a in ref.method.attributes if attr_key(a.name) == "apiversion"]
    if ref.type is not None and ref.style in ("controller", "razorpage"):
        for t in _chain_types(ctx.model, ref.type):
            attrs += [a for a in t.attributes if attr_key(a.name) == "apiversion"]
    return attrs


def _api_versions(ctx: Ctx) -> None:
    # Known limit: versions declared through minimal-API HasApiVersion, an ApiVersionSet or [MapToApiVersion]
    # are not read here; _unread_versioning reports that as one REVIEW per pipeline.
    # {version: [(ref, deprecated)]} in route order; attributes that could not be read, once each.
    by_version: dict[tuple, list] = {}
    unreadable: list[tuple] = []         # (ref, attr)
    seen_attrs: set = set()
    dep_calls = _deprecation_calls(ctx)
    dep_unreadable = any(d.key is None for d in dep_calls)
    for ref in ctx.refs:
        meta = ref.route.meta
        if meta.get("kind") == "openapi" or str(meta.get("env") or "").lower() == "development":
            continue
        mine: dict[tuple, bool] = {}
        for a in _route_api_attrs(ctx, ref):
            key = _args_version(a.args)
            if key is None:
                if id(a) not in seen_attrs:
                    seen_attrs.add(id(a))
                    unreadable.append((ref, a))
                continue
            flag = a.named.get("Deprecated") if isinstance(a.named, dict) else None
            mine[key] = mine.get(key, True) and const(flag) is True
        pv = _path_version(ref.route.path)
        if pv is not None and pv not in mine:
            mine[pv] = False
        for key, dep in mine.items():
            by_version.setdefault(key, []).append(
                (ref, dep or any(d.key == key and d.certain and _tied(d, ref) for d in dep_calls)))

    def finding(ref, title, desc):
        ctx.add("DNL-INV-004", "low", title, desc, ref.route.file, ref.route.line, route=ref.route, confidence="REVIEW")

    tail = (" A HasDeprecatedApiVersion call with an argument that is not a literal could not be matched."
            if dep_unreadable else "")
    for ref, a in unreadable:
        finding(ref, "API version could not be read",
                f"The [ApiVersion] attribute at {ref.route.file}:{a.line or ref.route.line} takes a value that is not a "
                "string or number literal, so the versions this solution serves cannot be listed. Confirm that no "
                "older API version is still mapped." + tail)
    if len(by_version) < 2:
        return
    newest = max(by_version)
    for key in sorted(by_version):
        if key == newest:
            continue
        live = [ref for ref, dep in by_version[key] if not dep]
        if not live:
            continue                      # every route of that version is marked deprecated
        ref = live[0]
        # A deprecation call only suppresses the routes it is tied to; any other call for this version is
        # named so the reviewer can check whether it covers this route.
        loose = [d for d in dep_calls if d.key == key and not (d.certain and _tied(d, ref))]
        note = ""
        if loose:
            where = ", ".join(f"{d.file}:{d.line}" + ("" if d.certain else " (not certain to run in Production)")
                              for d in loose)
            note = (f" A HasDeprecatedApiVersion({_version_text(key).replace('.', ', ')}) call that could not be "
                    f"tied to this route exists ({where}); confirm whether it deprecates this route.")
        finding(ref, f"Older API version {_version_text(key)} is still mapped",
                f"API version {_version_text(key)} ({len(live)} route(s), first {ref.route.path}) is still served "
                f"next to {_version_text(newest)}. Old versions keep old bugs and missing controls reachable; "
                "retire it, mark it deprecated with a sunset date, or confirm clients still need it." + note + tail)


_UNREAD_VERSIONING = ("HasApiVersion", "NewApiVersionSet", "WithApiVersionSet", "MapToApiVersion")


def _unread_versioning(ctx: Ctx) -> None:
    """Versions declared through HasApiVersion, an ApiVersionSet or [MapToApiVersion] are not read, so the
    version comparison above is incomplete: one route-less REVIEW per pipeline says so."""
    for pipe in ctx.pipes:
        site = None
        for c in pipe.calls:
            for n in walk(c.node):
                if n.get("k") == "call" and call_name(n) in _UNREAD_VERSIONING:
                    site = site or (c.file, n.get("line") or c.line, call_name(n))
        if site is None:
            for ref in ctx.refs:
                if ref.project is pipe.project and ref.method is not None and any(
                        attr_key(a.name) == "maptoapiversion" for a in ref.method.attributes):
                    site = (ref.route.file, ref.route.line, "[MapToApiVersion]")
                    break
        if site is not None:
            ctx.add("DNL-INV-004", "low", "API versions declared through conventions were not read",
                    f"{site[2]} at {site[0]}:{site[1]} declares API versions through a version set, a convention or "
                    "[MapToApiVersion], which this check does not read (only [ApiVersion] attributes and /vN path "
                    "prefixes are), so older versions that are still mapped could not be compared. Confirm no "
                    "older API version is still served.", site[0], site[1], confidence="REVIEW")


def _inventory(ctx: Ctx) -> None:
    _openapi(ctx)
    _api_versions(ctx)
    _unread_versioning(ctx)


# -- data protection (DNL-CRY-009) -----------------------------------------------------------------------

# Methods of IDataProtectionBuilder (and its extensions) that never register a key protector.
_DP_BUILDER = ("PersistKeysTo", "ProtectKeysWith", "UnprotectKeysWith", "SetApplicationName", "SetDefaultKeyLifetime",
               "DisableAutomaticKeyGeneration", "UseCryptographicAlgorithms", "UseCustomCryptographicAlgorithms",
               "AddKeyEscrowSink", "AddKeyManagementOptions", "AddDataProtection")


def _name_ids(node, name: str) -> bool:
    return any(n.get("k") == "name" and n.get("id") == name for n in walk(node))


def _builder_escape(c: PipeCall, bodies: list, by_node: dict) -> str | None:
    """Why the builder returned by this AddDataProtection call may be configured out of sight, or None. A
    chain that ends a statement is read in full. One stored in a local is read through the calls on that
    local (they are pipeline calls); handing it to a call the pipeline did not follow, returning it or
    aliasing it makes the rest invisible."""
    outer = c.chain[-1] if c.chain else c.node
    name = None
    for body in bodies:
        for n in walk(body):
            k = n.get("k")
            if k == "expr" and n.get("expr") is outer:
                return None
            if k == "local" and n.get("init") is outer:
                name = n.get("name")
            elif k == "assign" and n.get("value") is outer:
                t = n.get("target")
                name = t.get("id") if isinstance(t, dict) and t.get("k") == "name" else name
    if name is None:
        return ("the AddDataProtection builder is used as a value (passed on, returned or assigned to a member), "
                "so key storage may be configured where this code cannot see")
    for body in bodies:
        for n in walk(body):
            k = n.get("k")
            if k == "call":
                parts = list(n.get("args") or []) + list((n.get("named") or {}).values())
                if any(_name_ids(a, name) for a in parts):
                    pc = by_node.get(id(n))
                    if pc is None or pc.target is None:
                        return (f"the builder {name} is passed to {call_name(n)}(), which is not followed, so key "
                                "storage and protection may be configured there")
            elif k in ("return", "assign", "local"):
                v = n.get("init") if k == "local" else n.get("value")
                if isinstance(v, dict) and v.get("k") == "name" and v.get("id") == name:
                    return f"the builder {name} is returned or copied to another variable, so it is configured out of sight"
    return None


def _data_protection(ctx: Ctx) -> None:
    seen: set = set()
    bodies = [m.body for t in ctx.model.types() for m in t.methods]
    for pipe in ctx.pipes:
        def runs(prefix: str, pipe=pipe):
            """[(call, True | None)] of calls that run in Production or may (an unparsed guard)."""
            return [(c, c.runs_in("Production")) for c in pipe.calls
                    if c.name.startswith(prefix) and c.runs_in("Production") is not False]

        if any(run for _c, run in runs("ProtectKeysWith")):
            continue                        # an unconditional protector anywhere in the pipeline
        notes: list[str] = []
        for c, _run in runs("ProtectKeysWith"):
            notes.append(f"{c.name} at {c.file}:{c.line} is under a condition that could not be parsed, so it "
                         "may not run in Production")
        by_node = {id(c.node): c for c in pipe.calls}
        escapes = []
        for c, _run in runs("AddDataProtection"):
            why = _builder_escape(c, bodies, by_node)
            if why:
                escapes.append((c, why))
        notes += [f"{why} (AddDataProtection at {c.file}:{c.line})" for c, why in escapes]
        for c in pipe.unresolved():
            if (c.kind == "services" and c.name not in _NON_AUTHZ_EXTENSIONS and c.runs_in("Production") is not False
                    and not c.name.startswith(_DP_BUILDER)):
                notes.append(f"{c.name} at {c.file}:{c.line} is not resolved and may register a key protector")
        notes += pipe.notes
        persists = runs("PersistKeysTo")
        for c, run in persists:
            if (c.file, c.line) in seen:
                continue
            seen.add((c.file, c.line))
            desc = (f"{c.name}() stores the data-protection keys, which sign and encrypt cookies, antiforgery "
                    "tokens and other protected payloads, and no ProtectKeysWith* (certificate, DPAPI, DPAPI-NG "
                    "or Azure Key Vault) encrypts them at rest. Anyone who can read that store can forge or "
                    "decrypt those payloads; the keys are written as plain XML.")
            conf = None
            if run is None:
                conf = "REVIEW"
                desc += " The call sits under an environment condition that could not be parsed."
            if notes:
                conf = "REVIEW"
                desc += " Confirm that a protector is not registered elsewhere: " + "; ".join(notes) + "."
            ctx.add("DNL-CRY-009", "low", "Data-protection keys are stored without encryption at rest", desc,
                    c.file, c.line, confidence=conf)
        if not persists:
            for c, why in escapes:
                if (c.file, c.line) in seen:
                    continue
                seen.add((c.file, c.line))
                ctx.add("DNL-CRY-009", "low", "Data-protection key storage could not be read",
                        f"AddDataProtection() at {c.file}:{c.line}: {why}. Confirm the keys are not persisted to a "
                        "shared store without a ProtectKeysWith* protector.", c.file, c.line, confidence="REVIEW")


# (name, fn(ctx)) in run order; each fn appends to ctx.out.
_GROUPS: list = [("errors", _errors), ("transport", _transport), ("cors", _cors), ("inventory", _inventory),
                 ("data_protection", _data_protection),
                 ("cookies", rules_pipeline_auth.check_cookies),
                 ("antiforgery", rules_pipeline_auth.check_antiforgery),
                 ("tokens", rules_pipeline_auth.check_tokens),
                 ("identity", rules_pipeline_auth.check_identity),
                 ("secrets", rules_secrets_core.check),
                 ("limits", rules_limits_core.check)]


def check(model: ProjectModel, refs: list[CoreRouteRef]) -> list[Finding]:
    ctx: Ctx = build_ctx(model, refs)
    for name, fn in _GROUPS:
        try:
            fn(ctx)
        except Exception as exc:  # noqa: BLE001
            note = f"{name} failed ({type(exc).__name__}: {exc}); its findings are missing"
            if note not in model.notes:
                model.notes.append(note)
    return ctx.out
