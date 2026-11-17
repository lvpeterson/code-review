"""Aggregator of the ASP.NET Core configuration rules: builds the shared context once, then runs each
rule group in a fixed order. A group that crashes adds a model note (its findings are missing) and
never hides the others. Later tasks add their group to _GROUPS.
"""
from __future__ import annotations

import re

from checks.dnl.cfgctx import Ctx, build_ctx
from checks.dnl.ir import call_name, const_str, literal_str, receiver_text, walk
from checks.dnl.options import const, opt, options_of, verdict, walk_conditional
from checks.dnl.pipeline import PipeCall, Pipeline
from checks.dnl.project import ProjectModel
from checks.dnl.routes_core import CoreRouteRef
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


def _installs_handler(c: PipeCall) -> bool:
    """UseExceptionHandler, AddProblemDetails, or `Configure<ProblemDetailsOptions>` setting the customizer."""
    if c.name in ("UseExceptionHandler", "AddProblemDetails"):
        return True
    return (c.name == "Configure" and c.kind == "services"
            and opt(options_of(c.node), "CustomizeProblemDetails") is not None)


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
        if not _installs_handler(c):
            continue
        for line in _leak_sinks(_handler_args(c)):
            desc = ("The exception handler writes exception detail (Message, StackTrace or ToString) into the "
                    "response, which discloses internals to the client. Return a generic message and a trace "
                    "id, and log the detail.")
            if conf:
                desc += " The handler sits under an environment condition that could not be parsed."
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


# (name, fn(ctx)) in run order; each fn appends to ctx.out.
_GROUPS: list = [("errors", _errors), ("transport", _transport)]


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
