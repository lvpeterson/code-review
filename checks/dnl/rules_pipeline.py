"""Aggregator of the ASP.NET Core configuration rules: builds the shared context once, then runs each
rule group in a fixed order. A group that crashes adds a model note (its findings are missing) and
never hides the others. Later tasks add their group to _GROUPS.
"""
from __future__ import annotations

from checks.dnl.cfgctx import Ctx, build_ctx
from checks.dnl.ir import call_name, receiver_text, walk
from checks.dnl.options import const, opt, options_of
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
        o = opt(options_of(c.node), "DetailedErrors")
        if o is None:
            continue
        v = const(o.value)
        if v is False:
            continue
        if v is True:
            desc = "DetailedErrors = true sends exception detail to the browser; limit it to Development."
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


def _missing_handler(ctx: Ctx, pipe: Pipeline, add) -> None:
    if pipe.style == "none" or not _web_pipeline(pipe):
        return
    if any(_is_handler(c.name) for c in pipe.named(kinds=("app",))):
        return
    if pipe.named("UseDeveloperExceptionPage"):
        return  # a developer page that certainly runs is the handler; DNL-CFG-008 reports it
    first = next((c for c in pipe.calls if c.kind in ("app", "endpoints")), None)
    if first is not None:
        file, line = first.file, first.line
    else:
        file, line = (pipe.entries[0][0].file, pipe.entries[0][1].line) if pipe.entries else ("", 0)
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


# (name, fn(ctx)) in run order; each fn appends to ctx.out.
_GROUPS: list = [("errors", _errors)]


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
