"""Findings from the taint engine: the code-sink rules (SQL, Dynamic LINQ, command, LDAP, XPath, header,
XSS, path, redirect, SSRF and log injection).

`check` runs `taint_solver.entry_hits` and turns each row into a Finding, one per
(rule id, sink file, sink line). A proven hit (a request source reaches the sink,
`EntryHit.proven`) takes the table severity and, when an entry point reaches it,
that route. An unproven hit (the sink is fed only by its own method's parameters
and nothing in the solution passes untrusted data) is reported for review: one
severity level lower, `confidence="REVIEW"`, no route.
"""
from __future__ import annotations

from checks.dnl import taint_solver
from checks.dnl.findings import dnl_finding
from core.models import Finding

RULE_FOR_KIND = {
    "sql": "DNL-INJ-001", "linq": "DNL-INJ-006", "cmd": "DNL-INJ-002", "ldap": "DNL-INJ-003",
    "xpath": "DNL-INJ-004", "header": "DNL-INJ-005", "xss": "DNL-XSS-001", "path": "DNL-PATH-001",
    "redirect": "DNL-REDIR-001", "ssrf": "DNL-SSRF-001", "log": "DNL-LOG-001",
}
_SEVERITY = {
    "DNL-INJ-001": "high", "DNL-INJ-006": "high", "DNL-INJ-002": "high", "DNL-INJ-003": "high",
    "DNL-INJ-004": "medium", "DNL-INJ-005": "medium", "DNL-XSS-001": "high", "DNL-PATH-001": "high",
    "DNL-REDIR-001": "medium", "DNL-SSRF-001": "high", "DNL-LOG-001": "low",
}
_LABEL = {
    "sql": "SQL injection", "linq": "Dynamic LINQ injection", "cmd": "Command injection",
    "ldap": "LDAP injection", "xpath": "XPath injection", "header": "HTTP header injection",
    "xss": "Cross-site scripting", "path": "Path traversal", "redirect": "Open redirect",
    "ssrf": "Server-side request forgery", "log": "Log injection",
}
_LOWER = {"high": "medium", "medium": "low", "low": "info", "info": "info"}


def _param_name(model, method: str, line: int, index: str) -> str:
    """Name of parameter `index` of the `Type.Method` that contains `line`."""
    tname, _, mname = method.rpartition(".")
    for t in model.find_types(tname.split(".")[-1]) if tname else []:
        for m in t.methods:
            if m.name.lower() == mname.lower() and m.line <= line <= (m.end_line or m.line) and index.isdigit() \
                    and int(index) < len(m.params):
                return m.params[int(index)].name
    return f"#{index}"


def _path(h) -> str:
    chain = list(h.via)
    if not chain or chain[-1] != h.method:
        chain.append(h.method)
    return " -> ".join(chain)


def _proven_text(eh) -> str:
    h = eh.hit
    srcs = [o for o in eh.sources if o.kind == "source"] or list(eh.sources)
    first = srcs[0]
    more = f"; +{len(srcs) - 1} more" if len(srcs) > 1 else ""
    return (f"{_LABEL[h.kind]} -- untrusted input reaches {h.sink} ({h.file}:{h.line}) in {h.method}. "
            f"Source: {first.detail} ({first.file}:{first.line}){more}. Path: {_path(h)}.")


def _unproven_text(model, eh) -> str:
    h = eh.hit
    params = sorted((o.detail for o in h.taint.origins if o.kind == "param"), key=lambda d: (len(d), d))
    name = _param_name(model, h.method, h.line, params[0]) if params else "?"
    return (f"{_LABEL[h.kind]} -- untrusted input reaches {h.sink} ({h.file}:{h.line}) in {h.method} "
            f"from parameter '{name}' of {h.method}, and no caller passing untrusted data was found "
            f"-- verify how it is called.")


def _route_key(r) -> tuple:
    rt = r.ref.route
    return (rt.handler_name, rt.path, rt.file, rt.line)


def check(model, refs: list) -> list[Finding]:
    rows = [r for r in taint_solver.entry_hits(model, refs) if r.hit.kind in RULE_FOR_KIND]
    state = model.cache.get("taint", {})
    if state.get("converged") is False:
        note = (f"taint analysis stopped after {state.get('rounds')} rounds without converging; "
                "some deep flows may be missing")
        if note not in model.notes:
            model.notes.append(note)
    for key, text in (("truncated_methods", "{n} method(s) analysed partially (expression nesting too deep); "
                                            "some flows may be missing"),
                      ("failed_methods", "{n} method(s) could not be analysed (internal error); "
                                         "flows through them may be missing")):
        names = state.get(key) or []
        if names and text.format(n=len(names)) not in model.notes:
            model.notes.append(text.format(n=len(names)))
    # One finding per (rule, sink file, line); a proven row beats an unproven one, a routed one beats a
    # route-less one.
    # When several routes reach one sink, the first by (handler name, path, file, line) is named and
    # the rest are counted ("also reached from N more route(s)").
    best: dict[tuple, object] = {}
    routes_for: dict[tuple, set] = {}
    for r in rows:
        key = (RULE_FOR_KIND[r.hit.kind], r.hit.file, r.hit.line)
        if r.proven and r.ref is not None:
            routes_for.setdefault(key, set()).add(_route_key(r))
        cur = best.get(key)
        if cur is None or (r.proven, r.ref is not None) > (cur.proven, cur.ref is not None):
            best[key] = r
        elif ((r.proven, r.ref is not None) == (cur.proven, cur.ref is not None) and r.ref is not None
              and _route_key(r) < _route_key(cur)):
            best[key] = r
    out: list[Finding] = []
    for (rule, file, line), r in sorted(best.items(), key=lambda kv: (kv[0][1], kv[0][2], kv[0][0])):
        sev = _SEVERITY[rule]
        if r.proven:
            route = r.ref.route if r.ref is not None else None
            text = _proven_text(r)
            extra = len(routes_for.get((rule, file, line), ())) - 1
            if extra > 0:
                text += f"; also reached from {extra} more route(s)"
            out.append(dnl_finding(rule, sev, _LABEL[r.hit.kind], text, file, line, route=route,
                                   api_surface=bool(route.meta.get("api_surface", False)) if route else False))
        else:
            out.append(dnl_finding(rule, _LOWER[sev], _LABEL[r.hit.kind], _unproven_text(model, r), file, line,
                                   confidence="REVIEW"))
    return out
