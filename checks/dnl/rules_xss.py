"""Template XSS (DNL-XSS-003) and request-validation bypass (DNL-XSS-004) findings.

XSS-003 looks at every unencoded output in the Razor / ASPX templates
(`templates.scan`). Proven (high): the expression reads the request directly, or
reads `ViewBag.X` / `ViewData["X"]` that the rendering action assigns a tainted
value to, or reads `Model.X` while the action's `View(model)` argument is tainted
(object-level: any tainted member of its initializer taints the whole model). The
action body is evaluated by the taint engine with its parameters treated as
request input, as the entry points are in taint_solver. Anything else with a
non-literal expression is reported for review (low, `confidence="REVIEW"`).
Literal-only and encoded outputs never fire, nor does a single allowlisted framework helper call
with constant arguments (`Url.Content("~/x")`, `Html.Partial("_Nav")`, `Scripts.Render(..)`).

XSS-004 flags the places request validation is switched off in code:
`[AllowHtml]` on a property of a type bound as an action parameter,
`[ValidateInput(false)]` on an action or controller, and any `Request.Unvalidated` read.
"""
from __future__ import annotations

import re
from pathlib import Path

from checks.dnl import taint, taint_solver, templates
from checks.dnl.files import iter_dnl_files
from checks.dnl.findings import dnl_finding
from checks.dnl.ir import has_attr, receiver_text, walk
from core.models import Finding

# `Request` read directly, optionally qualified by this / Me / Page / Context / HttpContext(.Current) /
# ViewContext.HttpContext (never `someVar.Request`).
_REQUEST_REF = re.compile(
    r"(?<![\w.])(?:(?:this|me|page|context|httpcontext(?:\s*\.\s*current)?|viewcontext\s*\.\s*httpcontext)\s*\.\s*)?"
    r"Request\s*[.\[(]", re.IGNORECASE)
_VIEWBAG = re.compile(r"\bViewBag\s*\.\s*(\w+)", re.IGNORECASE)
_VIEWDATA = re.compile(r"\bViewData\s*(?:\[\s*\"([^\"]+)\"\s*\]|\.\s*(\w+))", re.IGNORECASE)
_MODEL = re.compile(r"(?<![\w.])Model\b", re.IGNORECASE)
_IDENT = re.compile(r"[A-Za-z_]\w*")
_SEV = {"high": 2, "medium": 1, "low": 0}


def _tainted(t) -> bool:
    """A request source reaches the value and nothing cleansed it for XSS."""
    return (t is not None and "*" not in t.cleansed and "xss" not in t.cleansed
            and any(o.kind == "source" for o in t.origins))


def _first_source(t) -> str:
    srcs = sorted((o.detail for o in t.origins if o.kind == "source"))
    return srcs[0] if srcs else "request input"


class _Actions:
    """Taint results for MVC action bodies, evaluated once each."""

    def __init__(self, model):
        taint_solver.solve(model)
        self.model = model
        self.state = model.cache["taint"]
        self.owner = {id(m): t for t, m, _acc in taint_solver._all_methods(model)}
        self.cache: dict[int, object] = {}

    def result(self, ref):
        key = id(ref.method)
        if key not in self.cache:
            decl = self.owner.get(key, ref.type)
            ft = taint_solver._type_field_taint(self.model, decl, self.state["ft"])
            self.cache[key] = taint.analyze_method(
                self.model, decl, ref.method, param_taint=taint_solver._entry_taint(self.model, decl, ref.method),
                field_taint=ft, summaries=self.state["summaries"])
        return self.cache[key]


def _viewbag_taint(res, expr: str):
    """First tainted value among the ViewBag / ViewData keys the expression reads."""
    env = {k.lower(): v for k, v in res.env.items()}
    for mo in _VIEWBAG.finditer(expr):
        v = env.get(f"viewbag.{mo.group(1).lower()}")
        if _tainted(v):
            return v
    if _VIEWDATA.search(expr):
        # `ViewData["k"] = v` is tracked per dictionary, not per key.
        v = env.get("viewdata")
        if _tainted(v):
            return v
    return None


def _route_key(ref) -> tuple:
    rt = ref.route
    return (rt.handler_name, rt.path, rt.file, rt.line)


def _template_findings(model, refs) -> list[Finding]:
    view_refs: dict[Path, list] = {}
    page_refs: dict[str, object] = {}
    for ref in refs:
        if ref.route.meta.get("kind") == "webforms":
            page_refs.setdefault(ref.route.file, ref)
        else:
            for v in templates.views_for(model, ref):
                view_refs.setdefault(v.resolve(), []).append(ref)
    actions = _Actions(model)
    best: dict[tuple, tuple] = {}
    for f in iter_dnl_files(model.root, templates.TEMPLATE_EXT):
        rel = model.rel(f)
        linked = sorted(view_refs.get(f.resolve(), []), key=_route_key)
        page = page_refs.get(rel)
        for o in templates.scan(f, rel):
            if o.encoded or o.kind == "aspx_encoded" or templates.is_literal(o.expr) \
                    or templates.is_benign_helper(o.expr):
                continue
            label = "ASPX" if f.suffix.lower() in templates.ASPX_EXT else "Razor"
            proof = None       # (route ref or None, source description)
            if _REQUEST_REF.search(o.expr):
                proof = (linked[0] if linked else page, "request data read in the template")
            else:
                for ref in linked:
                    res = actions.result(ref)
                    v = _viewbag_taint(res, o.expr)
                    if v is not None:
                        proof = (ref, f"{_first_source(v)} via ViewBag/ViewData")
                        break
                    if _MODEL.search(o.expr) and _tainted(res.view_model):
                        proof = (ref, f"{_first_source(res.view_model)} via the view model")
                        break
            if proof is not None:
                ref, src = proof
                where = f" rendered by {ref.route.handler_name}" if ref is not None else ""
                text = (f"Cross-site scripting -- untrusted input reaches unencoded {label} output "
                        f"`{o.expr}` ({rel}:{o.line}){where}. Source: {src}.")
                row = ("high", None, ref, text)
            else:
                ref = linked[0] if linked else page
                text = (f"Cross-site scripting -- unencoded {label} output `{o.expr}` ({rel}:{o.line}) "
                        f"of unknown provenance -- verify the value is encoded or trusted.")
                row = ("low", "REVIEW", ref, text)
            key = (rel, o.line)
            cur = best.get(key)
            if cur is None or (_SEV[row[0]], row[1] is None) > (_SEV[cur[0]], cur[1] is None):
                best[key] = row
    out = []
    for (rel, line), (sev, conf, ref, text) in sorted(best.items()):
        route = ref.route if ref is not None else None
        out.append(dnl_finding("DNL-XSS-003", sev, "Cross-site scripting: unencoded template output", text, rel, line,
                               route=route, confidence=conf,
                               api_surface=bool(route.meta.get("api_surface", False)) if route else False))
    return out


# -- XSS-004 --------------------------------------------------------------

def _is_false(expr) -> bool:
    return isinstance(expr, dict) and expr.get("k") == "lit" and expr.get("v") is False


def _bound_types(model, refs) -> dict[str, object]:
    """Lowercased simple type name -> first route ref binding it, for every type used (directly or
    through property types, three levels deep) as the parameter of an MVC / Web API action."""
    bound: dict[str, object] = {}
    frontier: list[tuple[str, object]] = []
    for ref in sorted((r for r in refs if r.method is not None), key=_route_key):
        for p in ref.method.params:
            for tok in _IDENT.findall(p.type or ""):
                frontier.append((tok.lower(), ref))
    for _ in range(3):
        nxt: list[tuple[str, object]] = []
        for name, ref in frontier:
            if name in bound:
                continue
            bound[name] = ref
            for t in model.find_types(name):
                for pr in t.properties:
                    nxt.extend((tok.lower(), ref) for tok in _IDENT.findall(pr.type or ""))
        frontier = nxt
    return bound


def _validation_findings(model, refs) -> list[Finding]:
    out: list[Finding] = []
    seen: set[tuple] = set()
    by_method = {id(r.method): r for r in refs if r.method is not None}

    def add(file: str, line: int, kind: str, text: str, ref) -> None:
        if (file, line, kind) in seen:
            return
        seen.add((file, line, kind))
        route = ref.route if ref is not None else None
        out.append(dnl_finding("DNL-XSS-004", "medium", f"Request validation bypassed: {kind}", text, file, line,
                               route=route,
                               api_surface=bool(route.meta.get("api_surface", False)) if route else False))

    bound = _bound_types(model, refs)
    for t in model.types():
        simple = t.name.split(".")[-1]
        if t.kind in ("class", "struct") and simple.lower() in bound:
            for p in t.properties:
                if has_attr(p.attributes, "AllowHtml"):
                    ref = bound[simple.lower()]
                    add(t.file, p.line, "AllowHtml",
                        f"Request validation bypassed -- [AllowHtml] on {t.name}.{p.name} ({t.file}:{p.line}); "
                        f"{t.name} is bound by {ref.route.handler_name}, so markup in this field is not "
                        f"rejected -- encode it on output.", ref)
        controller_va = has_attr(t.attributes, "ValidateInput")
        if controller_va is not None and controller_va.args and _is_false(controller_va.args[0]):
            first = next(iter(sorted((r for r in refs if r.type is t), key=_route_key)), None)
            add(t.file, controller_va.line or t.line, "ValidateInput(false)",
                f"Request validation bypassed -- [ValidateInput(false)] on controller {t.name} "
                f"({t.file}:{controller_va.line or t.line}) disables request validation for all its actions.", first)
        bodies = [(m.name, m.line, m.body) for m in t.methods]
        bodies += [(f"{p.name}", p.line, (p.get or []) + (p.set or [])) for p in t.properties if p.get or p.set]
        for m in t.methods:
            va = has_attr(m.attributes, "ValidateInput")
            if va is not None and va.args and _is_false(va.args[0]):
                add(t.file, va.line or m.line, "ValidateInput(false)",
                    f"Request validation bypassed -- [ValidateInput(false)] on {t.name}.{m.name} "
                    f"({t.file}:{va.line or m.line}) disables request validation for this action.",
                    by_method.get(id(m)))
        for name, mline, body in bodies:
            m_obj = next((m for m in t.methods if m.name == name and m.line == mline), None)
            for n in walk(body):
                if n.get("k") == "member" and (n.get("name") or "").lower() == "unvalidated" \
                        and receiver_text(n.get("obj")).lower().endswith("request"):
                    line = n.get("line") or mline
                    add(t.file, line, "Request.Unvalidated",
                        f"Request validation bypassed -- Request.Unvalidated read in {t.name}.{name} "
                        f"({t.file}:{line}) returns raw request data that skips request validation.",
                        by_method.get(id(m_obj)) if m_obj is not None else None)
    return sorted(out, key=lambda f: (f.file, f.line, f.title))


def check(model, refs: list) -> list[Finding]:
    return _template_findings(model, refs) + _validation_findings(model, refs)
