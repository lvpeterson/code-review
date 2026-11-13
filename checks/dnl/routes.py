"""Route discovery for ASP.NET MVC 5 and Web API 2 controllers.

Routes come from attribute routing ([RoutePrefix]/[Route]) or from the
conventional templates registered in RouteConfig / WebApiConfig / area
registrations. Auth is deliberately not resolved here (see the auth task);
only the explicit [AllowAnonymous] marker is carried onto the route.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from checks.dnl.files import iter_dnl_files, read_source, resolve_ci
from checks.dnl.ir import MethodIR, TypeIR, attr_key, call_name, const_str, has_attr, literal_str, receiver_text, walk
from checks.dnl.project import Project, ProjectModel
from checks.dnl.webconfig import load_configs

SITE = "(site)"
from core.models import Route

_CONTROLLER_BASES = {"Controller", "AsyncController", "ApiController"}
_VERB_ATTRS = {f"http{v}".lower(): v.upper() for v in ("Get", "Post", "Put", "Delete", "Patch", "Head", "Options")}
_NAME_PREFIXES = ("Get", "Post", "Put", "Delete", "Patch", "Head", "Options")
_DEFAULT_MVC = "{controller}/{action}/{id}"
_DEFAULT_API = "api/{controller}/{id}"
# `{year:int}` -> `{year}`, `{id:int?}` -> `{id?}`, `{id=5}` -> `{id}`; tolerates `{n}` quantifiers inside regex constraints.
_CONSTRAINT = re.compile(r"\{(\*?\w+)(?::(?:[^{}]|\{[^{}]*\})*?)?(?:=[^{}]*)?(\??)\}")
_AREA_NS = re.compile(r"(?:^|\.)Areas\.([^.]+)(?:\.|$)", re.IGNORECASE)


@dataclass
class RouteRef:
    route: Route
    # None for a WebForms page whose code-behind could not be found.
    type: TypeIR | None
    method: MethodIR | None
    project: Project | None


def _call_template(call: dict, named_key: str) -> str | None:
    """Template argument of a MapRoute-style call: named `named_key`, else 2nd positional."""
    named = call.get("named") or {}
    for k, v in named.items():
        if k.lower() == named_key:
            return literal_str(v)
    args = call.get("args") or []
    return literal_str(args[1]) if len(args) > 1 else None


def _calls(t: TypeIR, name: str):
    """(receiver text, call expr) for every call named `name` in the type's methods."""
    for m in t.methods:
        for n in walk(m.body):
            # Case-insensitive: VB `routes.maproute(...)` is the same call.
            if n.get("k") == "call" and (call_name(n) or "").lower() == name.lower():
                fn = n.get("fn") or {}
                yield receiver_text(fn.get("obj")) if fn.get("k") == "member" else "", n


def _first_mvc_template(model: ProjectModel) -> str:
    for t in model.types():
        if model.derives_from(t, {"AreaRegistration"}):
            continue  # area registrations never define the global template, whatever the parameter is named
        for recv, c in _calls(t, "MapRoute"):
            url = _call_template(c, "url")
            if recv.lower() != "context" and url and "{controller}" in url and "{action}" in url:
                return url
    return _DEFAULT_MVC


def _first_api_template(model: ProjectModel) -> str:
    for t in model.types():
        for _, c in _calls(t, "MapHttpRoute"):
            url = _call_template(c, "routetemplate")
            if url:
                return url
    return _DEFAULT_API


def _area_template(model: ProjectModel, area: str) -> str:
    for t in model.types():
        if not model.derives_from(t, {"AreaRegistration"}):
            continue
        for _, c in _calls(t, "MapRoute"):
            url = _call_template(c, "url")
            if url and url.lower().startswith(area.lower() + "/"):
                return url
    return f"{area}/{{controller}}/{{action}}/{{id}}"


def _verbs(m: MethodIR, is_api: bool) -> list[str]:
    verbs: list[str] = []
    for a in m.attributes:
        low = attr_key(a.name)
        if low in _VERB_ATTRS:
            verbs.append(_VERB_ATTRS[low])
        elif low == "acceptverbs":
            # "GET" literals and HttpVerbs.Get members, also inside `Get | Post` / `Get Or Post`.
            for n in walk(a.args):
                s = literal_str(n) or (n.get("name") if n.get("k") == "member" else None)
                if s:
                    verbs.extend(v.strip().upper() for v in str(s).split(",") if v.strip())
    if verbs:
        return list(dict.fromkeys(verbs))
    if is_api:
        for p in _NAME_PREFIXES:
            if m.name.lower().startswith(p.lower()):
                return [p.upper()]
        return ["POST"]
    return ["GET", "POST"]


def _attr_template(a) -> str:
    return (const_str(a.args[0]) if a.args else None) or ""


def _strip_constraints(path: str) -> str:
    return _CONSTRAINT.sub(lambda mo: "{" + mo.group(1) + mo.group(2) + "}", path)


def _attribute_paths(t: TypeIR, m: MethodIR) -> list[str]:
    """Paths from [RoutePrefix]/[Route] (one per stacked [Route]); empty when no attribute route applies."""
    prefix_attr = has_attr(t.attributes, "RoutePrefix")
    prefix = _attr_template(prefix_attr).strip("/") if prefix_attr else ""
    action_routes = [a for a in m.attributes if attr_key(a.name) == "route"]
    class_routes = [a for a in t.attributes if attr_key(a.name) == "route"]
    out = []
    for a in action_routes:
        tmpl = _attr_template(a)
        parts = [tmpl[2:].strip("/")] if tmpl.startswith("~/") else [prefix, tmpl.strip("/")]
        out.append(parts)
    if not out:
        out = [[_attr_template(a).strip("/")] for a in class_routes[:1]]
    return [_strip_constraints("/" + "/".join(p for p in parts if p)) for parts in out]


def _conventional_path(template: str, t: TypeIR, m: MethodIR) -> str:
    controller = t.name.split(".")[-1]
    controller = controller[: -len("Controller")] if controller.lower().endswith("controller") else controller
    out = template.replace("{controller}", controller).replace("{action}", m.name)
    return "/" + out.lstrip("/")


def _is_action_shape(m: MethodIR, is_vb: bool, allow_override: bool = False) -> bool:
    """Public, non-static, not [NonAction] (and not an override unless allowed)."""
    mods = {x.lower() for x in m.modifiers}
    # VB members with no access modifier are Public (C# ones are private).
    public = "public" in mods or (is_vb and not mods & {"private", "protected", "internal", "friend"})
    if not public or "static" in mods or "shared" in mods or m.name == ".ctor" or has_attr(m.attributes, "NonAction"):
        return False
    return allow_override or not mods & {"override", "overrides"}


def _action_candidates(model: ProjectModel, t: TypeIR) -> list[tuple[MethodIR, TypeIR]]:
    """(method, declaring type) for each action of the controller, walking from the
    concrete type up through its project base types (nearest first), so actions
    inherited from an abstract / generic base controller are routed under the
    concrete controller. The most-derived declaration of a name decides: if it is
    an action it is the one routed (even when it is an `override` in an
    intermediate base), and if it is not (non-public, static, [NonAction], a
    framework override such as Dispose) the name is closed and farther
    declarations are not routed either. An `override` counts as an action only
    when a project base type declares the same name as a public instance method
    (unlike a framework override such as Dispose / OnActionExecuting)."""
    chain = [t]
    for b in model.base_chain(t):
        chain.extend(bt for bt in model.find_types(b) if bt is not t)
    inherited: set[str] = set()
    for bt in chain[1:]:
        is_vb = model.files[bt.file].language == "vb"
        inherited.update(m.name.lower() for m in bt.methods if _is_action_shape(m, is_vb))
    out: list[tuple[MethodIR, TypeIR]] = []
    seen: set[str] = set()
    for dt in chain:
        is_vb = model.files[dt.file].language == "vb"
        out.extend((m, dt) for m in dt.methods
                   if m.name.lower() not in seen and _is_action_shape(m, is_vb, allow_override=m.name.lower() in inherited))
        seen.update(m.name.lower() for m in dt.methods)
    return out


def discover_mvc_webapi(model: ProjectModel) -> list[RouteRef]:
    mvc_tmpl = _first_mvc_template(model)
    api_tmpl = _first_api_template(model)
    area_tmpls: dict[str, str] = {}
    refs: list[RouteRef] = []
    for t in model.types():
        simple = t.name.split(".")[-1]
        if t.kind != "class" or {"abstract", "mustinherit"} & {x.lower() for x in t.modifiers} or not simple.lower().endswith("controller"):
            continue
        if not model.derives_from(t, _CONTROLLER_BASES):
            continue
        is_api = any(b.lower() == "apicontroller" for b in model.base_chain(t))
        area = None if is_api else _AREA_NS.search(t.namespace)
        if area:
            tmpl = area_tmpls.setdefault(area.group(1), _area_template(model, area.group(1)))
        else:
            tmpl = api_tmpl if is_api else mvc_tmpl
        proj = model.project_of(t.file)
        class_anon = has_attr(t.attributes, "AllowAnonymous")
        for m, decl in _action_candidates(model, t):
            for path in _attribute_paths(t, m) or [_conventional_path(tmpl, t, m)]:
                route = Route(
                    path=path, methods=_verbs(m, is_api), handler_name=f"{simple}.{m.name}",
                    file=decl.file, line=m.line, source_start_line=m.line, source_end_line=m.end_line,
                    explicit_access="PermitAll" if class_anon or has_attr(m.attributes, "AllowAnonymous") else None,
                    meta={"kind": "webapi" if is_api else "mvc", "api_surface": is_api, "controller": t.full_name},
                )
                refs.append(RouteRef(route, t, m, proj))
    return refs


# -- WebForms -------------------------------------------------------------

# `<%@ Page Language="VB" Inherits='X' ... %>`: the directive may span lines and quote with ' or ".
_DIRECTIVE = re.compile(r"<%@\s*(page|webservice|servicehost)\b(.*?)%>", re.IGNORECASE | re.DOTALL)
_DIRECTIVE_ATTR = re.compile(r"""([\w:.-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def _directive_attrs(text: str) -> dict[str, str]:
    """Lowercased attribute map of the first Page/WebService/ServiceHost directive (empty when none)."""
    m = _DIRECTIVE.search(text)
    if not m:
        return {}
    return {k.lower(): (v1 or v2).strip() for k, v1, v2 in _DIRECTIVE_ATTR.findall(m.group(2))}


def _page_type(model: ProjectModel, proj: Project, name: str) -> TypeIR | None:
    """Type named by an Inherits/Class value, retrying without the VB RootNamespace prefix
    (VB adds it implicitly, so `Inherits="WebApp.Orders"` names a class declared as `Orders`)."""
    t = _page_type_named(model, proj, name)
    rootns = proj.root_namespace
    if t is None and proj.language == "vb" and rootns and name.lower().startswith(rootns.lower() + "."):
        t = _page_type_named(model, proj, name[len(rootns) + 1:])
    return t


def _page_type_named(model: ProjectModel, proj: Project, name: str) -> TypeIR | None:
    """Type named by an Inherits/Class value: full name first, then simple name, case-insensitive.
    Partial classes yield several TypeIRs; prefer one in the page's own project."""
    cands = model.find_types(name.split(".")[-1])
    exact = ([t for t in cands if t.full_name.lower() == name.lower()]
             or [t for t in cands if "." not in name or t.full_name.lower().endswith("." + name.lower())])
    inproj = [t for t in exact if model.project_of(t.file) is proj]
    pick = inproj or exact
    # The class body (not a designer stub) is the one with methods.
    return max(pick, key=lambda t: len(t.methods), default=None)


def _owner(project_dirs: list[tuple[Project, Path]], f: Path) -> Project | None:
    """Deepest project dir containing the file (nested projects own their own pages).
    `project_dirs` pairs each project with its pre-resolved dir."""
    best: tuple[Project, Path] | None = None
    rf = f.resolve()
    for p, d in project_dirs:
        if rf.is_relative_to(d) and (best is None or len(d.parts) > len(best[1].parts)):
            best = (p, d)
    return best[0] if best else None


def _site_dir(root: Path, page: Path) -> Path:
    """App dir of a page outside every project: the nearest ancestor (up to the scan
    root) holding a web.config, else the scan root."""
    cur, top = page.parent.resolve(), root.resolve()
    while True:
        if any(c.name.lower() == "web.config" for c in cur.iterdir() if c.is_file()):
            return cur
        if cur == top or top not in cur.parents:
            return top
        cur = cur.parent


def _webform_pages(model: ProjectModel, exts: tuple[str, ...] = (".aspx", ".asmx")) -> list[tuple[Path, Project]]:
    """(page file, owning project) for every file with one of `exts`. A WebForms Web Site has
    no .csproj/.vbproj, so pages no project owns get a pathless "(site)" project
    rooted at their app dir (see _site_dir)."""
    projects = [p for p in model.projects if p.path is not None]
    project_dirs = [(p, p.dir.resolve()) for p in projects]
    pages: list[tuple[Path, Project]] = []
    for proj in projects:
        for f in iter_dnl_files(proj.dir, exts):
            if _owner(project_dirs, f) is proj:
                pages.append((f, proj))
    sites: dict[Path, Project] = {}
    for f in iter_dnl_files(model.root, exts):
        if _owner(project_dirs, f) is None:
            d = _site_dir(model.root, f)
            pages.append((f, sites.setdefault(d, Project(name=SITE, path=None, language="cs", dir=d))))
    return pages


def webforms_site_dirs(model: ProjectModel) -> set[Path]:
    """App dirs of the project-less WebForms sites in the scan."""
    return {p.dir for _, p in _webform_pages(model) if p.name == SITE}


def discover_webforms(model: ProjectModel) -> list[RouteRef]:
    """One route per .aspx/.asmx (.ascx user controls are not routable)."""
    refs: list[RouteRef] = []
    for f, proj in _webform_pages(model):
        attrs = _directive_attrs(read_source(f))
        t = None
        for key in ("inherits", "class"):
            if attrs.get(key):
                t = _page_type(model, proj, attrs[key])
                if t is not None:
                    break
        if t is None:
            # CodeBehind/CodeFile is relative to the page; spelling may differ from disk.
            for key in ("codebehind", "codefile"):
                cb = resolve_ci(f.parent, attrs[key]) if attrs.get(key) else None
                if cb is not None:
                    t = next((x for x in model.types() if x.file == model.rel(cb) and x.kind == "class"), None)
                    if t is not None:
                        break
        rel_page = f.resolve().relative_to(proj.dir.resolve()).as_posix()
        cb_rel = ""
        if t is not None:
            abs_t = Path(model.root, t.file).resolve()
            cb_rel = (abs_t.relative_to(proj.dir.resolve()).as_posix()
                      if abs_t.is_relative_to(proj.dir.resolve()) else t.file)
        route = Route(
            path="/" + rel_page, methods=["GET", "POST"],
            handler_name=t.name.split(".")[-1] if t is not None else f.name,
            file=model.rel(f), line=1,
            source_file=t.file if t is not None else None,
            source_start_line=t.line if t is not None else None,
            source_end_line=t.end_line if t is not None else None,
            meta={"kind": "webforms", "api_surface": f.suffix.lower() == ".asmx", "codebehind": cb_rel},
        )
        refs.append(RouteRef(route, t, None, proj))
    return refs


# -- WCF ------------------------------------------------------------------

def _wcf_contracts(model: ProjectModel, t: TypeIR) -> list[TypeIR]:
    """Types carrying [ServiceContract] that the service type implements: the type
    itself, its project base types and every project interface along the base chain."""
    cands = [t] + [bt for b in model.base_chain(t) for bt in model.find_types(b)]
    out: list[TypeIR] = []
    for c in cands:
        if has_attr(c.attributes, "ServiceContract") and all(c is not o for o in out):
            out.append(c)
    return out


def _simple_type(tn: str | None) -> str:
    return (tn or "").replace(" ", "").split(".")[-1].lower()


def _wcf_impl(model: ProjectModel, t: TypeIR, contract: TypeIR, op: MethodIR) -> tuple[str, TypeIR | None, MethodIR | None]:
    """The method implementing contract operation `op` on service type `t`, as
    (status, declaring type, method); status is ok / none / ambiguous. An explicit
    `Implements IFoo.Bar` / `T IFoo.Bar()` naming this contract wins; otherwise same name,
    arity and parameter type names, nearest type in the base chain first. Overloads are never
    guessed between: an ambiguous match yields no method."""
    chain = [t] + [bt for b in model.base_chain(t) for bt in model.find_types(b) if bt.kind != "interface"]
    op_sig = [_simple_type(p.type) for p in op.params]
    cname, oname = contract.name.split(".")[-1].lower(), op.name.lower()

    def explicit(m: MethodIR) -> bool:
        for target in m.implements:
            qual, _, member = target.rpartition(".")
            if member.lower() == oname and qual.split(".")[-1].split("<")[0].lower() == cname:
                return True
        return False

    for c in chain:
        hit = [m for m in c.methods if explicit(m)]
        if hit:
            return ("ok", c, hit[0]) if len(hit) == 1 else ("ambiguous", None, None)
    for c in chain:
        hit = [m for m in c.methods if m.name.lower() == oname and not m.implements
               and [_simple_type(p.type) for p in m.params] == op_sig]
        if hit:
            return ("ok", c, hit[0]) if len(hit) == 1 else ("ambiguous", None, None)
    return "none", None, None


def _op_name(op: MethodIR) -> str:
    """OperationContract(Name = "X") wins over the method name."""
    a = has_attr(op.attributes, "OperationContract")
    for k, v in ((a.named if a else None) or {}).items():
        if k.lower() == "name" and literal_str(v):
            return literal_str(v)
    return op.name


def _wcf_services(model: ProjectModel) -> list[tuple[str, str, str | None, str, Project]]:
    """(svc path relative to its project, Service value, Factory value, source rel, project)
    for every .svc file and every <serviceActivations><add> entry."""
    out: list[tuple[str, str, str | None, str, Project]] = []
    for f, proj in _webform_pages(model, (".svc",)):
        attrs = _directive_attrs(read_source(f))
        out.append((f.resolve().relative_to(proj.dir.resolve()).as_posix(), attrs.get("service", ""),
                    attrs.get("factory"), model.rel(f), proj))
    projects = [p for p in model.projects if p.path is not None]
    project_dirs = [(p, p.dir.resolve()) for p in projects]
    sites: dict[Path, Project] = {}
    for cfg in load_configs(model.root):
        if cfg.root is None or cfg.is_views:
            continue
        proj = _owner(project_dirs, cfg.path)
        if proj is None:
            d = _site_dir(model.root, cfg.path)
            proj = sites.setdefault(d, Project(name=SITE, path=None, language="cs", dir=d))
        for sa in cfg.root.iter("serviceActivations"):
            for add in sa.findall("add"):
                addr = add.get("relativeAddress")
                if not addr or not add.get("service"):
                    continue
                rel = addr.replace("\\", "/")
                while rel.startswith(("~/", "./")):
                    rel = rel[2:]
                out.append((rel.lstrip("/"), add.get("service"), None, cfg.rel, proj))
    return out


def _note(model: ProjectModel, text: str) -> None:
    # The set shadows the list so the dedupe stays O(1) however many notes a scan collects.
    seen = model.cache.setdefault("wcf_note_set", set())
    if text not in seen:
        seen.add(text)
        model.notes.append(text)


def _op_list_note(src: str, cname: str, ops: list[str], one: str, many: str) -> str:
    """One note for several operations of a contract: a single operation keeps its own wording, 2-3 are
    listed, more show the first three."""
    if len(ops) == 1:
        return f"{src}: operation {ops[0]} {one}"
    shown = ", ".join(ops[:3])
    return f"{src}: {len(ops)} operations of {cname} {many} ({shown if len(ops) <= 3 else 'first: ' + shown})"


# Framework / BCL interfaces a service may implement without carrying operations: no missing-contract note.
_FRAMEWORK_IFACES = {"idisposable", "iextensibleobject", "icommunicationobject", "ierrorhandler",
                     "iservicebehavior", "iendpointbehavior", "icontractbehavior", "ioperationbehavior",
                     "idispatchmessageinspector", "iclientmessageinspector", "iparameterinspector",
                     "iequatable", "icomparable", "iserializable"}


def discover_wcf(model: ProjectModel) -> list[RouteRef]:
    """One route per [OperationContract] of every WCF service hosted by a .svc file or a
    <serviceActivations> entry. Anything the model cannot resolve (service type, contract,
    implementation, overload) is noted on the model, never silently dropped."""
    refs: list[RouteRef] = []
    seen: set[tuple[str, str, str]] = set()
    for svc, service, factory, src, proj in _wcf_services(model):
        t = _page_type(model, proj, service) if service else None
        if t is None or t.kind != "class":
            why = f"Factory={factory}" if factory else f"Service={service}"
            _note(model, f"{src}: WCF service type not resolved ({why})")
            continue
        simple = t.name.split(".")[-1]
        contracts = _wcf_contracts(model, t)
        # Every interface of the service the model cannot resolve may carry operations: note each one.
        missing = [b for b in model.base_chain(t) if not model.find_types(b)
                   and re.match(r"I[A-Z]", b.split(".")[-1]) and b.split(".")[-1].lower() not in _FRAMEWORK_IFACES]
        for b in missing:
            _note(model, f"{src}: contract {b} not found in the scanned sources")
        if not contracts and not missing:
            _note(model, f"{src}: no [ServiceContract] contract found for {simple}")
        local: set[tuple[str, str]] = set()
        # (contract simple name, status) -> operations, flushed as one note per contract and kind.
        failed: dict[tuple[str, str], list[str]] = {}
        for contract in contracts:
            for op in contract.methods:
                if not has_attr(op.attributes, "OperationContract"):
                    continue
                name = _op_name(op)
                key = (svc, contract.full_name.lower(), name.lower())
                if (key[1], key[2]) in local:
                    _note(model, f"{src}: operation {contract.name.split('.')[-1]}.{op.name} repeats the "
                                 f"operation name {name}; the duplicate is not routed")
                    continue
                local.add((key[1], key[2]))
                if key in seen:
                    continue
                seen.add(key)
                status, decl, m = _wcf_impl(model, t, contract, op)
                if status != "ok":
                    cn = contract.name.split(".")[-1]
                    failed.setdefault((cn, status), []).append(f"{cn}.{op.name}")
                    continue
                route = Route(
                    path=f"/{svc}/{name}", methods=["POST"], handler_name=f"{simple}.{m.name}",
                    file=decl.file, line=m.line, source_start_line=m.line, source_end_line=m.end_line,
                    meta={"kind": "wcf", "api_surface": True, "contract": contract.full_name, "svc": svc},
                )
                refs.append(RouteRef(route, t, m, proj))
        for (cn, status), ops in failed.items():
            if status == "none":
                _note(model, _op_list_note(src, cn, ops, "has no implementation in the scanned sources",
                                           "have no implementation in the scanned sources"))
            else:
                _note(model, _op_list_note(src, cn, ops, f"is ambiguous between overloads of {simple}; not routed",
                                           f"are ambiguous between overloads of {simple}; not routed"))
    return refs
