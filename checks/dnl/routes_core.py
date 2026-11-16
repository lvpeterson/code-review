"""Route discovery for ASP.NET Core: controllers (attribute and conventional routing)
and Razor Pages.

Routes come from [Route]/[Http*] templates on the controller and its actions, or
from the conventional templates registered with MapControllerRoute /
MapDefaultControllerRoute / MapAreaControllerRoute. Auth is not resolved here;
each route carries the fluent calls chained on the mapping call (convention_calls)
so the auth pass can see `MapControllers().RequireAuthorization()`.

Partial classes: every declaration of a controller (same full name, same project)
is merged into one TypeIR before detection, so class attributes, [Route]/[Area], the
base list and the actions are the union of all halves. CoreRouteRef.type is that
merged TypeIR (attributes, bases and methods of every half; file/line of the first
declaration) and CoreRouteRef.partials lists the original declarations. A route's
route.file/line always point at the half that declares the action.

Razor Pages: a .cshtml under Pages/ or Areas/<A>/Pages/ with @page first is a page; its
PageModel is found by @model name (page namespace, then @using, via _ViewImports) and each
On<Verb><Handler> method is one route. A page whose model is missing is one GET route with
unknown set. meta["page"] is the page name conventions use (/Admin/Index), not the routed path.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.ir import MethodIR, TypeIR, attr_key, call_name, const_str, has_attr, literal_str
from checks.dnl.pipeline import PipeCall, pipeline_for
from checks.dnl.project import ProjectModel
from checks.dnl.routes import RouteRef, action_candidates, strip_constraints
from core.models import Route

_MAP_NAMES = ("MapControllers", "MapControllerRoute", "MapDefaultControllerRoute", "MapAreaControllerRoute")
_DEFAULT_TEMPLATE = "{controller=Home}/{action=Index}/{id?}"
_DEFAULT_AREA_TEMPLATE = "{area}/{controller}/{action}/{id?}"
_VERB_ATTRS = {f"http{v}": v.upper() for v in ("get", "post", "put", "delete", "patch", "head", "options")}
_CONTROLLER_BASES = {"controllerbase", "controller"}
# `{controller=Home}`, `{action:regex(..)=Index?}`, `{area:exists}`: the token with its constraint / default.
_ROUTE_TOKEN = re.compile(r"\{(controller|action|area)(?::(?:[^{}]|\{[^{}]*\})*?)?(?:=[^{}]*)?\??\}", re.IGNORECASE)
_ATTR_TOKEN = re.compile(r"\[(controller|action|area)\]", re.IGNORECASE)


@dataclass
class Group:
    prefix: str
    calls: list[dict]        # fluent calls applied to the group (RequireAuthorization, AllowAnonymous, AddEndpointFilter, ...)
    file: str
    line: int


@dataclass
class CoreRouteRef(RouteRef):
    style: str = "controller"                  # "controller" | "razorpage" | "minimalapi" | "endpoint"
    endpoint_calls: list[dict] = field(default_factory=list)
    groups: list[Group] = field(default_factory=list)       # outermost first
    convention_calls: list[dict] = field(default_factory=list)  # chain on MapControllers()/MapControllerRoute()/MapRazorPages()
    caller_unknown: bool = False
    unknown: list[str] = field(default_factory=list)        # discovery-time reasons auth may be incomplete
    partials: list[TypeIR] = field(default_factory=list)    # every declaration merged into `type`


def _simple(name: str) -> str:
    return name.split("<")[0].split(".")[-1].lower()


def _declarations(model: ProjectModel, t: TypeIR) -> list[TypeIR]:
    """All declarations of a (partial) type: same full name, same project."""
    proj = model.project_of(t.file)
    out = [d for d in model.find_types(t.name.split(".")[-1])
           if d.full_name.lower() == t.full_name.lower() and model.project_of(d.file) is proj]
    return out or [t]


def _merged(decls: list[TypeIR]) -> TypeIR:
    """One TypeIR holding the union of the declarations' modifiers, bases, attributes and members."""
    if len(decls) == 1:
        return decls[0]
    def uniq(xs):
        return list(dict.fromkeys(xs))
    first = decls[0]
    return replace(
        first,
        modifiers=uniq(m for d in decls for m in d.modifiers),
        bases=uniq(b for d in decls for b in d.bases),
        attributes=[a for d in decls for a in d.attributes],
        fields=[f for d in decls for f in d.fields],
        properties=[p for d in decls for p in d.properties],
        methods=[m for d in decls for m in d.methods],
        end_line=max(d.end_line for d in decls),
    )


def _chain_types(model: ProjectModel, t: TypeIR) -> list[TypeIR]:
    """The (merged) type then its project base types, nearest first (external bases are not types)."""
    out = [t]
    seen = {t.full_name.lower()}
    for b in model.base_chain(t):
        for bt in model.find_types(b):
            if bt.full_name.lower() not in seen:
                decls = _declarations(model, bt)
                seen.add(bt.full_name.lower())
                out.append(_merged(decls))
    return out


def _inherited(chain: list[TypeIR], *names: str) -> list:
    """Attributes named `names` on the nearest type of the chain that carries any (they are inherited)."""
    wanted = {attr_key(n) for n in names}
    for ct in chain:
        hit = [a for a in ct.attributes if attr_key(a.name) in wanted]
        if hit:
            return hit
    return []


def _is_controller(model: ProjectModel, t: TypeIR, chain: list[TypeIR]) -> bool:
    mods = {x.lower() for x in t.modifiers}
    if t.kind != "class" or "public" not in mods or "abstract" in mods or "<" in t.name:
        return False
    if any(has_attr(ct.attributes, "NonController") for ct in chain):
        return False
    bases = {_simple(b) for b in model.base_chain(t)}
    return bool(bases & _CONTROLLER_BASES
                or any(has_attr(ct.attributes, "ApiController", "Controller") for ct in chain)
                or t.name.split(".")[-1].lower().endswith("controller"))


def _api_surface(model: ProjectModel, t: TypeIR, chain: list[TypeIR]) -> bool:
    if any(has_attr(ct.attributes, "ApiController") for ct in chain):
        return True
    bases = {_simple(b) for b in model.base_chain(t)}
    return "controllerbase" in bases and "controller" not in bases


def _controller_name(t: TypeIR) -> str:
    n = t.name.split(".")[-1]
    return n[: -len("Controller")] if n.lower().endswith("controller") and len(n) > len("controller") else n


def _action_name(m: MethodIR) -> str:
    # SuppressAsyncSuffixInActionNames defaults to true: `GetAsync` is routed as `Get`.
    return m.name[: -len("Async")] if m.name.endswith("Async") and len(m.name) > len("Async") else m.name


def _area(chain: list[TypeIR]) -> str | None:
    for a in _inherited(chain, "Area"):
        v = const_str(a.args[0]) if a.args else None
        if v:
            return v
    return None


def _template(a, named_key: str = "template") -> str | None:
    """Template of a Route/Http* attribute: first positional (or the named key), None when absent."""
    if a.args:
        return const_str(a.args[0])
    for k, v in (a.named or {}).items():
        if k.lower() == named_key:
            return const_str(v)
    return None


def _verb_names(a) -> list[str]:
    """Verbs of an AcceptVerbs attribute: "GET" literals and HttpVerbs.Get-style members."""
    out: list[str] = []
    for x in a.args:
        s = literal_str(x) or (x.get("name") if isinstance(x, dict) and x.get("k") == "member" else "")
        out.extend(v.strip().upper() for v in str(s or "").split(",") if v.strip())
    return out


def _selectors(m: MethodIR) -> list[tuple[str | None, list[str] | None]]:
    """(template, verbs) per route-providing attribute of the action. A verb attribute without a
    template only adds its verb to the template-bearing attributes that name none (Route)."""
    templated: list[tuple[str, list[str] | None]] = []
    bare_verbs: list[str] = []
    for a in m.attributes:
        key = attr_key(a.name)
        if key in _VERB_ATTRS:
            t = _template(a)
            if t is None:
                bare_verbs.append(_VERB_ATTRS[key])
            else:
                templated.append((t, [_VERB_ATTRS[key]]))
        elif key == "acceptverbs":
            verbs = _verb_names(a)
            t = next((const_str(v) for k, v in (a.named or {}).items() if k.lower() == "route"), None)
            if t is None:
                bare_verbs.extend(verbs)
            else:
                templated.append((t, verbs or None))
        elif key == "route":
            t = _template(a)
            if t is not None:
                templated.append((t, None))
    bare = list(dict.fromkeys(bare_verbs)) or None
    if templated:
        return [(t, v or bare) for t, v in templated]
    return [(None, bare)]


def _join(*parts: str) -> str:
    return "/" + "/".join(p.strip("/") for p in parts if p and p.strip("/"))


def _attribute_paths(class_tmpls: list[str], sel_tmpl: str | None) -> list[str] | None:
    """Raw (token-bearing) paths of one selector; None when the selector is conventionally routed."""
    if sel_tmpl is not None and (sel_tmpl.startswith("~/") or sel_tmpl.startswith("/")):
        return [sel_tmpl.lstrip("~").lstrip("/")]  # overrides the class templates
    if class_tmpls:
        return [_join(c, sel_tmpl or "") for c in class_tmpls]
    return [sel_tmpl] if sel_tmpl is not None else None


def _attribute_path(raw: str, controller: str, action: str, area: str | None) -> str:
    vals = {"controller": controller, "action": action, "area": area or ""}
    return strip_constraints(_join(_ATTR_TOKEN.sub(lambda mo: vals[mo.group(1).lower()], raw)))


def _conventional_path(template: str, controller: str, action: str, area: str | None) -> str:
    # Defaults on the tokens ({controller=Home}) are consumed by the substitution (ruling R2).
    vals = {"controller": controller, "action": action, "area": area or ""}
    out = _ROUTE_TOKEN.sub(lambda mo: vals[mo.group(1).lower()], template)
    return strip_constraints(_join(out))


@dataclass
class _Mapping:
    name: str
    template: str | None     # None for MapControllers or a non-literal pattern
    area: str | None         # MapAreaControllerRoute's area name
    call: PipeCall
    unresolved_pattern: bool = False


def _arg(call: dict, idx: int, *named: str):
    for k, v in (call.get("named") or {}).items():
        if k.lower() in named:
            return v
    args = call.get("args") or []
    return args[idx] if len(args) > idx else None


def _mappings(calls: list[PipeCall]) -> list[_Mapping]:
    out: list[_Mapping] = []
    for c in calls:
        n = c.node
        if c.name == "MapControllers":
            out.append(_Mapping(c.name, None, None, c))
        elif c.name == "MapDefaultControllerRoute":
            out.append(_Mapping(c.name, _DEFAULT_TEMPLATE, None, c))
        elif c.name == "MapControllerRoute":
            p = const_str(_arg(n, 1, "pattern"))
            out.append(_Mapping(c.name, p, None, c, p is None))
        elif c.name == "MapAreaControllerRoute":
            p = const_str(_arg(n, 2, "pattern"))
            out.append(_Mapping(c.name, p, const_str(_arg(n, 1, "areaname")), c, p is None))
    return out


def _tail(call: PipeCall) -> list[dict]:
    """Fluent links after the mapping call itself."""
    for i, link in enumerate(call.chain):
        if link is call.node:
            return list(call.chain[i + 1:])
    return []


def _link_sig(link: dict) -> str:
    """Identity of a fluent link: name and arguments, ignoring source positions."""
    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k not in ("line", "sym")}
        if isinstance(x, list):
            return [strip(v) for v in x]
        return x
    return json.dumps([call_name(link), strip(link.get("args")), strip(link.get("named"))],
                      sort_keys=True, default=str)


def _common_tail(calls: list[PipeCall]) -> tuple[list[dict], str | None]:
    """Fluent links chained on every mapping call that may run in Production, plus a note when the
    answer is uncertain: a dev-only chain must not lend its RequireAuthorization to Production,
    and chains that differ between branches only protect what they all share."""
    prod = [c for c in calls if c.runs_in("Production") is not False]
    if not prod:
        return [], "the mapping call only runs outside Production; its conventions were not applied"
    tails = [_tail(c) for c in prod]
    common: list[dict] = []
    for links in zip(*tails):
        if len({_link_sig(x) for x in links}) != 1:
            break
        common.append(links[0])
    if any(len(t) != len(common) for t in tails) and len({tuple(map(_link_sig, t)) for t in tails}) > 1:
        return common, "the mapping call is chained differently on different paths; only shared conventions were applied"
    return common, None


def discover_controllers(model: ProjectModel) -> list[CoreRouteRef]:
    refs: list[CoreRouteRef] = []
    global_maps: list[_Mapping] | None = None
    done: set[tuple[str, int]] = set()
    for first in model.types():
        proj = model.project_of(first.file)
        key = (first.full_name.lower(), id(proj))
        if key in done:
            continue
        done.add(key)
        decls = _declarations(model, first)
        t = _merged(decls)
        chain = _chain_types(model, t)
        if not _is_controller(model, t, chain):
            continue
        maps = _mappings(pipeline_for(model, proj).named(*_MAP_NAMES, include_dev=True)) if proj is not None else []
        if not maps:
            # A controllers library is mapped by its host project: fall back to every mapping call in the scan.
            if global_maps is None:
                global_maps = _mappings(pipeline_for(model, None).named(*_MAP_NAMES, include_dev=True))
            maps = global_maps
        refs.extend(_controller_routes(model, t, decls, chain, maps))
    return refs


def _controller_routes(model: ProjectModel, t: TypeIR, decls: list[TypeIR], chain: list[TypeIR], maps: list[_Mapping]) -> list[CoreRouteRef]:
    controller, area = _controller_name(t), _area(chain)
    api = _api_surface(model, t, chain)
    proj = model.project_of(t.file)
    class_tmpls = [x for x in (_template(a) for a in _inherited(chain, "Route")) if x is not None]

    unknown: list[str] = []
    # Attribute routes are served by whichever controller mapping call is registered; prefer MapControllers.
    attr_calls = [m.call for m in maps if m.name == "MapControllers"] or [m.call for m in maps[:1]]
    attr_links, attr_note = _common_tail(attr_calls) if attr_calls else ([], None)
    if not maps:
        unknown.append("no MapControllers/MapControllerRoute call found for this controller")
    elif any(m.call.runs_in("Production") is None for m in maps):
        unknown.append("controller mapping sits under an environment condition that could not be parsed")
    if any(m.unresolved_pattern for m in maps):
        unknown.append("a conventional route pattern is not a literal")
    envs = {m.call.env for m in maps}
    env = None if not maps or None in envs else ", ".join(sorted(envs))

    # Conventional templates for this controller: area controllers match area routes only (and the reverse).
    def applies(m: _Mapping) -> bool:
        if m.template is None:
            return False
        has_area = "{area" in m.template.lower() or m.area is not None
        if area:
            return has_area and (m.area is None or m.area.lower() == area.lower())
        return not has_area

    conv = [m for m in maps if applies(m)]
    # A pattern without {controller}/{action} routes through defaults (not resolved here).
    by_defaults = [m for m in conv if not ("{controller" in m.template.lower() and "{action" in m.template.lower())]
    conv = [m for m in conv if m not in by_defaults]
    if by_defaults:
        names = ", ".join(repr(const_str(_arg(m.call.node, 0, "name")) or m.name) for m in by_defaults)
        unknown.append(f"conventional route {names} maps controllers through defaults, which are not resolved")

    simple = t.name.split(".")[-1]
    refs: list[CoreRouteRef] = []
    for m, decl in action_candidates(model, t):
        # An own action of a merged partial type is declared in one of its halves.
        if decl is t:
            decl = next((d for d in decls if any(x is m for x in d.methods)), decl)
        action = _action_name(m)
        seen: set[tuple[str, tuple[str, ...]]] = set()

        def add(path: str, verbs: list[str] | None, mapping: _Mapping | str | None, assumed: bool = False) -> None:
            methods = verbs or ["ANY"]
            if (path, tuple(methods)) in seen:
                return
            seen.add((path, tuple(methods)))
            meta: dict = {"kind": "controller", "api_surface": api, "controller": t.full_name}
            if env is not None:
                meta["env"] = env
            if assumed:
                meta["route_assumed"] = True
            route = Route(path=path, methods=methods, handler_name=f"{simple}.{m.name}",
                          file=decl.file, line=m.line, source_start_line=m.line, source_end_line=m.end_line,
                          meta=meta)
            if mapping == "attr":
                links, note = attr_links, attr_note
            elif mapping:
                links, note = _common_tail([mapping.call])
            else:
                links, note = [], None
            refs.append(CoreRouteRef(route, t, m, proj, style="controller", convention_calls=list(links),
                                     unknown=list(unknown) + ([note] if note else []), partials=list(decls)))

        conv_verbs: list[str] | None = None
        conventional = False
        for sel_tmpl, verbs in _selectors(m):
            raws = _attribute_paths(class_tmpls, sel_tmpl)
            if raws is None:
                conventional, conv_verbs = True, verbs
                continue
            for raw in raws:
                add(_attribute_path(raw, controller, action, area), verbs, "attr")
        if conventional:
            for cm in conv:
                add(_conventional_path(cm.template, controller, action, area), conv_verbs, cm)
            if not conv:
                tmpl = _DEFAULT_AREA_TEMPLATE if area else _DEFAULT_TEMPLATE
                add(_conventional_path(tmpl, controller, action, area), conv_verbs, None, assumed=True)
    return refs


# -- Razor Pages ---------------------------------------------------------------
# A page is a .cshtml under Pages/ (or Areas/<A>/Pages/) whose first directive is @page. Its
# handlers live on the PageModel named by @model, found by name among the project's types.

_HANDLER = re.compile(r"^On(Get|Post|Put|Delete|Patch)(\w*?)(Async)?$")
_RAZOR_COMMENT = re.compile(r"@\*.*?\*@", re.DOTALL)
_PAGE_DIRECTIVE = re.compile(r'^@page\b\s*(?:@?"((?:[^"\\]|\\.)*)")?')
_USING = re.compile(r"^@using\s+(?!static\b)(?:\w+\s*=\s*)?([\w.]+)\s*;?\s*$", re.MULTILINE)
_NAMESPACE = re.compile(r"^@namespace\s+([\w.]+)\s*;?\s*$", re.MULTILINE)
_MODEL = re.compile(r"^@model\s+([^\s;]+)", re.MULTILINE)
_FUNCTIONS = re.compile(r"^\s*@functions\b", re.MULTILINE)


@dataclass
class _Page:
    path: Path
    rel: str
    area: str | None
    folder: list[str]          # folders below Pages/
    template: str | None       # None: no @page template
    model: str | None
    namespaces: list[str]      # candidate namespaces, innermost first
    functions: bool
    lines: int


def _razor_text(path: Path) -> str:
    # Razor comments are blanked, keeping line numbers.
    return _RAZOR_COMMENT.sub(lambda mo: "\n" * mo.group(0).count("\n"), read_source(path))


def _first_directive(text: str) -> str | None:
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("@"):
            return s
        if s:
            # Markup before any directive: Razor only honours @page as the first directive.
            return None
    return None


def _import_chain(path: Path, proj_dir: Path) -> list[Path]:
    """_ViewImports.cshtml files that apply to the page, nearest first, up to the project root."""
    out: list[Path] = []
    cur = path.parent
    while True:
        for f in sorted(cur.iterdir()):
            if f.name.lower() == "_viewimports.cshtml" and f.is_file():
                out.append(f)
        if cur == proj_dir or proj_dir not in cur.parents:
            break
        cur = cur.parent
    return out


def _page_namespaces(path: Path, proj, text: str, from_root: list[str]) -> list[str]:
    """Namespaces to resolve @model in, innermost first: the page's namespace and its enclosing
    ones, then the @using namespaces of the page and of every _ViewImports up the chain."""
    own = _NAMESPACE.search(text)
    ns = own.group(1) if own else None
    usings = [m.group(1) for m in _USING.finditer(text)]
    for imp in _import_chain(path, proj.dir.resolve()):
        itext = _razor_text(imp)
        usings.extend(m.group(1) for m in _USING.finditer(itext))
        hit = _NAMESPACE.search(itext)
        if ns is None and hit:
            # A _ViewImports namespace is the base for pages in its folder and below (nearest wins).
            depth = len(imp.parent.relative_to(proj.dir.resolve()).parts)
            ns = ".".join([hit.group(1), *from_root[depth:]])
    if ns is None:
        ns = ".".join([proj.root_namespace or proj.name, *from_root])
    parts = ns.split(".")
    out = [".".join(parts[:i]) for i in range(len(parts), 0, -1)]
    out.append("")
    out.extend(usings)
    return list(dict.fromkeys(out))


def _find_pages(model: ProjectModel) -> list[tuple[_Page, object]]:
    found: list[tuple[_Page, object]] = []
    dirs = [p.dir.resolve() for p in model.projects]
    for proj in model.projects:
        pdir = proj.dir.resolve()
        nested = [d for d in dirs if d != pdir and pdir in d.parents]
        for f in iter_dnl_files(pdir, (".cshtml",)):
            fr = f.resolve()
            if f.name.startswith("_") or any(d in fr.parents for d in nested):
                continue
            rel_parts = list(fr.relative_to(pdir).parts)
            area = None
            if len(rel_parts) >= 4 and rel_parts[0].lower() == "areas" and rel_parts[2].lower() == "pages":
                area, below = rel_parts[1], rel_parts[3:]
            elif len(rel_parts) >= 2 and rel_parts[0].lower() == "pages":
                below = rel_parts[1:]
            else:
                continue
            text = _razor_text(f)
            d = _first_directive(text)
            pm = _PAGE_DIRECTIVE.match(d) if d else None
            if pm is None:
                continue
            m = _MODEL.search(text)
            found.append((_Page(f, model.rel(f), area, list(below[:-1]), pm.group(1), m.group(1) if m else None,
                                _page_namespaces(f, proj, text, rel_parts[:-1]),
                                bool(_FUNCTIONS.search(text)), len(text.splitlines()) or 1), proj))
    return found


def _resolve_model(model: ProjectModel, proj, page: _Page) -> tuple[TypeIR | None, str | None]:
    """The PageModel type the page names, and a note when the name was a guess."""
    name = (page.model or "").split("<")[0]
    simple = name.split(".")[-1]
    cands = [t for t in model.find_types(simple)
             if t.kind == "class" and model.project_of(t.file) is proj]
    if "." in name:
        # A qualified name binds only to a type in that namespace; a same-named local type under
        # another namespace is a different class (the real model may live in another assembly).
        low = name.lower()
        quals = {f"{ns}.{low}" for ns in page.namespaces if ns}
        full = [t for t in cands
                if t.full_name.lower() == low or t.full_name.lower().endswith("." + low)
                or t.full_name.lower() in quals]
        return (full[0], None) if full else (None, None)
    if not cands:
        return None, None
    for ns in page.namespaces:
        hit = [t for t in cands if t.namespace.lower() == ns.lower()]
        if hit:
            return hit[0], None
    if len({t.full_name.lower() for t in cands}) == 1:
        return cands[0], None
    return cands[0], f"page model {simple} matches several types and none is in scope; the first was used"


def _handlers(model: ProjectModel, chain: list[TypeIR]) -> list[tuple[MethodIR, TypeIR, re.Match]]:
    """Public instance handler methods of the PageModel and its project bases (nearest declaration wins)."""
    out: list[tuple[MethodIR, TypeIR, re.Match]] = []
    seen: set[str] = set()
    for ct in chain:
        decls = _declarations(model, ct)
        for m in ct.methods:
            if m.name.lower() in seen:
                continue
            seen.add(m.name.lower())
            mods = {x.lower() for x in m.modifiers}
            hit = _HANDLER.match(m.name)
            if (hit is None or "public" not in mods or "static" in mods
                    or has_attr(m.attributes, "NonHandler")):
                continue
            decl = next((d for d in decls if any(x is m for x in d.methods)), ct)
            out.append((m, decl, hit))
    return out


def _page_path(page: _Page) -> tuple[str, str]:
    """(page name as conventions see it, e.g. /Admin/Index; the routed path before the template)."""
    name = "/" + "/".join([*page.folder, page.path.name[: -len(".cshtml")]])
    routed = name
    if page.path.name.lower() == "index.cshtml":
        routed = "/" + "/".join(page.folder)
    return name, routed


def discover_pages(model: ProjectModel) -> list[CoreRouteRef]:
    refs: list[CoreRouteRef] = []
    global_maps: list[PipeCall] | None = None
    for page, proj in _find_pages(model):
        maps = pipeline_for(model, proj).named("MapRazorPages", include_dev=True)
        if not maps:
            # A Razor class library is mapped by its host project: fall back to every mapping call in the scan.
            if global_maps is None:
                global_maps = pipeline_for(model, None).named("MapRazorPages", include_dev=True)
            maps = global_maps
        unknown: list[str] = []
        if not maps:
            unknown.append("no MapRazorPages call found for this page")
        elif any(c.runs_in("Production") is None for c in maps):
            unknown.append("Razor Pages mapping sits under an environment condition that could not be parsed")
        envs = {c.env for c in maps}
        env = None if not maps or None in envs else ", ".join(sorted(envs))
        conv, conv_note = _common_tail(maps) if maps else ([], None)
        if conv_note:
            unknown.append(conv_note)

        name, routed = _page_path(page)
        tmpl = (page.template or "").strip()
        if tmpl.startswith("~/") or tmpl.startswith("/"):
            path = _join(tmpl.lstrip("~"))
        else:
            path = _join(routed, tmpl)
        if page.area:
            path = _join(page.area, path)
        path = strip_constraints(path)
        meta: dict = {"kind": "razorpage", "api_surface": False, "page": name}
        if page.area:
            meta["area"] = page.area
        if env is not None:
            meta["env"] = env

        def route(handler_name: str, verb: str, file: str, line: int, start: int, end: int, **extra) -> Route:
            return Route(path=path, methods=[verb], handler_name=handler_name, file=file, line=line,
                         source_start_line=start, source_end_line=end, meta={**meta, **extra})

        t = None
        if page.model:
            t, guess = _resolve_model(model, proj, page)
            if guess:
                unknown.append(guess)
        if t is None:
            what = f"page model {page.model} not found" if page.model else "page declares no @model"
            unknown.append(f"{what}; handlers unknown")
            refs.append(CoreRouteRef(route(page.model or page.path.name, "GET", page.rel, 1, 1, page.lines),
                                     None, None, proj, style="razorpage", convention_calls=list(conv),
                                     unknown=unknown))
            continue
        if page.functions:
            unknown.append("page declares @functions; inline handlers are not analysed")
        decls = _declarations(model, t)
        mt = _merged(decls)
        chain = _chain_types(model, mt)
        simple = mt.name.split(".")[-1]
        handlers = _handlers(model, chain)
        if not handlers:
            refs.append(CoreRouteRef(route(simple, "GET", mt.file, mt.line, mt.line, mt.end_line),
                                     mt, None, proj, style="razorpage", convention_calls=list(conv),
                                     unknown=list(unknown), partials=decls))
            continue
        for m, decl, hit in handlers:
            refs.append(CoreRouteRef(
                route(f"{simple}.{m.name}", hit.group(1).upper(), decl.file, m.line, m.line, m.end_line,
                      handler=hit.group(2)),
                mt, m, proj, style="razorpage", convention_calls=list(conv),
                unknown=list(unknown), partials=decls))
    return refs
