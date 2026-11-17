"""Route discovery for ASP.NET Core: controllers (attribute and conventional routing),
Razor Pages, and minimal-API / other endpoints.

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
meta["page_attributes"] (when present) lists the raw `@attribute` directive texts of the page and its
_ViewImports chain, e.g. "[AllowAnonymous]"; they are class-level attributes of the generated page.

Endpoints (discover_endpoints): `Map{Get,Post,..}`, `MapMethods`, `Map` and the other Map*/Use* calls
that register endpoints. The walk follows what the pipeline follows (entry points, solution methods
and `UseEndpoints` lambdas, found through PipeCall.via/target) and keeps a small value model of the
builders it meets: a root builder, a group (`MapGroup` nodes chained by parent), a registered route,
or a `_Result` (what a followed method provably returns). Conventions chained on a group go into
Group.calls, those chained on a Map call into endpoint_calls; conventions chained on a followed
call apply as a Group(prefix="") on the group the method returns, or are recorded as an `unknown`
note on the routes registered inside when the returned builder cannot be traced. Methods that take
an endpoint builder but are never reached are scanned too, with caller_unknown set.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from pathlib import Path

from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.ir import (Attr, MethodIR, ParamIR, TypeIR, attr_key, call_chain, call_name, const_str,
                           has_attr, literal_str, receiver_text, walk)
from checks.dnl.pipeline import _FRAMEWORK_CALLS, PipeCall, _is_ext, _is_member_call, pipeline_for
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
            elif maps and all(x.call.runs_in("Production") is False for x in maps):
                # An assumed route leans on whatever mapping exists; none of it runs in Production.
                links, note = [], "the mapping call only runs outside Production; its conventions were not applied"
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
# `@attribute [AllowAnonymous]` on a page or in a _ViewImports it inherits: class-level attributes of the generated page.
_ATTRIBUTE = re.compile(r"^[ 	]*@attribute\s+(.+?)\s*$", re.MULTILINE)
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
    attributes: list[str] = field(default_factory=list)   # raw `@attribute` directive texts, page first then _ViewImports


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
            attrs = [x.group(1) for x in _ATTRIBUTE.finditer(text)]
            for imp in _import_chain(f, pdir):
                attrs.extend(x.group(1) for x in _ATTRIBUTE.finditer(_razor_text(imp)))
            found.append((_Page(f, model.rel(f), area, list(below[:-1]), pm.group(1), m.group(1) if m else None,
                                _page_namespaces(f, proj, text, rel_parts[:-1]),
                                bool(_FUNCTIONS.search(text)), len(text.splitlines()) or 1, attrs), proj))
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
        if page.attributes:
            # Raw `@attribute` texts (e.g. "[AllowAnonymous]"); the auth pass parses them as class attributes.
            meta["page_attributes"] = list(page.attributes)
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


# -- Minimal API and other endpoints -------------------------------------------
# A forward walk over the pipeline's entry methods, mirroring its statement walk. Environment
# and "was this call reached" facts come from the pipeline's PipeCall for the same node (looked
# up by (via, id(node))); builder values and group chains are tracked here.

_VERB_CALLS = {"MapGet": "GET", "MapPost": "POST", "MapPut": "PUT", "MapPatch": "PATCH", "MapDelete": "DELETE"}
_OTHER_MAPS = ("MapMethods", "Map", "MapHub", "MapGrpcService", "MapRazorComponents", "MapBlazorHub",
               "MapHealthChecks", "MapOpenApi", "MapSwagger")
_SWAGGER_PATHS = ("/swagger/{documentName}/swagger.json", "/swagger")
# Parameter types that make an unreached method worth scanning.
_ROOT_TYPES = {"iendpointroutebuilder", "routegroupbuilder", "webapplication", "iapplicationbuilder"}
_BUILDER_PARAMS = _ROOT_TYPES
# Calls that hand the receiver back (a convention or middleware link) when no symbol says so.
_CONVENTION_NAMES = frozenset("""
RequireAuthorization AllowAnonymous WithTags WithName WithOpenApi WithMetadata WithDisplayName WithGroupName
WithSummary WithDescription Produces ProducesProblem ProducesValidationProblem Accepts RequireCors
RequireRateLimiting RequireHost DisableAntiforgery AddEndpointFilter AddEndpointFilterFactory
ExcludeFromDescription DisableRateLimiting CacheOutput WithRequestTimeout
""".split())
_SWEEP_MSG = "registration not reached by the pipeline walk"
_SWEEP_ENV_MSG = "environment and group prefix of this registration were not traced"
# Map* calls other discovery code handles (controllers, pages) or that register nothing worth listing.
_HANDLED_MAPS = frozenset(_MAP_NAMES) | {"MapRazorPages", "MapStaticAssets"}


@dataclass(eq=False)
class _Node:
    """A builder that routes register on: the app / a bare endpoint builder ("root"), or a group."""
    group: Group | None
    parent: "_Node | None" = None
    kind: str = "root"                  # "root" | "group"
    extras: list[Group] = field(default_factory=list)   # conventions a caller applied to the group
    notes: list[str] = field(default_factory=list)
    traced: bool = True                 # False: a builder whose group context is not known
    depth: int = 0                      # conditional depth of the code that created it


@dataclass(eq=False)
class _Entry:
    ref: CoreRouteRef
    leaf: _Node
    depth: int = 0


@dataclass(eq=False)
class _Result:
    """The value a followed solution method returns: the builders it provably returns, or not."""
    targets: list           # _Node (groups) and _Entry values
    traced: bool
    label: str              # the method's name
    entries: list[_Entry]   # every route registered while the method ran
    file: str
    line: int
    group: Group | None = None
    depth: int = 0
    origin: object = None   # the value an untraced call was made on (its group is what a trailing convention missed)


@dataclass
class _Frame:
    type: TypeIR
    method: MethodIR
    scope: dict             # name -> _Node | _Entry | _Result | None
    fns: dict               # local function name -> lambda node
    via: tuple
    reached: bool           # False: scanned without a caller
    lenient: bool = False   # local-function body: no PipeCalls of its own, the call site's env applies
    env_pc: PipeCall | None = None
    returns: list = field(default_factory=list)
    cond: int = 0           # nesting of branches / loops / catches the code runs under


def _simple_type(t: str | None) -> str:
    return (t or "").split("<")[0].strip().rstrip("?").split(".")[-1].lower()


def _merge_scopes(base: dict, branches: list[dict]) -> dict:
    """Scope after alternative branches: a name keeps its value only when every branch agrees."""
    out = dict(base)
    for name in {n for b in branches for n in b}:
        vals = [b.get(name) for b in branches]
        out[name] = vals[0] if all(v is vals[0] for v in vals) else None
    return out


def _lambda_method(lam: dict, name: str | None = None) -> MethodIR:
    """A synthetic MethodIR for a lambda / local function: params from param_info, an expression
    body wrapped as one `return`."""
    line = lam.get("line", 0)
    infos = lam.get("param_info")
    if infos is None:
        infos = [{"name": n} for n in lam.get("params") or []]
    params = [ParamIR(i.get("name", ""), i.get("type"),
                      [Attr(a.get("name", ""), a.get("args") or [], a.get("named") or {}, a.get("line", 0))
                       for a in i.get("attributes") or []],
                      i.get("modifiers") or []) for i in infos]
    body = lam.get("body")
    stmts = body if isinstance(body, list) else [{"k": "return", "line": line, "value": body}]
    attrs = [Attr(a.get("name", ""), a.get("args") or [], a.get("named") or {}, a.get("line", 0))
             for a in lam.get("attributes") or []]
    return MethodIR(name=name or f"<lambda@{line}>", params=params, attributes=attrs, body=stmts, line=line,
                    end_line=lam.get("end_line", line))


def _is_branch_lambda(lam) -> bool:
    """`app.Map("/x", b => b.Run(..))` is a middleware branch, not an endpoint handler."""
    if not (isinstance(lam, dict) and lam.get("k") == "lambda"):
        return False
    params = lam.get("params") or []
    if len(params) != 1:
        return False
    infos = lam.get("param_info") or []
    if infos and _simple_type(infos[0].get("type")) == "iapplicationbuilder":
        return True
    return any(n.get("k") == "call" and call_name(n) in ("Run", "Use", "UseMiddleware")
               and receiver_text((n.get("fn") or {}).get("obj")) == params[0] for n in walk(lam.get("body")))


def _declared(type_text: str | None, certain: bool = False) -> _Node | None:
    """A builder value for a declared parameter / local type, None for other types. The group
    context of a declared RouteGroupBuilder is the caller's, hence not traced; a root builder is
    only certain when the declaration is an entry point's (otherwise the caller may hold a group)."""
    simple = _simple_type(type_text)
    if simple == "routegroupbuilder":
        return _Node(None, None, "group", notes=["the group this builder belongs to could not be traced"], traced=False)
    if simple in _ROOT_TYPES:
        if certain:
            return _Node(None)
        return _Node(None, None, "root", notes=["the endpoint builder routes were registered on could not be traced"],
                     traced=False)
    return None


class _Scan:
    """Endpoint discovery for one project (or the whole model when proj is None)."""

    def __init__(self, model: ProjectModel, proj) -> None:
        self.model, self.proj = model, proj
        self.pipe = pipeline_for(model, proj)
        self.index = {(c.via, id(c.node)): c for c in self.pipe.calls}
        self.entries: list[_Entry] = []
        self.visited: set[int] = set()
        self.local_fns: list[tuple] = []        # (type, name, lambda) of every local function met
        self.called_fns: set[int] = set()
        self.fn_stack: set[int] = set()
        self.seen_mw: set[tuple] = set()
        self.method_names = {m.name for f in model.files.values() for t in f.types for m in t.methods}
        self.consumed: set[int] = set()         # id() of the Map / Use* call nodes already registered

    # -- driver ------------------------------------------------------------
    def run(self) -> list[CoreRouteRef]:
        for t, m in self.pipe.entries:
            self.walk_method(t, m, self.param_scope(m, True), (), True)
        types = [t for rel, f in self.model.files.items()
                 if self.proj is None or self.model.project_of(rel) is self.proj for t in f.types]
        # Methods taking an endpoint builder that nothing reached: the caller is unknown.
        for t in types:
            for m in t.methods:
                if id(m) not in self.visited and any(_simple_type(p.type) in _BUILDER_PARAMS for p in m.params):
                    self.walk_method(t, m, self.param_scope(m, True), (), False)
        for t, name, lam in list(self.local_fns):
            m = _lambda_method(lam, name)
            if id(lam) not in self.called_fns and any(_simple_type(p.type) in _BUILDER_PARAMS for p in m.params):
                self.called_fns.add(id(lam))
                self.walk_body(t, m, self.param_scope(m, True), (), False, True)
        self.sweep(types)
        return [self.finish(e) for e in self.entries]

    def sweep(self, types: list[TypeIR]) -> None:
        """Registrations the walk never consumed: Map calls inside lambdas the pipeline does not
        walk (host-builder callbacks, `MapWhen`/`UseWhen` branches, startup filters), in methods
        with no builder parameter (a field, `this`), in dead code, or in call arguments."""
        for t in types:
            for m in t.methods:
                fr = _Frame(t, m, {}, {}, (), False, True)
                for link in walk(m.body):
                    name = call_name(link) if link.get("k") == "call" else None
                    if not name or id(link) in self.consumed:
                        continue
                    if name in ("UseSwagger", "UseSwaggerUI") and self.is_endpoint_call(link, name, True):
                        before = len(self.entries)
                        self.middleware(fr, link, name, None)
                        for e in self.entries[before:]:
                            e.ref.unknown[:0] = [_SWEEP_MSG, _SWEEP_ENV_MSG]
                    elif self.is_map(link, name, False):
                        entry = self.register(fr, link, name, None, None)
                        entry.ref.unknown[:0] = [_SWEEP_MSG, _SWEEP_ENV_MSG]
                    elif self.is_unmodelled(link, name, False):
                        self.unmodelled(fr, link, name, None, None)

    def finish(self, e: _Entry) -> CoreRouteRef:
        """Fill in the group chain (outermost first) once every convention has been seen."""
        chain: list[_Node] = []
        n: _Node | None = e.leaf
        while n is not None:
            chain.append(n)
            n = n.parent
        for n in reversed(chain):
            if n.group is not None:
                e.ref.groups.append(n.group)
            e.ref.groups.extend(n.extras)
            for note in n.notes:
                if note not in e.ref.unknown:
                    e.ref.unknown.append(note)
        return e.ref

    @staticmethod
    def param_scope(m: MethodIR, certain: bool) -> dict:
        scope = {}
        for p in m.params:
            node = _declared(p.type, certain)
            if node is not None:
                scope[p.name] = node
        return scope

    # -- methods and statements ---------------------------------------------
    def walk_method(self, t: TypeIR, m: MethodIR, scope: dict, via: tuple, reached: bool, cond: int = 0) -> list:
        self.visited.add(id(m))
        return self.walk_body(t, m, scope, via, reached, cond=cond)

    def walk_body(self, t, m, scope, via, reached, lenient=False, env_pc=None, fns=None, cond=0) -> list:
        fr = _Frame(t, m, scope, dict(fns or {}), via, reached, lenient, env_pc, cond=cond)
        self.stmts(fr, m.body)
        return fr.returns

    def stmts(self, fr: _Frame, stmts) -> None:
        # Local functions may be used before their declaration.
        for s in stmts or []:
            if (isinstance(s, dict) and s.get("k") == "local" and s.get("name")
                    and isinstance(s.get("init"), dict) and s["init"].get("k") == "lambda"):
                fr.fns[s["name"]] = s["init"]
                self.local_fns.append((fr.type, s["name"], s["init"]))
        for s in stmts or []:
            self.stmt(fr, s)

    def branch(self, fr: _Frame, bodies: list) -> None:
        """Run alternative bodies on copies of the scope and keep what they agree on."""
        base = fr.scope
        results = []
        fr.cond += 1
        for b in bodies:
            fr.scope = dict(base)
            self.stmts(fr, b)
            results.append(fr.scope)
        fr.cond -= 1
        fr.scope = _merge_scopes(base, results + ([base] if len(bodies) == 1 else []))

    def stmt(self, fr: _Frame, s) -> None:
        if not isinstance(s, dict):
            return
        k = s.get("k")
        if k == "expr":
            self.eval(fr, s.get("expr"))
        elif k == "assign":
            self.eval(fr, s)
        elif k == "local":
            state = self.eval(fr, s.get("init"))
            nm = s.get("name")
            if nm:
                if state is None:
                    state = _declared(s.get("type_full")) or _declared(s.get("type"))
                fr.scope[nm] = state
        elif k in ("return", "throw"):
            state = self.eval(fr, s.get("value"))
            if k == "return":
                fr.returns.append(state)
        elif k == "if":
            self.branch(fr, [s.get("then"), s.get("else") or []])
        elif k == "loop":
            self.branch(fr, [s.get("body")])
        elif k == "using":
            self.stmts(fr, s.get("resource"))
            self.stmts(fr, s.get("body"))
        elif k == "try":
            fr.cond += 1            # an exception may skip the rest of the block
            self.stmts(fr, s.get("body"))
            fr.cond -= 1
            self.branch(fr, [c.get("body") for c in s.get("catches") or []] + [[]])
            self.stmts(fr, s.get("finally"))

    # -- expressions ----------------------------------------------------------
    def eval(self, fr: _Frame, e, arg: bool = False):
        """Value of an expression, registering the routes in it. `arg`: an argument of a call,
        which the pipeline does not visit -- groups are built there, routes are not registered."""
        if not isinstance(e, dict):
            return None
        k = e.get("k")
        if k == "assign":
            state = self.eval(fr, e.get("value"))
            tgt = e.get("target")
            if isinstance(tgt, dict) and tgt.get("k") == "name":
                fr.scope[tgt.get("id")] = state
            return state
        if k == "name":
            return fr.scope.get(e.get("id"))
        if k != "call":
            return None
        root, links = call_chain(e)
        state = fr.scope.get(root.get("id")) if isinstance(root, dict) and root.get("k") == "name" else None
        for link in links:
            state = self.link(fr, link, state, arg)
        return state

    def link(self, fr: _Frame, link: dict, state, arg: bool):
        """One call of a fluent chain applied to the value so far; returns the new value."""
        name = call_name(link) or ""
        pc = self.index.get((fr.via, id(link)))
        if not arg and fr.reached and not fr.lenient and pc is None:
            return None             # the pipeline did not visit it (dead code, or a cycle)
        if pc is not None and pc.target is not None:
            return self.follow(fr, link, pc, state)
        if not arg and name in fr.fns and not _is_member_call(link):
            return self.follow_local(fr, link, name, pc)
        if name == "UseEndpoints" and not arg:
            return self.use_endpoints(fr, link, state)
        node = self.builder(state)
        known = node is not None
        if name in ("Build", "Create") and state is None and pc is not None and pc.kind == "app":
            return _Node(None)      # WebApplication.CreateBuilder(..).Build() / WebApplication.Create(..)
        if name == "MapGroup" and (self.is_endpoint_call(link, name, known)
                                   or (not link.get("sym") and self.shaped(link, name))):
            if node is None:
                node = _Node(None, None, "group", notes=["the receiver of MapGroup could not be traced"], traced=False,
                             depth=fr.cond)
            args = link.get("args") or []
            prefix = const_str(args[0]) if args else ""
            g = _Node(Group(prefix or "", [], fr.type.file, link.get("line", 0)), node, "group", depth=fr.cond)
            if prefix is None:
                g.notes.append("a MapGroup prefix is not a literal")
            return g
        if not arg and self.is_map(link, name, known):
            return self.register(fr, link, name, node, pc)
        if not arg and self.is_unmodelled(link, name, known):
            self.unmodelled(fr, link, name, pc, node)
        if (not arg and name in ("UseSwagger", "UseSwaggerUI")
                and self.is_endpoint_call(link, name, known or (pc is not None and pc.kind == "app"))):
            self.middleware(fr, link, name, pc)
            return state
        return self.convention(fr, link, state, name)

    def is_unmodelled(self, link: dict, name: str, known: bool) -> bool:
        """A Map* call that registers endpoints the engine does not model. With no symbol the name
        decides (`Map` + capital, called on something, not a solution method)."""
        if (len(name) < 4 or not name.startswith("Map") or not name[3].isupper() or name == "MapGroup"
                or name in _HANDLED_MAPS or name in self.method_names):
            return False
        if self.is_endpoint_call(link, name, known):
            return True
        fn = link.get("fn")
        return not link.get("sym") and isinstance(fn, dict) and fn.get("k") == "member"

    def unmodelled(self, fr: _Frame, link: dict, name: str, pc: PipeCall | None, node: _Node | None) -> None:
        """A Map* extension on a builder (`MapIdentityApi`) registers endpoints this engine cannot
        list: say so on the model, and on the routes of the group it was called on."""
        self.consumed.add(id(link))
        where = f"{pc.file if pc is not None else fr.type.file}:{link.get('line', 0)}"
        note = f"{name} at {where} registers endpoints the engine cannot list; review them manually"
        if note not in self.model.notes:
            self.model.notes.append(note)
        if node is not None and node.kind == "group":
            msg = f"{name} registers endpoints the engine cannot list on this group"
            if msg not in node.notes:
                node.notes.append(msg)

    # -- values ---------------------------------------------------------------
    @staticmethod
    def builder(state) -> _Node | None:
        """The builder a value stands for, when routes can register on it."""
        if isinstance(state, _Node):
            return state
        if (isinstance(state, _Result) and state.traced and len(state.targets) == 1
                and isinstance(state.targets[0], _Node)):
            return state.targets[0]
        return None

    @staticmethod
    def is_endpoint_call(link: dict, name: str, known: bool) -> bool:
        """An ASP.NET Core endpoint-builder extension: by symbol, or (no symbol) on a known builder.
        A symbol that resolves anywhere else is some other API with the same name."""
        sym = link.get("sym")
        if sym:
            owner = sym.rsplit(".", 1)[0]
            return owner.startswith("Microsoft.AspNetCore.") and (
                name != "Map" or "EndpointRouteBuilder" in owner.rsplit(".", 1)[-1])
        return known

    def is_map(self, link: dict, name: str, known: bool) -> bool:
        if name not in _VERB_CALLS and name not in _OTHER_MAPS and not name.startswith("MapFallback"):
            return False
        if name == "Map" and not link.get("sym") and _is_branch_lambda(self.handler_arg(link, name)):
            return False
        if self.is_endpoint_call(link, name, known):
            return True
        return not link.get("sym") and self.shaped(link, name)

    def shaped(self, link: dict, name: str) -> bool:
        """With no symbol and a receiver the value model does not know (a factory-returned app, a
        field, `this`): a call shaped like a registration still counts -- a spurious route costs
        less than a missing one."""
        if name in _VERB_CALLS or name in ("Map", "MapMethods", "MapGroup"):
            p = _arg(link, 0, "pattern", "prefix")
            if not (const_str(p) is not None or (isinstance(p, dict) and p.get("k") in ("name", "member"))):
                return False
            if name == "MapGroup":
                return True
            h = self.handler_arg(link, name)
            return isinstance(h, dict) and h.get("k") in ("lambda", "name", "member")
        targs = (link.get("fn") or {}).get("targs") or []
        if name in ("MapHub", "MapGrpcService", "MapRazorComponents"):
            return bool(targs)
        if name == "MapHealthChecks":
            return const_str(_arg(link, 0, "pattern")) is not None
        return False

    @staticmethod
    def handler_arg(link: dict, name: str):
        return _arg(link, 2 if name == "MapMethods" else 1, "handler", "requestdelegate")

    def passes_through(self, link: dict, name: str, state) -> bool:
        """Whether a non-Map call hands its receiver back: ASP.NET Core calls by symbol, and with no
        symbol the known convention / middleware names (never a Map* call). Anything else (a solution call that was not
        followed, an external extension such as MapIdentityApi) returns something we cannot trace."""
        if name.startswith("Map"):
            return False        # an endpoint registration returns the builder of its own endpoints
        sym = link.get("sym")
        if sym:
            return sym.rsplit(".", 1)[0].startswith("Microsoft.AspNetCore.")
        if (name in _CONVENTION_NAMES or name in _FRAMEWORK_CALLS) and isinstance(state, (_Node, _Entry, _Result)):
            return True
        return isinstance(state, _Node) and state.kind == "root" and name.startswith(("Use", "Add"))

    def convention(self, fr: _Frame, link: dict, state, name: str):
        """A non-Map call chained on a builder, a route, or a followed call's result."""
        if state is None:
            return None
        if not self.passes_through(link, name, state):
            # A call this engine cannot follow, made on a route or a group: whatever it applies (an
            # anonymous opt-out, say) is unknown, noted now because nothing may be chained after it.
            if not name.startswith("Map"):
                msg = f"{name} is not analysed and may change this endpoint's metadata"
                if isinstance(state, _Entry) and msg not in state.ref.unknown:
                    state.ref.unknown.append(msg)
                elif isinstance(state, _Node) and state.kind == "group" and msg not in state.notes:
                    state.notes.append(msg)
                elif isinstance(state, _Result):
                    # On a followed call's result: what it returns (groups, routes), the routes it
                    # registered and the value it was called on.
                    for t in state.targets:
                        if isinstance(t, _Node) and msg not in t.notes:
                            t.notes.append(msg)
                        elif isinstance(t, _Entry) and msg not in t.ref.unknown:
                            t.ref.unknown.append(msg)
                    for e in state.entries:
                        if msg not in e.ref.unknown:
                            e.ref.unknown.append(msg)
                    o = state.origin
                    if isinstance(o, _Node) and o.kind == "group" and msg not in o.notes:
                        o.notes.append(msg)
                    elif isinstance(o, _Entry) and msg not in o.ref.unknown:
                        o.ref.unknown.append(msg)
            # Two untraced hops in a row (`g.MapX().Foo().RequireAuthorization()`): the origin stays the
            # first thing that was a group or a route, not the previous untraced result.
            if isinstance(state, _Result) and not state.traced:
                return _Result([], False, name, list(state.entries), fr.type.file, link.get("line", 0),
                               depth=fr.cond, origin=state.origin)
            return _Result([], False, name, [], fr.type.file, link.get("line", 0), depth=fr.cond, origin=state)
        cond_note = f"{name} applied conditionally"
        if isinstance(state, _Entry):
            state.ref.endpoint_calls.append(link)
            if fr.cond > state.depth and cond_note not in state.ref.unknown:
                state.ref.unknown.append(cond_note)
        elif isinstance(state, _Node):
            if state.kind == "group":
                if state.group is not None:
                    state.group.calls.append(link)
                else:
                    state.extras.append(Group("", [link], fr.type.file, link.get("line", 0)))
                if fr.cond > state.depth and cond_note not in state.notes:
                    state.notes.append(cond_note)
        elif isinstance(state, _Result):
            if not state.traced:
                msg = f"{name} applied to the result of {state.label} could not be traced"
                for e in state.entries:
                    if msg not in e.ref.unknown:
                        e.ref.unknown.append(msg)
                # The convention may belong to the receiver's group: every route on it, registered
                # before or after, carries the note (a root builder would mark every route).
                o = state.origin
                if isinstance(o, _Node) and o.kind == "group" and msg not in o.notes:
                    o.notes.append(msg)
                elif isinstance(o, _Entry) and msg not in o.ref.unknown:
                    o.ref.unknown.append(msg)
            else:
                # What the method provably returns takes the call: as an extra group on a group,
                # on the route itself for a returned Map call.
                if state.group is None:
                    state.group = Group("", [], state.file, state.line)
                    for t in state.targets:
                        if isinstance(t, _Node):
                            t.extras.append(state.group)
                state.group.calls.append(link)
                for t in state.targets:
                    if isinstance(t, _Entry):
                        t.ref.endpoint_calls.append(link)
                if fr.cond > state.depth:
                    for t in state.targets:
                        if isinstance(t, _Node):
                            if cond_note not in t.notes:
                                t.notes.append(cond_note)
                        elif cond_note not in t.ref.unknown:
                            t.ref.unknown.append(cond_note)
        return state

    # -- following calls ---------------------------------------------------------
    def follow(self, fr: _Frame, link: dict, pc: PipeCall, recv):
        t, m = pc.target
        scope = self.bind(fr, link, t, m, recv)
        start = len(self.entries)
        rets = self.walk_method(t, m, scope, fr.via + (id(link),), True, fr.cond)
        return self.result(rets, m.name, start, fr, link)

    def follow_local(self, fr: _Frame, link: dict, name: str, pc: PipeCall | None):
        """A call to a local function: its body runs under the call site's environment."""
        lam = fr.fns[name]
        if id(lam) in self.fn_stack:
            return None
        self.called_fns.add(id(lam))
        m = _lambda_method(lam, name)
        scope = {k: v for k, v in fr.scope.items() if k not in {p.name for p in m.params}}
        scope.update(self.bind(fr, link, fr.type, m, None, False))
        start = len(self.entries)
        self.fn_stack.add(id(lam))
        rets = self.walk_body(fr.type, m, scope, fr.via, fr.reached, True, pc or fr.env_pc, fr.fns, fr.cond)
        self.fn_stack.discard(id(lam))
        return self.result(rets, name, start, fr, link)

    def bind(self, fr: _Frame, link: dict, t: TypeIR, m: MethodIR, recv, ext_ok: bool = True) -> dict:
        """Parameter values of a followed method: the receiver for an extension's first parameter,
        the evaluated arguments for the rest. A declared builder type fills what stays unknown."""
        params = list(m.params)
        scope: dict = {}
        if (ext_ok and params and _is_ext(m) and _is_member_call(link)
                and receiver_text(link["fn"].get("obj")) not in ("this", t.name, t.full_name)):
            scope[params[0].name] = recv
            params = params[1:]
        for p, a in zip(params, link.get("args") or []):
            scope[p.name] = self.eval(fr, a, arg=True)
        for k, a in (link.get("named") or {}).items():
            for p in params:
                if p.name.lower() == k.lower():
                    scope[p.name] = self.eval(fr, a, arg=True)
        for p in m.params:
            if scope.get(p.name) is None:
                node = _declared(p.type)
                if node is not None:
                    scope[p.name] = node
        return scope

    def result(self, rets: list, label: str, start: int, fr: _Frame, link: dict) -> _Result:
        targets: list = []
        traced = bool(rets)
        for r in rets:
            if isinstance(r, _Result):
                traced = traced and r.traced
                targets.extend(r.targets)
            elif isinstance(r, _Entry) or (isinstance(r, _Node) and r.kind == "group" and r.traced):
                targets.append(r)
            else:
                traced = False
        return _Result(targets, traced, label, self.entries[start:], fr.type.file, link.get("line", 0),
                       depth=fr.cond)

    def use_endpoints(self, fr: _Frame, link: dict, state):
        """`UseEndpoints(e => ..)`: the lambda body runs with its parameter bound to the root builder."""
        for a in link.get("args") or []:
            if not (isinstance(a, dict) and a.get("k") == "lambda"):
                continue
            params = a.get("params") or []
            inner = _Frame(fr.type, fr.method, dict(fr.scope), dict(fr.fns), fr.via, fr.reached, fr.lenient,
                           fr.env_pc, cond=fr.cond)
            if params:
                inner.scope[params[0]] = state if isinstance(state, _Node) else _Node(None)
            body = a.get("body")
            if isinstance(body, list):
                self.stmts(inner, body)
            else:
                self.eval(inner, body)
        return state

    # -- registering endpoints -------------------------------------------------
    def register(self, fr: _Frame, link: dict, name: str, node: _Node | None, pc: PipeCall | None):
        notes: list[str] = []
        if node is None:
            node = _Node(None, None, "group", notes=[f"the receiver of {name} could not be traced"], traced=False)
        prefixes: list[str] = []
        n: _Node | None = node
        while n is not None:
            if n.group is not None:
                prefixes.append(n.group.prefix)
            n = n.parent
        prefixes.reverse()
        line = link.get("line", 0)
        file = pc.file if pc is not None else fr.type.file
        env_pc = pc or fr.env_pc
        meta: dict = {"kind": "minimalapi", "api_surface": True}
        style, methods, handler, htype, hmeth = "minimalapi", ["ANY"], None, None, None
        start = end = line
        src_file = None
        pattern = const_str(_arg(link, 0, "pattern"))
        targs = (link.get("fn") or {}).get("targs") or []
        t_text = targs[0] if targs else None
        if name in _VERB_CALLS or name in ("Map", "MapMethods"):
            if name in _VERB_CALLS:
                methods = [_VERB_CALLS[name]]
            elif name == "MapMethods":
                verbs = [v.strip().upper() for x in walk(_arg(link, 1, "httpmethods")) if (v := literal_str(x))]
                if verbs:
                    methods = list(dict.fromkeys(verbs))
                else:
                    notes.append("the HTTP methods of MapMethods are not literals")
            harg = self.handler_arg(link, name)
            htype, hmeth, handler, hnote = self.resolve_handler(fr, harg)
            if hnote:
                notes.append(hnote)
            if hmeth is not None:
                if isinstance(harg, dict) and harg.get("k") == "lambda":
                    start, end = min(line, hmeth.line), max(line, hmeth.end_line)
                else:
                    # A method group or local function: the range is the handler's own code, in
                    # the file that declares it (a local function lives in the Map call's file).
                    start, end = hmeth.line, hmeth.end_line
                    src_file = htype.file if htype is not None and any(x is hmeth for x in htype.methods) else file
        else:
            style = "endpoint"
            meta["api_surface"] = False
            if name == "MapHub":
                meta["kind"], handler = "hub", t_text or "Hub"
                htype = self.find_type(t_text)
            elif name == "MapGrpcService":
                meta["kind"], meta["api_surface"], methods = "grpc", True, ["POST"]
                handler, htype = t_text or "GrpcService", self.find_type(t_text)
                pattern = f"/{t_text or '{service}'}/*"
            elif name == "MapRazorComponents":
                meta["kind"], handler, pattern = "blazor", t_text or "App", "/*"
                htype = self.find_type(t_text)
            elif name == "MapBlazorHub":
                meta["kind"], handler, pattern = "blazor", name, pattern or "/_blazor"
            elif name == "MapHealthChecks":
                meta["kind"], handler = "health", name
            elif name.startswith("MapFallback"):
                meta["kind"], handler, pattern = "fallback", name, "/{**path}"
            elif name == "MapOpenApi":
                meta["kind"], methods, handler = "openapi", ["GET"], name
                pattern = pattern or "/openapi/{documentName}.json"
            else:   # MapSwagger
                meta["kind"], methods, handler = "openapi", ["GET"], name
                pattern = pattern or _SWAGGER_PATHS[0]
        if pattern is None:
            notes.append(f"the pattern of {name} is not a literal")
            pattern = "{?}"
        path = strip_constraints(_join(*prefixes, pattern))
        if env_pc is not None and env_pc.runs_in("Production") is not True and env_pc.env:
            meta["env"] = env_pc.env
        route = Route(path=path, methods=methods, handler_name=handler or name, file=file, line=line,
                      source_file=src_file, source_start_line=start, source_end_line=end, meta=meta)
        ref = CoreRouteRef(route, htype, hmeth, self.proj, style=style, caller_unknown=not fr.reached, unknown=notes)
        entry = _Entry(ref, node, fr.cond)
        self.entries.append(entry)
        self.consumed.add(id(link))
        return entry

    def middleware(self, fr: _Frame, link: dict, name: str, pc: PipeCall | None) -> None:
        """UseSwagger / UseSwaggerUI: middleware that serves the document and the UI."""
        env_pc = pc or fr.env_pc
        env = env_pc.env if env_pc is not None and env_pc.runs_in("Production") is not True else None
        line = link.get("line", 0)
        self.consumed.add(id(link))
        for path in _SWAGGER_PATHS:
            if (path, env) in self.seen_mw:
                continue
            self.seen_mw.add((path, env))
            meta: dict = {"kind": "openapi", "api_surface": False, "middleware": True}
            if env:
                meta["env"] = env
            route = Route(path=path, methods=["GET"], handler_name=name, file=pc.file if pc is not None else fr.type.file,
                          line=line, source_start_line=line, source_end_line=line, meta=meta)
            self.entries.append(_Entry(CoreRouteRef(route, None, None, self.proj, style="endpoint",
                                                    caller_unknown=not fr.reached), _Node(None)))

    def find_type(self, text: str | None) -> TypeIR | None:
        if not text:
            return None
        simple = text.split("<")[0].split(".")[-1]
        cands = [t for t in self.model.find_types(simple)
                 if self.proj is None or self.model.project_of(t.file) is self.proj]
        return cands[0] if cands else None

    def resolve_handler(self, fr: _Frame, arg) -> tuple:
        """(declaring type, MethodIR, handler name, note) of a handler argument."""
        if isinstance(arg, dict):
            k = arg.get("k")
            if k == "lambda":
                m = _lambda_method(arg)
                return fr.type, m, m.name, None
            if k == "name":
                nm = arg.get("id") or ""
                if nm in fr.fns:
                    self.called_fns.add(id(fr.fns[nm]))
                    return fr.type, _lambda_method(fr.fns[nm], nm), nm, None
                hit = next((m for m in fr.type.methods if m.name == nm), None)
                if hit is not None:
                    return fr.type, hit, f"{fr.type.name.split('.')[-1]}.{nm}", None
            elif k == "member":
                recv = receiver_text(arg.get("obj"))
                nm = arg.get("name") or ""
                owners = [fr.type] if recv == "this" else (self.model.find_types(recv.split(".")[-1]) if recv else [])
                for ot in owners:
                    hit = next((m for m in ot.methods if m.name == nm), None)
                    if hit is not None:
                        return ot, hit, f"{ot.name.split('.')[-1]}.{nm}", None
        text = receiver_text(arg) or "<expression>"
        return fr.type, None, text, f"handler {text} not resolved"


def discover_endpoints(model: ProjectModel) -> list[CoreRouteRef]:
    """Minimal-API routes (Map{Get,Post,..}/MapMethods/Map, through groups and followed methods)
    and the other endpoint registrations (hubs, gRPC, health checks, fallbacks, OpenAPI)."""
    refs: list[CoreRouteRef] = []
    for proj in list(model.projects) or [None]:
        refs.extend(_Scan(model, proj).run())
    return refs


def discover_all(model: ProjectModel) -> list[CoreRouteRef]:
    """Controllers, Razor Pages and endpoints, computed once per model."""
    if "core_routes" not in model.cache:
        model.cache["core_routes"] = discover_controllers(model) + discover_pages(model) + discover_endpoints(model)
    return model.cache["core_routes"]
