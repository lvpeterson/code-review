"""Route discovery for ASP.NET Core: controllers (attribute and conventional routing).

Routes come from [Route]/[Http*] templates on the controller and its actions, or
from the conventional templates registered with MapControllerRoute /
MapDefaultControllerRoute / MapAreaControllerRoute. Auth is not resolved here;
each route carries the fluent calls chained on the mapping call (convention_calls)
so the auth pass can see `MapControllers().RequireAuthorization()`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from checks.dnl.ir import MethodIR, TypeIR, attr_key, const_str, has_attr, literal_str
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


def _simple(name: str) -> str:
    return name.split("<")[0].split(".")[-1].lower()


def _chain_types(model: ProjectModel, t: TypeIR) -> list[TypeIR]:
    """The type then its project base types, nearest first (external bases are not types)."""
    out = [t]
    for b in model.base_chain(t):
        out.extend(bt for bt in model.find_types(b) if all(bt is not o for o in out))
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


def discover_controllers(model: ProjectModel) -> list[CoreRouteRef]:
    refs: list[CoreRouteRef] = []
    global_maps: list[_Mapping] | None = None
    for t in model.types():
        chain = _chain_types(model, t)
        if not _is_controller(model, t, chain):
            continue
        proj = model.project_of(t.file)
        maps = _mappings(pipeline_for(model, proj).named(*_MAP_NAMES, include_dev=True)) if proj is not None else []
        if not maps:
            # A controllers library is mapped by its host project: fall back to every mapping call in the scan.
            if global_maps is None:
                global_maps = _mappings(pipeline_for(model, None).named(*_MAP_NAMES, include_dev=True))
            maps = global_maps
        refs.extend(_controller_routes(model, t, chain, maps))
    return refs


def _controller_routes(model: ProjectModel, t: TypeIR, chain: list[TypeIR], maps: list[_Mapping]) -> list[CoreRouteRef]:
    controller, area = _controller_name(t), _area(chain)
    api = _api_surface(model, t, chain)
    proj = model.project_of(t.file)
    class_tmpls = [x for x in (_template(a) for a in _inherited(chain, "Route")) if x is not None]

    unknown: list[str] = []
    # Attribute routes are served by whichever controller mapping call is registered; prefer MapControllers.
    attr_map = next((m for m in maps if m.name == "MapControllers"), maps[0] if maps else None)
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
        unknown.append("a conventional route maps controllers through defaults, which are not resolved")

    simple = t.name.split(".")[-1]
    refs: list[CoreRouteRef] = []
    for m, decl in action_candidates(model, t):
        action = _action_name(m)
        seen: set[tuple[str, tuple[str, ...]]] = set()

        def add(path: str, verbs: list[str] | None, mapping: _Mapping | None, assumed: bool = False) -> None:
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
            refs.append(CoreRouteRef(route, t, m, proj, style="controller",
                                     convention_calls=_tail(mapping.call) if mapping else [],
                                     unknown=list(unknown)))

        conv_verbs: list[str] | None = None
        conventional = False
        for sel_tmpl, verbs in _selectors(m):
            raws = _attribute_paths(class_tmpls, sel_tmpl)
            if raws is None:
                conventional, conv_verbs = True, verbs
                continue
            for raw in raws:
                add(_attribute_path(raw, controller, action, area), verbs, attr_map)
        if conventional:
            for cm in conv:
                add(_conventional_path(cm.template, controller, action, area), conv_verbs, cm)
            if not conv:
                tmpl = _DEFAULT_AREA_TEMPLATE if area else _DEFAULT_TEMPLATE
                add(_conventional_path(tmpl, controller, action, area), conv_verbs, None, assumed=True)
    return refs
