"""Inter-procedural layer of the legacy .NET taint engine.

`solve` computes a Summary per project method by running taint.analyze_method on
every method once per round (a round reads only the previous round's summaries,
so recursion is safe) until nothing changes or the round cap is hit. A Summary
says which sinks a parameter reaches, what flows to the return value and which
of the object's fields a parameter is stored in. Per-type `field_taint` (request
sources written to a field by any method of the type) is recomputed each round
from the previous round's writes, so a value stored in Page_Load is visible in a
click handler.

`resolve_call` maps a call expression to project method candidates (sym first,
then this/base, then the receiver's declared type, with interface / abstract
dispatch to every implementation, then static `Type.Method`).

`entry_hits` replays the entry points (MVC / Web API actions with request
parameters tainted, every WebForms page method) over the final summaries and
adds hits from non-entry methods: proven when they read a request source
themselves, unproven (ref None) when only their own parameters are tainted and
nothing outside their call cycle calls them. Rows are deduplicated per (sink,
route) after collection, so the result is independent of iteration order.

Convergence: `model.cache["taint"]` holds `converged` (False when MAX_ROUNDS, 24, was hit
before the summaries stabilised) and `rounds`; callers should note a non-converged scan.
It also lists `truncated_methods` (a body nested too deeply to evaluate fully) and
`failed_methods` (analysis raised; the method contributes an empty summary), both as
`Type.Method` names, for the caller to turn into scan notes.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from checks.dnl import taint as TN
from checks.dnl.ir import MethodIR, ParamIR, TypeIR, attr_key, has_attr
from checks.dnl.taint import Origin, SinkHit, Taint, merge

MAX_ROUNDS = 24
_THIS = ("this", "me", "base", "mybase", "myclass")
_VIRTUAL = {"abstract", "mustoverride", "virtual", "overridable", "override", "overrides"}


@dataclass
class Summary:
    param_sinks: dict[int, list[SinkHit]]
    param_to_ret: frozenset
    ret_source: Taint | None
    # Parameter i is stored in a field of the target object (R4) ...
    param_to_this: frozenset = frozenset()
    # ... and these are the field keys written from parameters.
    this_fields: frozenset = frozenset()
    # Sink kinds the callee cleanses on the parameter -> return path.
    ret_cleansed: frozenset = frozenset()


@dataclass
class EntryHit:
    """One sink hit and the entry point it belongs to.

    `proven` is True iff the hit's taint includes a request-source origin. Proven hits
    carry the entry `ref` that reaches them, or `ref=None` when the method reads a
    source itself but no entry point reaches it. Unproven hits (`proven=False`,
    `ref=None`) are sinks fed only by their own method's parameters with no outside
    caller; consumers report those for review.
    """
    ref: Any                       # RouteRef, or None (see above)
    hit: SinkHit
    sources: list[Origin] = field(default_factory=list)
    proven: bool = False


# -- call resolution ------------------------------------------------------

def _simple(name: str | None) -> str:
    return TN._simple(name)


def _partials(model, t: TypeIR) -> list[TypeIR]:
    """All declarations of a (partial) type."""
    out = [d for d in model.find_types(t.name.split(".")[-1]) if d.full_name.lower() == t.full_name.lower()]
    return out or [t]


def _chain(model, t: TypeIR) -> list[TypeIR]:
    """The type's declarations, then each project base type's (nearest first)."""
    out = list(_partials(model, t))
    seen = {t.full_name.lower()}
    for b in model.base_chain(t):
        for bt in model.find_types(_simple(b)):
            if bt.full_name.lower() not in seen:
                out.append(bt)
        seen.update(bt.full_name.lower() for bt in model.find_types(_simple(b)))
    return out


def _derived_index(model) -> dict[str, list[TypeIR]]:
    """Lowered simple base / interface name -> project types that derive from it (transitively)."""
    idx = model.cache.get("taint_derived")
    if idx is None:
        idx = {}
        for t in model.types():
            for b in model.base_chain(t):
                idx.setdefault(_simple(b), []).append(t)
        model.cache["taint_derived"] = idx
    return idx


def _modules(model) -> dict[str, list[tuple[TypeIR, MethodIR]]]:
    """VB module members by lowered name (callable without a qualifier)."""
    idx = model.cache.get("taint_modules")
    if idx is None:
        idx = {}
        for t in model.types():
            if t.kind == "module":
                for m in t.methods:
                    idx.setdefault(m.name.lower(), []).append((t, m))
        model.cache["taint_modules"] = idx
    return idx


def _pick(methods: list[MethodIR], nargs: int) -> list[MethodIR]:
    """Overloads: exact argument count, else every overload of the name."""
    exact = [m for m in methods if len(m.params) == nargs]
    return exact or methods


def _methods_named(types: list[TypeIR], name: str, nargs: int, first_level_only: bool = False
                   ) -> list[tuple[TypeIR, MethodIR]]:
    """Methods of that name in the first type (declaration group) that has any, so an
    override wins over the base declaration. `types` is ordered nearest first."""
    low = name.lower()
    for t in types:
        ms = [m for m in t.methods if m.name.lower() == low]
        if ms:
            # partials of the same type share a level: gather them all
            level = [(d, m) for d in types if d.full_name.lower() == t.full_name.lower()
                     for m in d.methods if m.name.lower() == low]
            ms = _pick([m for _, m in level], nargs)
            return [(d, m) for d, m in level if m in ms]
    return []


def _expand(model, found: list[tuple[TypeIR, MethodIR]], nargs: int) -> list[tuple[TypeIR, MethodIR]]:
    """Interface / abstract / virtual targets also reach every derived implementation."""
    out = list(found)
    seen = {id(m) for _, m in out}
    idx = _derived_index(model)
    for owner, m in found:
        if owner.kind != "interface" and not (_VIRTUAL & {x.lower() for x in m.modifiers}):
            continue
        for d in idx.get(_simple(owner.name), []):
            # the implementation may be inherited from a base class of the implementer
            for dt, dm in _methods_named(_chain(model, d), m.name, nargs):
                if id(dm) not in seen:
                    seen.add(id(dm))
                    out.append((dt, dm))
    return out


def _extensions(model) -> dict[str, list[tuple[TypeIR, MethodIR]]]:
    """Extension methods (first parameter marked `this`) by lowered name."""
    idx = model.cache.get("taint_ext")
    if idx is None:
        idx = {}
        for t in model.types():
            for m in t.methods:
                if m.params and "this" in {x.lower() for x in m.params[0].modifiers}:
                    idx.setdefault(m.name.lower(), []).append((t, m))
        model.cache["taint_ext"] = idx
    return idx


def _types_for(model, tn: str, ns: str | None = None) -> list[TypeIR]:
    """Project types a type name denotes: the full name when it is qualified, else the
    simple name, preferring the caller's namespace when several types share it."""
    base = re.sub(r"<.*>|\(.*\)|\[\]|\?$", "", tn.strip())
    cands = model.find_types(_simple(tn))
    if "." in base:
        low = base.lower()
        exact = [t for t in cands if t.full_name.lower() == low or t.full_name.lower().endswith("." + low)]
        if exact:
            return exact
    if len(cands) > 1 and ns is not None:
        same = [t for t in cands if t.namespace.lower() == ns.lower()]
        if same:
            return same
    return cands


def _ext_applies(model, m: MethodIR, recv_type: str) -> bool:
    """Whether an extension applies to a receiver of type `recv_type`. It is rejected only when
    both the `this` type and the receiver type are project types and the receiver is neither
    that type nor a subtype; a framework type on either side applies by name. Keyword
    spellings (`int` / `Int32`, `string` / `String`) are equal on both sides."""
    pt = _simple(m.params[0].type)
    rt = _simple(recv_type)
    ext_types, recv_types = model.find_types(pt), model.find_types(rt)
    if not ext_types or not recv_types:
        return True                     # a framework type on either side: apply by name
    pn = TN._alias_names(pt)
    # both are project types: the receiver must be that type or a subtype
    return bool(pn & TN._alias_names(rt)) or any(
        pn & {n for b in model.base_chain(t) for n in TN._alias_names(_simple(b))} for t in recv_types)


def _ext_targets(model, name: str, nargs: int, recv_type: str | None = None) -> list[tuple[TypeIR, MethodIR]]:
    """Instance-form extension call: the receiver is the first parameter. With a known
    receiver type only extensions whose `this` type fits it apply."""
    cands = _extensions(model).get(name.lower(), [])
    if recv_type:
        cands = [c for c in cands if _ext_applies(model, c[1], recv_type)]
    exact = [c for c in cands if len(c[1].params) == nargs + 1]
    return exact or cands


def _lookup(env_types: dict[str, str], text: str) -> str | None:
    low = text.lower()
    for pre in ("this.", "me."):
        if low.startswith(pre):
            text, low = text[len(pre):], low[len(pre):]
    return env_types.get(text) or env_types.get(low)


def _expr_type(model, e: Any, env_types: dict[str, str]) -> str | None:
    """Declared / inferred type of a receiver expression, from the environment alone."""
    if not isinstance(e, dict):
        return None
    k = e.get("k")
    if k == "name":
        return _lookup(env_types, e.get("id") or "")
    if k == "member":
        obj, name = e.get("obj"), e.get("name") or ""
        if isinstance(obj, dict) and obj.get("k") == "name" and (obj.get("id") or "").lower() in ("this", "me"):
            return _lookup(env_types, name)
        ot = _expr_type(model, obj, env_types)
        if ot:
            for d in model.find_types(_simple(ot)):
                for f in list(d.fields) + list(d.properties):
                    if f.name.lower() == name.lower() and f.type:
                        return f.type
        return None
    if k == "new":
        return e.get("type_full") or e.get("type")
    if k == "cast":
        return e.get("type")
    return None


def resolve_call(model, caller_t: TypeIR, call: dict, env_types: dict[str, str], *,
                 type_of: Callable[[Any], str | None] | None = None,
                 with_target: dict | None = None) -> list[tuple[TypeIR, MethodIR]]:
    """Project (type, method) candidates for a call expression; [] for external calls.
    `type_of` lets the evaluator supply its richer receiver typing; `with_target` is the
    enclosing VB With object for `.Method()` calls."""
    fn = call.get("fn") or {}
    fk = fn.get("k")
    if fk == "member":
        name, recv = fn.get("name") or "", fn.get("obj")
        if recv is None:
            recv = with_target
    elif fk == "name":
        name, recv = fn.get("id") or "", None
    else:
        return []
    if not name:
        return []
    nargs = len(call.get("args") or []) + len(call.get("named") or {})

    # 1. semantic symbol: containing type full name + member
    sym = call.get("sym") or fn.get("sym")
    if sym:
        head, _, member = sym.rpartition(".")
        head = re.sub(r"<.*>$", "", head)
        if member.lower() == name.lower():
            owners = [d for d in model.find_types(head.split(".")[-1]) if d.full_name.lower() == head.lower()]
            if not owners:
                return []                       # resolved to an external type
            found = _methods_named(_chain(model, owners[0]), name, nargs)
            return _expand(model, found, nargs)

    from checks.dnl.ir import receiver_text
    text = receiver_text(recv) if recv is not None else ""
    low = text.lower()

    # 2. this / base / implicit receiver
    if recv is None or low in _THIS:
        chain = _chain(model, caller_t)
        if low in ("base", "mybase"):
            own = {d.full_name.lower() for d in _partials(model, caller_t)}
            chain = [d for d in chain if d.full_name.lower() not in own]
        found = _methods_named(chain, name, nargs)
        if not found and recv is None:
            # VB module members are callable without a qualifier
            mods = _modules(model).get(name.lower(), [])
            ms = _pick([m for _, m in mods], nargs)
            found = [(d, m) for d, m in mods if m in ms]
        return _expand(model, found, nargs)

    # 3. receiver with a declared / inferred type
    tn = type_of(recv) if type_of else None
    tn = tn or _expr_type(model, recv, env_types)
    if tn:
        types = _types_for(model, tn, caller_t.namespace)
        found = _methods_named([d for t in types for d in _chain(model, t)], name, nargs) if types else []
        return _expand(model, found, nargs) if found else _ext_targets(model, name, nargs, tn)

    # 4. static `Type.Method` by simple type name (head is not a variable)
    head = text.split(".")[0]
    if text and _lookup(env_types, head) is None:
        types = model.find_types(text.split(".")[-1])
        if types:
            found = _methods_named([d for t in types for d in _chain(model, t)], name, nargs)
            if found:
                return _expand(model, found, nargs)
    return _ext_targets(model, name, nargs)


# -- solving --------------------------------------------------------------

def _accessors(model, t: TypeIR) -> list[MethodIR]:
    """Property accessor bodies as synthetic methods (`get_X`, `set_X(value)`), cached."""
    cache = model.cache.setdefault("taint_accessors", {})
    got = cache.get(id(t))
    if got is None:
        got = []
        for p in t.properties:
            if p.get is not None:
                got.append(MethodIR(name=f"get_{p.name}", return_type=p.type, body=p.get, line=p.line, end_line=p.line))
            if p.set is not None:
                got.append(MethodIR(name=f"set_{p.name}", params=[ParamIR(p.set_param or "value", p.type)],
                                    body=p.set, line=p.line, end_line=p.line))
        cache[id(t)] = got
    return got


def _all_methods(model) -> list[tuple[TypeIR, MethodIR, bool]]:
    """(type, method, is_accessor) for every project method and property accessor."""
    out = []
    for t in model.types():
        out.extend((t, m, False) for m in t.methods)
        out.extend((t, m, True) for m in _accessors(model, t))
    return out


def _key(t: TypeIR, m: MethodIR) -> tuple[str, str, int]:
    return (t.full_name, m.name, m.line)


def _param_seeds(t: TypeIR, m: MethodIR) -> dict[int, Taint]:
    return {i: Taint(frozenset({Origin("param", str(i), t.file, m.line)}), frozenset())
            for i in range(len(m.params))}


def _param_idx(taint: Taint | None) -> set[int]:
    if taint is None or "*" in taint.cleansed:
        return set()
    return {int(o.detail) for o in taint.origins if o.kind == "param" and o.detail.isdigit()}


def _summarize(r: TN.MethodResult) -> Summary:
    sinks: dict[int, list[SinkHit]] = {}
    for h in r.hits:
        for i in sorted(int(o.detail) for o in h.taint.origins if o.kind == "param" and o.detail.isdigit()):
            sinks.setdefault(i, []).append(h)
    ret_src = None
    if r.ret is not None:
        keep = frozenset(o for o in r.ret.origins if o.kind != "param")
        if keep:
            ret_src = Taint(keep, r.ret.cleansed)
    to_this: set[int] = set()
    fields: set[str] = set()
    for fk, v in r.field_out.items():
        ps = _param_idx(v)
        if ps:
            to_this |= ps
            fields.add(fk)
    return Summary(sinks, r.param_to_ret, ret_src, frozenset(to_this), frozenset(fields),
                   r.ret.cleansed if r.ret is not None and r.param_to_ret else frozenset())


def _strip_params(v: Taint | None) -> Taint | None:
    if v is None:
        return None
    keep = frozenset(o for o in v.origins if o.kind != "param")
    return Taint(keep, v.cleansed) if keep else None


def _type_field_taint(model, t: TypeIR, ft: dict[str, dict]) -> dict[str, Taint]:
    """Field taint visible to a method of t: its own type's plus its project base types'."""
    out: dict[str, Taint] = {}
    for d in _chain(model, t):
        for k, v in ft.get(d.full_name.lower(), {}).items():
            out[k] = merge(out.get(k), v)
    return out


def solve(model) -> dict[tuple[str, str, int], Summary]:
    """Summary per project method, keyed (type full name, method name, method line)."""
    cached = model.cache.get("taint")
    if cached is not None:
        return cached["summaries"]
    methods = _all_methods(model)
    summaries: dict[tuple, Summary] = {}
    ft: dict[str, dict[str, Taint]] = {}
    results: dict[tuple, tuple] = {}
    ftc: dict[str, dict] = {}
    rounds, converged = 0, False
    truncated: list[str] = []
    failed: list[str] = []
    for rounds in range(1, MAX_ROUNDS + 1):
        truncated, failed = [], []
        new_sums: dict[tuple, Summary] = {}
        new_ft: dict[str, dict[str, Taint]] = {}
        ftc.clear()
        for t, m, acc in methods:
            key = _key(t, m)
            if not m.body:
                new_sums[key] = Summary({}, frozenset(), None)
                continue
            lk = t.full_name.lower()
            if lk not in ftc:
                ftc[lk] = _type_field_taint(model, t, ft)
            try:
                r = TN.analyze_method(model, t, m, param_taint=_param_seeds(t, m), field_taint=ftc[lk],
                                      summaries=summaries)
            except Exception:       # one broken method must not abort the scan
                failed.append(f"{t.name}.{m.name}")
                new_sums[key] = Summary({}, frozenset(), None)
                continue
            if r.truncated:
                truncated.append(f"{t.name}.{m.name}")
            new_sums[key] = _summarize(r)
            results[key] = (t, m, acc, r)
            bucket = new_ft.setdefault(lk, {})
            for fk, v in r.field_out.items():
                sv = _strip_params(v)
                if sv is not None:
                    bucket[fk] = merge(bucket.get(fk), sv)
        changed = new_sums != summaries or new_ft != ft
        summaries, ft = new_sums, new_ft
        if not changed:
            converged = True
            break
    model.cache["taint"] = {"summaries": summaries, "ft": ft, "results": results,
                            "converged": converged, "rounds": rounds,
                            "truncated_methods": truncated, "failed_methods": failed}
    return summaries


# -- entry points ---------------------------------------------------------

_SAFE_PARAM = {"byte", "sbyte", "short", "ushort", "int", "uint", "long", "ulong", "float", "double", "decimal",
               "bool", "char", "integer", "boolean", "single", "date", "datetime", "datetimeoffset", "timespan",
               "guid", "cancellationtoken", "int16", "int32", "int64", "uint16", "uint32", "uint64"}
_NULLABLE_INNER = re.compile(r"(?i)^(?:system\.)?nullable\s*(?:<\s*([\w.]+)\s*>|\(\s*of\s+([\w.]+)\s*\))")


def _tainted_param_type(model, tn: str | None) -> bool:
    """False for parameter types that cannot carry an injection payload."""
    if not tn:
        return True
    mo = _NULLABLE_INNER.match(tn.strip())
    if mo:
        tn = mo.group(1) or mo.group(2)
    if tn.strip().endswith("[]"):
        return True
    simple = _simple(tn)
    if simple in _SAFE_PARAM:
        return False
    return not any(d.kind == "enum" for d in model.find_types(simple))


def _entry_taint(model, t: TypeIR, m: MethodIR) -> dict[int, Taint]:
    out: dict[int, Taint] = {}
    for i, p in enumerate(m.params):
        if _tainted_param_type(model, p.type):
            o = Origin("source", f"request parameter {p.name}", t.file, m.line)
            out[i] = Taint(frozenset({o}), frozenset())
    return out


# -- ASP.NET Core parameter binding ---------------------------------------
# Legacy MVC keeps `_entry_taint` (every non-primitive parameter is request input). For a Core
# route a parameter is request input unless the framework fills it from the container or the
# request cannot carry it (plan Decision 1); `[BindProperty]` properties are request input too
# (Decision 2).

_CORE_FRAMEWORK = frozenset("""httpcontext httprequest httpresponse cancellationtoken claimsprincipal ilogger
iloggerfactory iconfiguration iwebhostenvironment ihostenvironment iserviceprovider ioptions ioptionssnapshot
ioptionsmonitor ihttpclientfactory httpclient iauthorizationservice usermanager signinmanager linkgenerator
iurlhelper""".split())
# Interfaces the binder fills from the request (files, form) or builds a concrete collection for.
_CORE_BINDABLE_IFACES = frozenset("""iformfile iformfilecollection iformcollection ienumerable icollection ilist
iset ireadonlylist ireadonlycollection ireadonlyset idictionary ireadonlydictionary iasyncenumerable
ihtmlcontent""".split())
_EXTERNAL_IFACE = re.compile(r"^I[A-Z][a-z]")
# An explicit binding source (or [AsParameters]) overrides every type-based exclusion.
_BIND_SOURCE_ATTRS = ("FromBody", "FromQuery", "FromForm", "FromRoute", "FromHeader", "AsParameters")
_SERVICE_ADDS = ("AddScoped", "AddTransient", "AddSingleton", "AddKeyedScoped", "AddKeyedTransient",
                 "AddKeyedSingleton", "TryAddScoped", "TryAddTransient", "TryAddSingleton", "TryAddKeyedScoped",
                 "TryAddKeyedTransient", "TryAddKeyedSingleton", "AddDbContext", "AddDbContextPool", "AddHttpClient")
_USING_RE = re.compile(r"(?m)^\s*(global\s+)?using\s+([A-Za-z_][\w.]*)\s*;")
_DB_CONTEXTS = {"dbcontext", "identitydbcontext"}


def _bare(text: str | None) -> tuple[str, str]:
    """(type head, generic argument text) of a type name: nullable marks, `global::` and spacing dropped."""
    t = (text or "").replace(" ", "").rstrip("?")
    if t.startswith("global::"):
        t = t[len("global::"):]
    head, _, rest = t.partition("<")
    return head, rest.rstrip(">").lower()


def _read(model, rel: str) -> str:
    try:
        return (model.root / rel).read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""


def _type_index(model) -> dict:
    """Project types by lowered full name, plus the usings of each file (read lazily) and every
    `global using` of the model."""
    idx = model.cache.get("core_type_index")
    if idx is None:
        full: dict[str, list[TypeIR]] = {}
        for t in model.types():
            full.setdefault(t.full_name.lower(), []).append(t)
        glob: set[str] = set()
        for rel in model.files:
            glob.update(m.group(2).lower() for m in _USING_RE.finditer(_read(model, rel)) if m.group(1))
        idx = model.cache["core_type_index"] = {"full": full, "global": glob, "files": {}}
    return idx


def _file_usings(model, rel: str, proj) -> set[str]:
    idx = _type_index(model)
    if rel not in idx["files"]:
        idx["files"][rel] = {m.group(2).lower() for m in _USING_RE.finditer(_read(model, rel))}
    out = set(idx["files"][rel]) | idx["global"]
    if proj is not None:
        out.update(u.lower() for u in proj.global_usings)
    return out


def _type_keys(model, text: str | None, rel: str, ns: str, proj, strict: bool) -> frozenset[str]:
    """Identity keys of the type a name refers to from code in file `rel`, namespace `ns`:
    `t:<full name>` for project types, `~<simple name>` for anything else, each with the generic
    argument text. A simple name follows the C# lookup order (enclosing namespaces, then the
    global namespace, then using directives); an ambiguous name yields every candidate.
    `strict` (registrations) yields nothing when no candidate is in scope, where the lenient
    form (parameters) yields every project type of the name."""
    head, args = _bare(text)
    if not head:
        return frozenset()
    suffix = f"<{args}>" if args else ""
    full = _type_index(model)["full"]
    parts = ns.split(".") if ns else []
    if "." in head:
        for i in range(len(parts), -1, -1):
            hit = full.get(".".join(parts[:i] + [head]).lower())
            if hit:
                return frozenset(f"t:{t.full_name.lower()}{suffix}" for t in hit)
        return frozenset({f"~{head.rsplit('.', 1)[-1].lower()}{suffix}"})
    cands = [t for t in model.find_types(head) if "." not in t.name]
    if not cands:
        return frozenset({f"~{head.lower()}{suffix}"})
    if len(cands) == 1:
        return frozenset({f"t:{cands[0].full_name.lower()}{suffix}"})
    for i in range(len(parts), 0, -1):
        inner = ".".join(parts[:i]).lower()
        hit = [t for t in cands if t.namespace.lower() == inner]
        if hit:
            return frozenset(f"t:{t.full_name.lower()}{suffix}" for t in hit)
    usings = _file_usings(model, rel, proj)
    hit = [t for t in cands if not t.namespace] or [t for t in cands if t.namespace.lower() in usings]
    if hit:
        return frozenset(f"t:{t.full_name.lower()}{suffix}" for t in hit)
    return frozenset() if strict else frozenset(f"t:{t.full_name.lower()}{suffix}" for t in cands)


def _enclosing_ns(model, rel: str, line: int) -> str:
    """Namespace of the type declared around `line` of a file ("" for top-level statements)."""
    f = model.files.get(rel)
    if f is None:
        return ""
    hit = [t for t in f.types if t.line <= line <= (t.end_line or t.line)]
    if hit:
        return hit[0].namespace
    return f.types[0].namespace if len(f.types) == 1 else ""


def core_services(model, proj) -> frozenset[str]:
    """Identity keys of the types the project registers in the container: the first type argument of
    every registration that certainly runs in Production (a registration that may not run
    leaves the type a request source, the safe side)."""
    cache = model.cache.setdefault("core_services", {})
    pk = id(proj) if proj is not None else None
    if pk not in cache:
        from checks.dnl import pipeline
        keys: set[str] = set()
        for c in pipeline.pipeline_for(model, proj).named(*_SERVICE_ADDS, kinds=("services",)):
            targs = (c.node.get("fn") or {}).get("targs") or []
            if targs:
                keys |= _type_keys(model, targs[0], c.file, _enclosing_ns(model, c.file, c.line), proj, True)
        cache[pk] = frozenset(keys)
    return cache[pk]


def _derives_any(model, t: TypeIR, names: set[str]) -> bool:
    return any(_bare(b)[0].rsplit(".", 1)[-1].lower() in names for b in model.base_chain(t))


def _core_type_excluded(model, text: str | None, rel: str, ns: str, proj, services: frozenset[str]) -> bool:
    """True when a value of this type is never request input on a Core route."""
    head, _args = _bare(text)
    if not head or head.endswith("[]"):
        return False
    last = head.rsplit(".", 1)[-1]
    simple = last.lower()
    keys = _type_keys(model, text, rel, ns, proj, False)
    if keys and keys <= services:
        return True
    full = _type_index(model)["full"]
    cands = [t for k in keys if k.startswith("t:") for t in full.get(k[2:].split("<")[0], [])]
    if not cands:
        if simple in _CORE_FRAMEWORK:
            return True
        return bool(_EXTERNAL_IFACE.match(last)) and simple not in _CORE_BINDABLE_IFACES
    # A project type named like a framework type is judged as the project type (never silently safe).
    if all(_derives_any(model, t, _DB_CONTEXTS) for t in cands):
        return True
    return simple not in _CORE_BINDABLE_IFACES and all(
        t.kind == "interface" or "abstract" in [x.lower() for x in t.modifiers] for t in cands)


def _owners(model) -> dict[int, TypeIR]:
    own = model.cache.get("taint_owner")
    if own is None:
        own = model.cache["taint_owner"] = {id(m): t for t, m, _acc in _all_methods(model)}
    return own


def core_param_taint(model, ref) -> dict[int, Taint]:
    """Request-input taint of a Core handler's parameters (see the block comment above)."""
    m = ref.method
    t = _owners(model).get(id(m), ref.type)
    ns = (ref.type or t).namespace
    services = core_services(model, ref.project)
    out: dict[int, Taint] = {}
    for i, p in enumerate(m.params):
        if not _tainted_param_type(model, p.type):
            continue
        if has_attr(p.attributes, "FromServices", "FromKeyedServices"):
            continue
        if not has_attr(p.attributes, *_BIND_SOURCE_ATTRS) \
                and _core_type_excluded(model, p.type, t.file, ns, ref.project, services):
            continue
        o = Origin("source", f"request parameter {p.name}", t.file, m.line)
        out[i] = Taint(frozenset({o}), frozenset())
    return out


_ON_GET = re.compile(r"^On(?:Get|Head)(?![a-z])")


def _handler_is_get(m: MethodIR) -> bool | None:
    """True for a GET/HEAD-only handler, False for another verb, None when the verb is unknown."""
    if re.match(r"^On[A-Z]", m.name):
        return bool(_ON_GET.match(m.name))
    verbs = {attr_key(a.name) for a in m.attributes} & {"httpget", "httphead", "httppost", "httpput", "httpdelete",
                                                        "httppatch", "acceptverbs"}
    if not verbs or "acceptverbs" in verbs:
        return None
    return verbs <= {"httpget", "httphead"}


def _supports_get(a) -> bool:
    v = (a.named or {}).get("SupportsGet")
    return isinstance(v, dict) and v.get("v") is True


def _bound(model, t: TypeIR, method: MethodIR, proj) -> dict[str, tuple[str, int]]:
    """Bound property name (lowered) -> (file, line) of its declaration."""
    get = _handler_is_get(method) is True
    services = core_services(model, proj)
    out: dict[str, tuple[str, int]] = {}
    for d in _chain(model, t):
        cls = has_attr(d.attributes, "BindProperties")
        for p in d.properties:
            attr = has_attr(p.attributes, "BindProperty") or cls
            if attr is None or has_attr(p.attributes, "BindNever", "FromServices", "FromKeyedServices"):
                continue
            if get and not _supports_get(attr):
                continue
            if not _tainted_param_type(model, p.type) or _core_type_excluded(model, p.type, d.file, d.namespace, proj, services):
                continue
            out.setdefault(p.name.lower(), (d.file, p.line))
    return out


def bound_properties(model, t: TypeIR, method: MethodIR, proj=None) -> set[str]:
    """Lower-cased names of the properties that are request input for this handler: `[BindProperty]`
    properties (every property when a class in the chain has `[BindProperties]`; the IR does not
    say whether a setter exists) of the page model / controller and its project bases; for a
    GET/HEAD handler only those with `SupportsGet = true`. An unknown verb counts as non-GET.
    `[BindNever]` / `[FromServices]` properties and types the request cannot carry are left out."""
    return set(_bound(model, t, method, proj))


def _bound_origins(model, t: TypeIR, method: MethodIR, proj) -> dict[str, Taint]:
    """Field taint for the entry replay: one `[BindProperty] <Name>` source per bound property."""
    names = {}
    for d in _chain(model, t):
        for p in d.properties:
            names.setdefault(p.name.lower(), p.name)
    return {names[k]: Taint(frozenset({Origin("source", f"[BindProperty] {names[k]}", f, line)}), frozenset())
            for k, (f, line) in _bound(model, t, method, proj).items()}


def _sources(h: SinkHit) -> list[Origin]:
    return sorted((o for o in h.taint.origins if o.kind == "source"), key=lambda o: (o.detail, o.file, o.line))


def _components(edges: dict, nodes: list) -> dict:
    """Strongly connected component id per node (iterative Tarjan)."""
    index: dict = {}
    low: dict = {}
    on: set = set()
    stack: list = []
    comp: dict = {}
    counter = 0
    ncomp = 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, iter(sorted(edges.get(root, ()))))]
        index[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on.add(root)
        while work:
            v, it = work[-1]
            for w in it:
                if w not in index:
                    index[w] = low[w] = counter
                    counter += 1
                    stack.append(w)
                    on.add(w)
                    work.append((w, iter(sorted(edges.get(w, ())))))
                    break
                if w in on:
                    low[v] = min(low[v], index[w])
            else:
                work.pop()
                if work:
                    u = work[-1][0]
                    low[u] = min(low[u], low[v])
                if low[v] == index[v]:
                    while True:
                        w = stack.pop()
                        on.discard(w)
                        comp[w] = ncomp
                        if w == v:
                            break
                    ncomp += 1
    return comp


def external_hits(model) -> list[SinkHit]:
    """Sink hits (one per kind / file / line) whose taint carries an outbound-response origin and no request-source origin, over
    every project method. Only DNL-CONSUME-002 reads these; `entry_hits` never returns them."""
    solve(model)
    out: dict[tuple, SinkHit] = {}
    for _key_, (_t, _m, _acc, r) in sorted(model.cache["taint"]["results"].items(), key=lambda kv: str(kv[0])):
        for h in r.hits:
            kinds = {o.kind for o in h.taint.origins}
            # Flows that also carry request input are already INJ / PATH / REDIR findings.
            if "external" in kinds and "source" not in kinds:
                out.setdefault((h.kind, h.file, h.line), h)
    return [out[k] for k in sorted(out, key=lambda k: (k[1], k[2], k[0]))]


def entry_hits(model, refs: list) -> list[EntryHit]:
    """Sink hits mapped to the entry point that reaches them (see module docstring)."""
    from checks.dnl.routes_core import CoreRouteRef
    solve(model)
    state = model.cache["taint"]
    summaries, ft, results = state["summaries"], state["ft"], state["results"]
    owner = {id(m): t for t, m, _acc in _all_methods(model)}
    ftc: dict[str, dict] = {}

    def field_taint(t: TypeIR) -> dict:
        lk = t.full_name.lower()
        if lk not in ftc:
            ftc[lk] = _type_field_taint(model, t, ft)
        return ftc[lk]

    # entry methods -> refs
    entries: list[tuple[Any, TypeIR, MethodIR, bool]] = []     # (ref, type, method, taint request params)
    for ref in refs:
        if ref.type is None:
            continue
        if ref.method is not None:
            decl = owner.get(id(ref.method), ref.type)
            entries.append((ref, decl, ref.method, True))
        else:
            for d in _partials(model, ref.type):
                for m in d.methods:
                    entries.append((ref, d, m, False))

    # Candidate rows (ref, hit) are collected first and deduplicated afterwards, so the
    # result does not depend on method iteration order.
    cands: list[tuple[Any, SinkHit]] = []
    entry_ids: set[int] = set()
    entry_keys: list[tuple[Any, tuple]] = []
    extra_calls: dict[tuple, set] = {}
    for ref, t, m, req in entries:
        entry_ids.add(id(m))
        entry_keys.append((ref, _key(t, m)))
        if not m.body:
            continue
        try:
            ftaint = field_taint(t)
            if not req:
                ptaint = None
            elif isinstance(ref, CoreRouteRef):
                ptaint = core_param_taint(model, ref)
                bound = _bound_origins(model, t, m, ref.project)
                if bound:
                    ftaint = {**ftaint, **{k: merge(ftaint.get(k), v) for k, v in bound.items()}}
            else:
                ptaint = _entry_taint(model, t, m)
            r = TN.analyze_method(model, t, m, param_taint=ptaint, field_taint=ftaint, summaries=summaries)
        except Exception:
            name = f"{t.name}.{m.name}"
            if name not in state["failed_methods"]:
                state["failed_methods"].append(name)
            continue
        if _key(t, m) not in results:
            # A synthetic handler (minimal-API lambda / local function) is not a solved method: its
            # callees come from this replay so they are attributed to its route.
            extra_calls.setdefault(_key(t, m), set()).update(r.calls)
        for h in r.hits:
            if any(o.kind == "source" for o in h.taint.origins):
                cands.append((ref, h))

    # call graph from the final-round results
    callees: dict[tuple, set] = {}
    callers: dict[tuple, set] = {}
    for key, (t, m, acc, r) in results.items():
        for c in r.calls:
            callees.setdefault(key, set()).add(c)
            callers.setdefault(c, set()).add(key)
    for key, cs in extra_calls.items():
        callees.setdefault(key, set()).update(cs)
    reachable: dict[tuple, set] = {}
    reach: dict[tuple, list] = {}
    for ref, key in entry_keys:
        if key not in reachable:
            seen_k, stack = set(), [key]
            while stack:
                cur = stack.pop()
                if cur not in seen_k:
                    seen_k.add(cur)
                    stack.extend(callees.get(cur, ()))
            reachable[key] = seen_k
        for k2 in reachable[key]:
            lst = reach.setdefault(k2, [])
            if not any(x is ref for x in lst):
                lst.append(ref)

    # A method counts as called only when something outside its whole call cycle
    # (strongly connected component) calls it, or an entry point sits in the cycle.
    scc = _components(callees, list(results))
    called: set[int] = {scc[k] for _, k in entry_keys if k in scc}
    for key in results:
        called.update(scc[key] for c in callers.get(key, ()) if scc.get(c) != scc[key])
    for key, (t, m, acc, r) in results.items():
        if id(m) in entry_ids:
            continue
        for h in r.hits:
            if any(o.kind == "source" for o in h.taint.origins):
                for ref in reach.get(key) or [None]:
                    cands.append((ref, h))
            elif scc[key] not in called and not (h.taint.origins and all(o.kind == "external" for o in h.taint.origins)):
                # only the method's own parameters are tainted and nothing outside its
                # call cycle calls it. A flow that starts at an outbound response alone (origin
                # kind "external") is DNL-CONSUME-002's, never a request-source row.
                cands.append((None, h))

    def loc(h: SinkHit) -> tuple:
        return (h.kind, h.sink, h.file, h.line)

    def rank(ref, h: SinkHit) -> tuple:
        # per route a chained copy (names the entry) beats an unchained one, then shortest
        proven = any(o.kind == "source" for o in h.taint.origins)
        return (not h.via, len(h.via), h.via) if ref is not None else (not proven, len(h.via), h.via)

    best: dict[tuple, tuple] = {}
    for ref, h in cands:
        k = (loc(h), id(ref) if ref is not None else None)
        if k not in best or rank(ref, h) < rank(*best[k]):
            best[k] = (ref, h)
    proven_locs = {loc(h) for _ref, h in cands if any(o.kind == "source" for o in h.taint.origins)}
    rows = []
    for (lc, _rid), (ref, h) in best.items():
        src = _sources(h)
        if not src and lc in proven_locs:
            continue                    # a sink with a proven row never also gets an unproven one
        rows.append(EntryHit(ref, h, src, bool(src)))
    rows.sort(key=lambda x: (x.hit.file, x.hit.line, x.hit.kind, x.hit.sink,
                             (x.ref.route.path, x.ref.route.handler_name) if x.ref is not None else ("", ""),
                             x.hit.via))
    return rows
