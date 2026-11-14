"""Resource and inventory rules: DNL-RES-002 (unbounded list endpoint), DNL-RES-003 (file upload with no
size check) and DNL-INV-002 (HelpPage / Swagger UI without auth, test and debug controllers).

RES-002 interprets an action's body in order, tracking locals that hold an EF query (a `DbSet`
property of a project DbContext, `Set<T>()`, or a project method that returns one). The returned
value is an unbounded list when it is such a query, not reduced to a scalar (`First`, `Count`,
`Find` ...) and not bounded by a `Take` / `ToPagedList` / `Paginate` applied to THAT query -- a Take on
a different query in the same method, or a page-size parameter the body never applies, does not count.
`Skip` alone does not bound a result. `[EnableQuery(PageSize = N)]` (or `[Queryable(PageSize = N)]`)
on the action, its controller, a base controller, or registered at startup, counts.

RES-003 treats `SaveAs`, `InputStream.CopyTo`, `File.WriteAllBytes` of the posted stream and Web API
`ReadAsMultipartAsync` as the save, and a `ContentLength` / `InputStream.Length` comparison as a size
check only when it guards the save: the save sits in the branch that passed the check, or follows an
`if` whose failing branch returns / throws / continues. A check that is present but does not stop the
save (the failing branch only adds a model error) does not count. A helper method that validates the
upload is not followed. web.config `maxRequestLength` is global and usually huge, so it is not
treated as protection.

INV-002 reports the Web API HelpPage area (its `HelpController`, or the `HelpPageAreaRegistration`
when the controller lives in a package) unless an authorize attribute or global filter covers it,
Swashbuckle / NSwag `EnableSwagger*` / `UseSwagger*` unless web.config denies anonymous users for
`swagger` (the Swagger UI is served by a message handler, so a global authorize filter does not
cover it), and controllers named like test or debug endpoints in non-test projects.
"""
from __future__ import annotations

import json
import re

from checks.dnl import auth
from checks.dnl.findings import dnl_finding
from checks.dnl.flowutil import Ctx, attrs_of, lit_bool, own_level, stmt_exprs, terminates, tokens, uncond_nodes, walk_nl
from checks.dnl.ir import call_name, has_attr, literal_str, receiver_text, walk
from checks.dnl.rules_flows import startup_auth_filters, startup_nodes
from checks.dnl.rules_object import _dbset_map
from checks.dnl.typestate import simple
from core.models import Finding

# -- RES-002 --------------------------------------------------------------------------

_PAGERS = {"take", "topagedlist", "topagedlistasync", "paginate", "topaged", "topagedresult", "limit",
           "getpaged", "topageddata"}
_SCALAR = {"first", "firstordefault", "firstasync", "firstordefaultasync", "single", "singleordefault",
           "singleasync", "singleordefaultasync", "last", "lastordefault", "count", "countasync", "longcount",
           "any", "anyasync", "all", "sum", "sumasync", "max", "min", "average", "find", "findasync",
           "contains", "elementat", "elementatordefault", "remove", "add", "attach", "executesqlcommand"}
_WRAPPERS = {"ok", "json", "view", "partialview", "content", "createresponse", "jsonresult", "negotiatedresult",
             "created", "accepted", "ajax"}


_LISTERS = {"tolist", "toarray", "tolistasync", "toarrayasync", "asenumerable", "todictionary", "todictionaryasync",
            "tohashset", "tolookup"}


class _Q:
    """(is a DbSet query, bounded by a pager, reduced to a scalar, already materialized). A pager applied
    after materialization (`db.Orders.ToList().Take(10)`) trims the response, not the query, so it does
    not bound anything."""
    __slots__ = ("query", "bounded", "scalar", "mat", "weak")

    def __init__(self, query=False, bounded=False, scalar=False, mat=False, weak=False):
        # weak: the only limit is a Take whose count is an unclamped parameter (the caller picks the size).
        self.query, self.bounded, self.scalar, self.mat, self.weak = query, bounded, scalar, mat, weak


def _take_kind(m, arg) -> str:
    """"max" for `Take(int.MaxValue)`, "param" for a count that is a bare action parameter (or a member of
    one) with no clamp, else "ok" (a literal, a constant, `Math.Min(n, 100)`, a local)."""
    if not isinstance(arg, dict):
        return "ok"
    if arg.get("k") == "member" and (arg.get("name") or "").lower() == "maxvalue":
        return "max"
    if any(x.get("k") == "call" and (call_name(x) or "").lower() in ("min", "clamp") for x in walk_nl(arg)):
        return "ok"
    params = {p.name.lower() for p in m.params} if m is not None else set()
    root = arg
    while isinstance(root, dict) and root.get("k") == "member":
        root = root.get("obj")
    if isinstance(root, dict) and root.get("k") == "name" and (root.get("id") or "").lower() in params:
        return "param"
    return "ok"


def _query_of(ctx: Ctx, t, m, e, state: dict, dbsets: dict, depth: int = 2) -> _Q:
    if not isinstance(e, dict):
        return _Q()
    k = e.get("k")
    if k == "name":
        return state.get((e.get("id") or "").lower(), _Q())
    if k == "member":
        nm = (e.get("name") or "").lower()
        if nm in dbsets and e.get("obj") is not None:
            return _Q(query=True)
        inner = _query_of(ctx, t, m, e.get("obj"), state, dbsets, depth)
        if inner.query and (nm in _SCALAR or nm == "length"):
            return _Q(True, inner.bounded, True, inner.mat, inner.weak)
        # Any other property read on it: the DbSet-named member was an entity's navigation property
        # (`setting.ApplicationSetting.Value`), not the set -- no list comes out of it.
        return _Q() if inner.query and not inner.mat else inner
    if k == "cast":
        return _query_of(ctx, t, m, e.get("e"), state, dbsets, depth)
    if k == "call":
        nm = (call_name(e) or "").lower()
        fn = e.get("fn") or {}
        args = e.get("args") or []
        if nm == "set" and fn.get("k") == "member":
            return _Q(query=True)
        if nm in _PAGERS:
            inner = _query_of(ctx, t, m, fn.get("obj"), state, dbsets, depth) if fn.get("k") == "member" else _Q()
            if not inner.query and args:                    # `Paginate(db.Orders, page, size)` / `Take(db.Orders, n)`
                inner = _query_of(ctx, t, m, args[0], state, dbsets, depth)
            if nm == "take" and args:
                kind = _take_kind(m, args[-1] if fn.get("k") == "member" and inner.query else args[1] if len(args) > 1 else args[0])
                if kind == "max":
                    return _Q(inner.query, inner.bounded, inner.scalar, inner.mat, inner.weak)
                if kind == "param":
                    return _Q(inner.query, inner.bounded, inner.scalar, inner.mat, True)
            return _Q(inner.query, inner.bounded or not inner.mat, inner.scalar, inner.mat, inner.weak)
        if fn.get("k") == "member":
            inner = _query_of(ctx, t, m, fn.get("obj"), state, dbsets, depth)
            if inner.query:
                return _Q(True, inner.bounded, inner.scalar or nm in _SCALAR, inner.mat or nm in _LISTERS, inner.weak)
        if depth > 0:
            tg = ctx.targets(t, m, e)
            if tg:
                outs = [_returned(ctx, ty, tm, dbsets, depth - 1) for ty, tm in tg]
                if outs and all(o is not None and o.query for o in outs):
                    return _Q(True, all(o.bounded for o in outs), all(o.scalar for o in outs), any(o.mat for o in outs), any(o.weak for o in outs))
        return _Q()
    return _Q()


def _merge(a: dict, b: dict, base: dict) -> dict:
    out = {}
    for k in set(a) | set(b):
        qa, qb = a.get(k, base.get(k)), b.get(k, base.get(k))
        if qa is None or qb is None:
            out[k] = qa or qb
        else:
            out[k] = _Q(qa.query or qb.query, qa.bounded and qb.bounded, qa.scalar and qb.scalar, qa.mat or qb.mat, qa.weak or qb.weak)
    return out


def _run(ctx: Ctx, t, m, stmts, state: dict, dbsets: dict, depth: int, returns: list) -> None:
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        k = s.get("k")
        if k == "local" and s.get("name") and s.get("init") is not None:
            state[s["name"].lower()] = _query_of(ctx, t, m, s["init"], state, dbsets, depth)
        elif k == "assign" and (s.get("target") or {}).get("k") == "name" and s.get("op") in ("=", None):
            state[(s["target"].get("id") or "").lower()] = _query_of(ctx, t, m, s.get("value"), state, dbsets, depth)
        elif k == "if":
            a, b = dict(state), dict(state)
            _run(ctx, t, m, s.get("then"), a, dbsets, depth, returns)
            _run(ctx, t, m, s.get("else"), b, dbsets, depth, returns)
            state.clear()
            state.update(_merge(a, b, state))
        elif k == "loop":
            body = dict(state)
            _run(ctx, t, m, s.get("body"), body, dbsets, depth, returns)
            merged = _merge(state, body, state)
            state.clear()
            state.update(merged)
        elif k in ("try", "using", "with"):
            _run(ctx, t, m, s.get("body"), state, dbsets, depth, returns)
            for c in s.get("catches") or []:
                _run(ctx, t, m, c.get("body"), dict(state), dbsets, depth, returns)
            _run(ctx, t, m, s.get("finally"), state, dbsets, depth, returns)
        elif k == "return" and s.get("value") is not None:
            hit = _unbounded_in(ctx, t, m, s["value"], state, dbsets, depth)
            returns.append((s.get("line") or 0, hit))


def _unbounded_in(ctx, t, m, e, state, dbsets, depth):
    """The first unbounded list query inside a returned value (a wrapper call, an initializer ...), else None."""
    if isinstance(e, list):
        for x in e:
            r = _unbounded_in(ctx, t, m, x, state, dbsets, depth)
            if r:
                return r
        return None
    if not isinstance(e, dict) or e.get("k") == "lambda":
        return None
    # A comparison / logical / arithmetic result is a value, never a list (`x.Role != Admin`); only
    # `a ?? b` can hand back one of its operands.
    if e.get("k") == "unary" or (e.get("k") == "bin" and str(e.get("op") or "") != "??"):
        return None
    if e.get("k") in ("call", "member", "name", "cast"):
        q = _query_of(ctx, t, m, e, state, dbsets, depth)
        if q.query:
            return None if (q.bounded or q.scalar) else (e, q.weak)
        if e.get("k") == "call" and (call_name(e) or "").lower() in _WRAPPERS or e.get("k") == "cast":
            return _unbounded_in(ctx, t, m, [e.get("args"), e.get("e")], state, dbsets, depth)
        return None
    return next((r for v in e.values() if isinstance(v, (dict, list))
                 for r in [_unbounded_in(ctx, t, m, v, state, dbsets, depth)] if r), None)


def _returned(ctx, t, m, dbsets, depth) -> _Q | None:
    """Merged query status of everything a project method returns; None when it returns no query."""
    qs: list = []
    _collect(ctx, t, m, m.body, {}, dbsets, depth, qs)
    qs = [q for q in qs if q.query]
    if not qs:
        return None
    return _Q(True, all(q.bounded for q in qs), all(q.scalar for q in qs), any(q.mat for q in qs), any(q.weak for q in qs))


def _collect(ctx, t, m, stmts, state, dbsets, depth, out) -> None:
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        k = s.get("k")
        if k == "local" and s.get("name") and s.get("init") is not None:
            state[s["name"].lower()] = _query_of(ctx, t, m, s["init"], state, dbsets, depth)
        elif k == "assign" and (s.get("target") or {}).get("k") == "name" and s.get("op") in ("=", None):
            state[(s["target"].get("id") or "").lower()] = _query_of(ctx, t, m, s.get("value"), state, dbsets, depth)
        elif k == "return" and s.get("value") is not None:
            out.append(_query_of(ctx, t, m, s["value"], state, dbsets, depth))
        for key in ("then", "else", "body", "finally"):
            v = s.get(key)
            if isinstance(v, list) and v and isinstance(v[0], dict) and v[0].get("k") in (
                    "local", "assign", "expr", "return", "throw", "if", "loop", "try", "using", "with", "other"):
                _collect(ctx, t, m, v, state, dbsets, depth, out)
        for c in s.get("catches") or []:
            _collect(ctx, t, m, c.get("body"), state, dbsets, depth, out)


def _pagesize_attr(model, t, m) -> bool:
    for a in attrs_of(model, t, m):
        if a.name.lower().split(".")[-1] in ("enablequery", "enablequeryattribute", "queryable", "queryableattribute"):
            for k, v in (a.named or {}).items():
                val = v.get("v") if isinstance(v, dict) else v
                if str(k).lower() == "pagesize" and isinstance(val, int) and not isinstance(val, bool) and val > 0:
                    return True
    return False


def _global_pagesize(ctx: Ctx) -> bool:
    for _t, _m, n in startup_nodes(ctx):
        if n.get("k") == "new" and simple(n.get("type")) in ("enablequeryattribute", "queryableattribute"):
            for it in n.get("init") or []:
                tgt = (it.get("target") or {}) if isinstance(it, dict) else {}
                if (tgt.get("name") or tgt.get("id") or "").lower() == "pagesize":
                    return True
    return False


def check_res002(ctx: Ctx) -> list[Finding]:
    dbsets = _dbset_map(ctx.model)
    if not dbsets:
        return []
    glob = _global_pagesize(ctx)
    out: list[Finding] = []
    seen: set = set()
    for ref in ctx.refs:
        r, t, m = ref.route, ref.type, ref.method
        if m is None or t is None or r.meta.get("kind") not in ("mvc", "webapi") or (t.file, m.line) in seen:
            continue
        seen.add((t.file, m.line))
        if glob or _pagesize_attr(ctx.model, t, m):
            continue
        returns: list = []
        _run(ctx, t, m, m.body, {}, dbsets, 2, returns)
        got = next((h for _ln, h in returns if h), None)
        if got is None:
            continue
        hit, weak = got
        line = hit.get("line") or m.line
        out.append(dnl_finding(
            "DNL-RES-002", "low", f"Unbounded list endpoint: {t.name.split('.')[-1]}.{m.name}",
            f"{m.name} returns every row of a query over a DbSet with no Take / paging applied to it and no "
            f"[EnableQuery(PageSize = ...)], so one request can load the whole table into memory and the "
            f"response; accepting a page-size parameter that the query never uses does not bound it "
            f"({t.file}:{line}) (in {t.name}.{m.name}).",
            t.file, line, route=r, api_surface=bool(r.meta.get("api_surface")),
            confidence="REVIEW" if weak else None))
    return out


# -- RES-003 --------------------------------------------------------------------

_UPLOAD_TYPE = re.compile(r"(?i)httppostedfile|iformfile|multipartformdata|multipartmemorystreamprovider|"
                          r"fileupload|htmlinputfile")
_UPLOAD_MEMBERS = {"postedfile", "filebytes", "filecontent", "hasfile", "files"}
_ANY = "*"
_REQUEST_ROOTS = ("request", "this.request", "httpcontext.current.request", "system.web.httpcontext.current.request")


def _idx_key(args, al: dict) -> str:
    """`[0]` / `["a"]` for a literal index, `[$name]` for a variable, else the expression itself: two
    indexes match only when they are the same literal or the same expression."""
    a = (args or [None])[0]
    if isinstance(a, dict) and a.get("k") == "lit":
        return f"[{a.get('v')!r}]"
    if isinstance(a, dict) and a.get("k") == "name":
        return "[$" + (a.get("id") or "").lower() + "]"
    return "[?" + json.dumps(_strip(a), sort_keys=True) + "]"


def _strip(x):
    """Expression without line numbers, so equal expressions compare equal."""
    if isinstance(x, dict):
        return {k: _strip(v) for k, v in x.items() if k not in ("line", "sym", "type_full")}
    if isinstance(x, list):
        return [_strip(v) for v in x]
    return x


def _canon(e, al: dict) -> str:
    """A key for the object an expression names, so a size check can be tied to the saved file:
    locals resolve to what they were assigned (`var f = Request.Files[name]`), `.PostedFile` /
    `.InputStream` / `.FileContent` fall back to their owner, indexes collapse (`Files[0]`, `Files[name]`)."""
    if not isinstance(e, dict):
        return ""
    k = e.get("k")
    if k == "name":
        nm = (e.get("id") or "").lower()
        return al.get(nm, nm)
    if k == "member":
        nm = (e.get("name") or "").lower()
        obj = _canon(e.get("obj"), al)
        if nm in ("postedfile", "inputstream", "filecontent"):
            return obj
        return f"{obj}.{nm}" if obj else nm
    if k == "index":
        return _canon(e.get("obj"), al) + _idx_key(e.get("args"), al)
    if k == "call" and (call_name(e) or "").lower() in ("get", "item"):
        return _canon((e.get("fn") or {}).get("obj"), al) + _idx_key(e.get("args"), al)
    if k == "cast":
        return _canon(e.get("e"), al)
    return ""


def _key_set(key: str) -> frozenset:
    """Keys a size check on `key` covers. A request-level length (`Request.ContentLength`) covers any save."""
    if not key or (key.startswith(_REQUEST_ROOTS) and "files" not in key):
        return frozenset({_ANY})
    return frozenset({key})


def _size_keys(e, al: dict, sizes: dict) -> frozenset:
    """Keys of every size read inside `e` (ContentLength, InputStream.Length, FileBytes.Length, a size alias)."""
    out: set = set()
    for n in walk_nl(e):
        k = n.get("k")
        if k == "member":
            nm = (n.get("name") or "").lower()
            if nm == "contentlength":
                out |= _key_set(_canon(n.get("obj"), al))
            elif nm == "length" and any(x in receiver_text(n.get("obj")).lower() for x in ("inputstream", "filebytes")):
                out |= _key_set(_canon(n.get("obj"), al))
        elif k == "name" and (n.get("id") or "").lower() in sizes:
            out |= sizes[(n.get("id") or "").lower()]
    return frozenset(out)


def _bound_lit(e) -> bool:
    """A literal the comparison cannot bound anything with (`ContentLength > 0`)."""
    return isinstance(e, dict) and e.get("k") == "lit" and isinstance(e.get("v"), (int, float)) \
        and not isinstance(e.get("v"), bool) and e["v"] <= 1


def _passes(cond, pol: bool, al: dict, sizes: dict) -> frozenset:
    """Keys proven size-checked when `cond` evaluates to `pol` (empty: nothing is)."""
    if not isinstance(cond, dict):
        return frozenset()
    k = cond.get("k")
    if k == "unary" and cond.get("op") in ("!", "Not", "not"):
        return _passes(cond.get("e"), not pol, al, sizes)
    if k == "bin":
        op = str(cond.get("op") or "").lower()
        l, r = cond.get("l"), cond.get("r")
        if op in ("&&", "andalso", "and", "||", "orelse", "or"):
            a, b = _passes(l, pol, al, sizes), _passes(r, pol, al, sizes)
            conj = op in ("&&", "andalso", "and")
            return (a | b) if conj == pol else (a & b)
        if op in ("<", "<=", ">", ">="):
            ls, rs = _size_keys(l, al, sizes), _size_keys(r, al, sizes)
            if bool(ls) == bool(rs) or _bound_lit(r if ls else l):
                return frozenset()
            small_left = op in ("<", "<=")
            return (ls or rs) if pol == (small_left if ls else not small_left) else frozenset()
    return frozenset()


def _carry(a, data: dict, al: dict) -> tuple[bool, frozenset]:
    """(does the expression hold bytes of the upload, the keys of the upload objects they came from).
    No key means the source is unknown: only a request-level length check can then guard a write."""
    carries = False
    keys: set = set()
    for x in walk_nl(a):
        k = x.get("k")
        if k == "member" and (x.get("name") or "").lower() in ("inputstream", "filebytes"):
            carries = True
            keys.add(_canon(x.get("obj"), al))
        elif k == "name" and (x.get("id") or "").lower() in data:
            carries = True
            keys |= data[(x.get("id") or "").lower()]
        elif k == "call" and (call_name(x) or "").lower() in ("readbytes", "readallbytes"):
            carries = True
        elif k == "call" and (call_name(x) or "").lower() in ("readasstreamasync", "readasbytearrayasync"):
            carries = True
            keys.add(_canon((x.get("fn") or {}).get("obj"), al) or "request.content")
    return carries, frozenset(keys - {""})


def _aliases(m) -> tuple[dict, dict, dict]:
    """(object aliases, size aliases, upload-derived locals -> source keys) of a method body, to a fixpoint."""
    al: dict = {}
    sizes: dict = {}
    data: dict = {}
    nodes = [n for n in walk(m.body) if n.get("k") in ("local", "assign", "call")]
    for _ in range(len(nodes) + 1):
        before = (len(al), len(sizes), sum(len(v) + 1 for v in data.values()))
        for n in nodes:
            k = n.get("k")
            if k == "call":
                # `f.InputStream.Read(buf, 0, n)` fills buf from the upload f.
                args = n.get("args") or []
                obj = (n.get("fn") or {}).get("obj")
                if (call_name(n) or "").lower() in ("read", "readasync", "readbytes") and args \
                        and "inputstream" in receiver_text(obj).lower() \
                        and isinstance(args[0], dict) and args[0].get("k") == "name":
                    nm = (args[0].get("id") or "").lower()
                    data[nm] = data.get(nm, frozenset()) | frozenset({_canon(obj, al)} - {""})
                continue
            if k == "local":
                tgt, val = (n.get("name") or "").lower(), n.get("init")
            else:
                t_ = n.get("target") or {}
                tgt, val = ((t_.get("id") or "").lower() if t_.get("k") == "name" else ""), n.get("value")
            if not tgt or val is None:
                continue
            if isinstance(val, dict) and (val.get("k") in ("name", "member", "index", "cast") or (
                    val.get("k") == "call" and (call_name(val) or "").lower() in ("get", "item"))):
                ck = _canon(val, al)
                if ck and tgt not in al:
                    al[tgt] = ck
            sk = _size_keys(val, al, sizes)
            if sk:
                sizes[tgt] = sizes.get(tgt, frozenset()) | sk
            carries, keys = _carry(val, data, al)
            if carries:
                data[tgt] = data.get(tgt, frozenset()) | keys
        if (len(al), len(sizes), sum(len(v) + 1 for v in data.values())) == before:
            break
    return al, sizes, data


def _direct_save(n: dict, al: dict, data: dict):
    """(what, keys) when the call saves an upload; keys are the saved upload objects (empty: unknown)."""
    if n.get("k") != "call":
        return None
    nm = (call_name(n) or "").lower()
    fn = n.get("fn") or {}
    obj = fn.get("obj") if fn.get("k") == "member" else None
    recv = receiver_text(obj).lower() if obj is not None else ""
    args = n.get("args") or []
    if nm == "saveas":
        return "SaveAs", frozenset({_canon(obj, al)} - {""})
    if nm in ("copyto", "copytoasync") and ("inputstream" in recv or recv.endswith("request.content")
                                            or _root_of(obj) in data):
        keys = data.get(_root_of(obj), frozenset()) | frozenset({_canon(obj, al)} - {""})
        return "InputStream.CopyTo", keys
    if nm == "readasmultipartasync":
        return "ReadAsMultipartAsync", frozenset({_canon(obj, al) or "request.content"})
    if nm in ("writeallbytes", "writeallbytesasync", "write", "writeasync"):
        use = args[1:] if nm.startswith("writeall") else args[:1]
        keys: set = set()
        carries = False
        for a in use:
            c, kk = _carry(a, data, al)
            carries |= c
            keys |= kk
        if carries:
            return ("File.WriteAllBytes" if nm.startswith("writeall") else "Stream.Write of the upload"), frozenset(keys)
    return None


def _root_of(e) -> str:
    while isinstance(e, dict) and e.get("k") in ("member", "index"):
        e = e.get("obj")
    return (e.get("id") or "").lower() if isinstance(e, dict) and e.get("k") == "name" else ""


def _guarded(keys, g: frozenset) -> bool:
    """A request-level check guards any save; a per-file check only the save of that same file. A save whose
    file is unknown is guarded by a request-level check alone."""
    return _ANY in g or bool(keys and keys & g)


def _expr_uses(key: str, name: str) -> bool:
    """True when an expression index key (`[?{json}]`) reads the local `name` (e.g. `Files[i + 1]`)."""
    return "[?" in key and re.search(r'"id": "' + re.escape(name) + r'"', key, re.I) is not None


def _assigned(s: dict) -> set:
    """Lowered names a statement (nested statements included) assigns, increments or redeclares."""
    out: set = set()
    for n in walk(s):
        k = n.get("k")
        if k == "assign" and (n.get("target") or {}).get("k") == "name":
            out.add((n["target"].get("id") or "").lower())
        elif k == "unary" and n.get("op") in ("++", "--") and isinstance(n.get("e"), dict) and n["e"].get("k") == "name":
            out.add((n["e"].get("id") or "").lower())
        elif k == "local" and n.get("name"):
            out.add(n["name"].lower())
        elif k == "call":                    # the IR keeps no out/ref marker: any bare-name argument may be written
            out.update((a.get("id") or "").lower() for a in n.get("args") or []
                       if isinstance(a, dict) and a.get("k") == "name")
    return out


def _scan(ctx, t, m, stmts, g: frozenset, env, depth: int, out: list) -> None:
    """Append (node, what, guarded) for every save under `stmts`; `g` = keys a passed size check covers. A
    check on `Files[i]` stops covering anything once `i` is assigned."""
    al, sizes, _data = env
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        changed = _assigned(s)
        if changed and g:
            g = frozenset(x for x in g if not any(f"[${n}]" in x or _expr_uses(x, n) for n in changed))
        k = s.get("k")
        if k == "if":
            cond = s.get("cond")
            _nodes(ctx, t, m, [cond], g, env, depth, out)
            tp, ep = _passes(cond, True, al, sizes), _passes(cond, False, al, sizes)
            _scan(ctx, t, m, s.get("then"), g | tp, env, depth, out)
            _scan(ctx, t, m, s.get("else"), g | ep, env, depth, out)
            if terminates(s.get("then")):
                g = g | ep
            if s.get("else") and terminates(s.get("else")):
                g = g | tp
        elif k in ("try", "using", "with"):
            _nodes(ctx, t, m, [s.get("resource"), s.get("target")], g, env, depth, out)
            _scan(ctx, t, m, s.get("body"), g, env, depth, out)
            for c in s.get("catches") or []:
                _scan(ctx, t, m, c.get("body"), g, env, depth, out)
            _scan(ctx, t, m, s.get("finally"), g, env, depth, out)
        elif k == "loop":
            _nodes(ctx, t, m, [s.get("header")], g, env, depth, out)
            _scan(ctx, t, m, s.get("body"), g, env, depth, out)
        else:
            _nodes(ctx, t, m, list(stmt_exprs(s)), g, env, depth, out)


def _nodes(ctx, t, m, exprs, g, env, depth, out) -> None:
    al, _sizes, data = env
    for e in exprs:
        for n in walk_nl(e):
            got = _direct_save(n, al, data)
            what, keys = got if got else (None, frozenset())
            if what is None and depth > 0 and n.get("k") == "call":
                for ty, tm in ctx.targets(t, m, n):
                    inner: list = []
                    _scan(ctx, ty, tm, tm.body, frozenset(), _aliases(tm), depth - 1, inner)
                    if any(not gd for _n, _w, gd in inner):
                        what = f"{tm.name} (which saves the file)"
                        # The callee saves what it is handed: the file is whichever argument carries one.
                        keys = frozenset(x for a in n.get("args") or [] for x in [_canon(a, al)] if x)
                        break
            if what:
                out.append((n, what, _guarded(keys, g)))


def _upload_names(model, t) -> set:
    """Lowered names of fields / properties typed as an upload control or posted file, over the partial
    declarations of the type (a WebForms designer file declares the controls)."""
    out = set()
    for d in model.find_types(t.name.split(".")[-1]):
        for f in list(d.fields) + list(d.properties):
            if _UPLOAD_TYPE.search(f.type or ""):
                out.add(f.name.lower())
    return out


def _has_upload(model, t, m) -> bool:
    if any(_UPLOAD_TYPE.search(p.type or "") for p in m.params):
        return True
    names = _upload_names(model, t)
    for n in walk(m.body):
        k = n.get("k")
        if k == "member" and (n.get("name") or "").lower() in _UPLOAD_MEMBERS and (
                (n.get("name") or "").lower() != "files" or "request" in receiver_text(n.get("obj")).lower()):
            return True
        if k == "name" and (n.get("id") or "").lower() in names:
            return True
        # Raw-body uploads: Request.InputStream, or the Web API request content read as a stream / bytes.
        if k == "member" and (n.get("name") or "").lower() == "inputstream" and "request" in receiver_text(n.get("obj")).lower():
            return True
        if k == "call" and (call_name(n) or "").lower() in ("readasstreamasync", "readasbytearrayasync", "copytoasync") \
                and "request" in receiver_text((n.get("fn") or {}).get("obj")).lower():
            return True
        if k == "local" and _UPLOAD_TYPE.search(n.get("type_full") or n.get("type") or ""):
            return True
        if k == "call" and (call_name(n) or "").lower() in ("readasmultipartasync", "ismimemultipartcontent"):
            return True
    return False


def check_res003(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    seen: set = set()
    for ref in ctx.refs:
        r, t = ref.route, ref.type
        if t is None:
            continue
        # A WebForms page has no action method: its handlers are the code-behind methods.
        methods = [ref.method] if ref.method is not None else [x for x in t.methods if x.body]
        for m in methods:
            if m is None or not m.body or (t.file, m.line) in seen or not _has_upload(ctx.model, t, m):
                continue
            seen.add((t.file, m.line))
            found: list = []
            _scan(ctx, t, m, m.body, frozenset(), _aliases(m), 2, found)
            bad = next(((n, w) for n, w, gd in found if not gd), None)
            if bad is None:
                continue
            line = bad[0].get("line") or m.line
            out.append(dnl_finding(
                "DNL-RES-003", "medium", f"File upload without a size check: {t.name.split('.')[-1]}.{m.name}",
                f"{m.name} saves an uploaded file ({bad[1]}) without a ContentLength comparison on that file "
                f"that guards the save, so one request can fill the disk or exhaust memory; reject files over "
                f"a maximum size before saving. A check that does not stop the save, a check on a different "
                f"file, or a limit only in web.config maxRequestLength, does not count ({t.file}:{line}) "
                f"(in {t.name}.{m.name}).",
                t.file, line, route=r, api_surface=bool(r.meta.get("api_surface"))))
    return out


# -- INV-002 --------------------------------------------------------------------------

_SWAGGER = {"enableswagger", "enableswaggerui", "useswagger", "useswaggerui", "useswaggerui3", "useopenapi",
            "useredoc"}
_TEST_REFS = ("nunit.framework", "xunit", "microsoft.visualstudio.testtools.unittesting",
              "microsoft.visualstudio.qualitytools.unittestframework")
_DEBUG_TOKENS = {"debug", "diagnostics", "diagnostic"}


def _is_test_project(model, t) -> bool:
    proj = model.project_of(t.file)
    if proj is None:
        return False
    low = proj.name.lower()
    return low.endswith(("test", "tests", ".unittests")) or any(r.startswith(_TEST_REFS) for r in proj.references)


def _swagger_prefix(body) -> str:
    """First path segment Swagger is served under: the first literal argument of EnableSwagger(..)
    (`swagger/docs/{apiVersion}` -> swagger), default swagger."""
    for n in walk(body):
        if n.get("k") == "call" and (call_name(n) or "").lower() == "enableswagger":
            for a in n.get("args") or []:
                lit = literal_str(a)
                if lit:
                    return re.split(r"[/{]", lit.strip("/~ "))[0].lower() or "swagger"
    return "swagger"


def _swagger_denied(configs, prefix: str) -> bool:
    """A web.config <location> whose path is exactly the swagger prefix denies anonymous users. A rule on
    a sub-path (`swagger/ui`) leaves the rest (`swagger/docs`) open, so it does not count."""
    for cfg in configs or []:
        if cfg.root is None:
            continue
        for loc in cfg.root.iter("location"):
            if (loc.get("path") or "").strip("/~ ").lower() == prefix and any(
                    (d.get("users") or "").strip() in ("?", "*") for d in loc.iter("deny")):
                return True
    return False


def _test_like(short: str) -> bool:
    """Controller named like a test or debug endpoint: the whole name is Test(s) / Debug / Diagnostics, or it
    ends in Test(s) / Debug / Diagnostics (OrdersTest, SmokeTest). TestResults and Latest are not."""
    tk = tokens(short[: -len("controller")])
    return bool(tk) and (len(tk) == 1 and tk[0] in _DEBUG_TOKENS | {"test", "tests"}
                         or tk[-1] in _DEBUG_TOKENS | {"test", "tests"})


def check_inv002(ctx: Ctx, configs) -> list[Finding]:
    model = ctx.model
    out: list[Finding] = []
    # Only filters a startup path adds unconditionally count (`auth.global_filters` lists every
    # `Filters.Add` in the solution, even under `if (false)` or in a method nobody calls).
    filters = startup_auth_filters(ctx)
    chain_for = auth.chain_for_model(model)

    # HelpPage: the controller when present (auth resolved like any route), else the area registration.
    done_types: set = set()
    for ref in ctx.refs:
        t = ref.type
        if t is None or t.name.split(".")[-1].lower() != "helpcontroller" or id(t) in done_types:
            continue
        if "helppage" not in (t.file + "." + t.namespace).lower():
            continue
        done_types.add(id(t))
        info = auth.resolve(model, ref, filters, chain_for)
        if info.protected:
            continue
        out.append(dnl_finding(
            "DNL-INV-002", "low", "Web API HelpPage reachable without authentication",
            f"The HelpPage area ({t.name}) lists every API route, parameter and model to any caller; no "
            f"[Authorize], global authorize filter or web.config rule covers it. Remove it from production "
            f"or require authentication ({t.file}:{t.line}).", t.file, t.line,
            route=ref.route, api_surface=True))
    if not done_types:
        for t in model.types():
            short = t.name.split(".")[-1].lower()
            if short == "helppagearearegistration" or (model.derives_from(t, {"AreaRegistration"}) and "helppage" in t.file.lower()):
                if any(k == "mvc" and auth.is_auth_attr(model, n) for k, n, _f, _l in filters):
                    continue
                out.append(dnl_finding(
                    "DNL-INV-002", "low", "Web API HelpPage area registered without authentication",
                    f"{t.name} registers the HelpPage area, which documents every API route to any caller; no "
                    f"global authorize filter covers it ({t.file}:{t.line}).", t.file, t.line, api_surface=True))

    # Swagger UI / document endpoints.
    if True:
        seen: set = set()
        for t in model.types():
            for m in t.methods:
                prefix = _swagger_prefix(m.body)
                if _swagger_denied(configs, prefix):
                    continue
                for n in walk(m.body):
                    if n.get("k") == "call" and (call_name(n) or "").lower() in _SWAGGER and (t.file, n.get("line")) not in seen:
                        seen.add((t.file, n.get("line")))
                        out.append(ctx.finding(
                            t, m.name, "DNL-INV-002", "low", "Swagger UI reachable without authentication",
                            f"{call_name(n)}(..) publishes the API description (routes, parameters, models) to "
                            "any caller. The UI is served by a message handler, so a global authorize filter "
                            "does not cover it; only a web.config <location path=\"swagger\"> deny rule, "
                            "authentication middleware or removal from production does", n.get("line") or 0))

    # Test and debug controllers in non-test projects.
    for t in model.types():
        short = t.name.split(".")[-1]
        if t.kind != "class" or not short.lower().endswith("controller"):
            continue
        tk = tokens(short[: -len("controller")])
        if not _test_like(short):
            continue
        if _is_test_project(model, t):
            continue
        out.append(dnl_finding(
            "DNL-INV-002", "low", f"Test or debug controller shipped: {short}",
            f"{short} looks like a test, debug or diagnostics endpoint inside a production project; such "
            f"controllers often expose internals or skip authorization. Remove it from the deployed build "
            f"({t.file}:{t.line}).", t.file, t.line, api_surface=True))
    return out


def check(model, refs=(), configs=()) -> list[Finding]:
    if not model.files:
        return []
    ctx = Ctx(model, refs)
    return check_res002(ctx) + check_res003(ctx) + check_inv002(ctx, configs)
