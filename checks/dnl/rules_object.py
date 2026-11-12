"""Object-level authorization findings for MVC / Web API actions.

DNL-AUTHZ-005 (IDOR): an action takes an id-like parameter that selects a record
  (EF `Find` / `FirstOrDefault` / `Where` ... on a `DbSet`, a `sql` sink, or a project
  method that does either) and neither the action nor the methods it passes the id
  through reference the signed-in user. Independent of [Authorize]: being logged in
  is not the same as owning the object.
DNL-AUTHZ-006 (over-posting): a write action binds an entity type with no [Bind].
DNL-AUTHZ-007 (over-exposure): a Web API action hands an entity back to the client.

EF and MVC are usually not referenced by the project compilation, so entity types
and DbSet members are recognized by the names written in source, not by symbols.
"""
from __future__ import annotations

import re

from checks.dnl import taint_solver
from checks.dnl.findings import dnl_finding
from checks.dnl.ir import MethodIR, TypeIR, attr_key, call_name, has_attr, receiver_text, walk
from checks.dnl.project import ProjectModel
from checks.dnl.routes import RouteRef
from checks.idor import _is_id_like
from core.models import Finding

_CONTEXT_BASES = {"DbContext", "ObjectContext", "IdentityDbContext"}
# `DbSet<Order>`, `System.Data.Entity.IDbSet<Order>`, VB `DbSet(Of Order)`.
_DBSET = re.compile(r"(?:^|\.)I?(?:DbSet|ObjectSet)\s*(?:<\s*([\w.]+)\s*>|\(\s*Of\s+([\w.]+)\s*\))\s*$", re.IGNORECASE)
_TOKEN = re.compile(r"[A-Za-z_][\w.]*")
# Data-access calls that take the id on a DbSet.
_LOOKUPS = {"find", "findasync", "first", "firstordefault", "firstasync", "firstordefaultasync", "single",
            "singleordefault", "singleasync", "singleordefaultasync", "where", "any", "anyasync", "last",
            "lastordefault"}
# Calls on a DbSet chain whose result is still entity-shaped (so returning it exposes entities).
_ENTITY_RESULT = _LOOKUPS | {"tolist", "toarray", "tolistasync", "toarrayasync", "orderby", "orderbydescending",
                             "include", "asqueryable", "asnotracking", "take", "skip", "thenby"}
# Dotted-segment sequences that tie a request to the signed-in user (whole segments only).
_USER_MARKERS = (("user", "identity"), ("user", "isinrole"), ("getuserid",), ("httpcontext", "current", "user"),
                 ("thread", "currentprincipal"), ("claimsprincipal",), ("websecurity", "currentuserid"),
                 ("requestcontext", "principal"), ("membership", "getuser"))
# Receivers that are the ASP.NET Session object.
_SESSIONS = {"session", "this.session", "me.session", "base.session", "mybase.session", "context.session",
             "httpcontext.session", "httpcontext.current.session", "system.web.httpcontext.current.session"}
_REJECT_CALLS = {"httpnotfound", "notfound", "unauthorized", "forbid", "forbidden", "httpunauthorized", "challenge",
                 "statuscode"}
# `User.Identity.IsAuthenticated` says someone is logged in, not who: never an ownership signal.
_NOT_IDENTITY = {"isauthenticated", "authenticationtype"}
# Session keys that hold the signed-in identity (UserId, user_id, CurrentUserId, Username), not UserTheme.
_SESSION_KEY = re.compile(r"(?i)^(current)?(user|member|customer|account)(_)?id$|^(logged_?in_?)?user(name)?$")
# Raw-SQL entry points of EF 4-6 / Core (the receiver is `db.Database` or a context).
_RAW_SQL = {"sqlquery", "executesqlcommand", "executesqlcommandasync", "executesqlquery", "fromsql", "fromsqlraw",
            "fromsqlinterpolated", "executesqlraw", "executesqlrawasync", "executesqlinterpolated",
            "executesqlinterpolatedasync", "sqlqueryraw", "executestorequery", "executestorecommand",
            "executestorequeryasync", "executestorecommandasync"}
_WRITE_VERBS = {"POST", "PUT", "PATCH"}
_VERB_ATTRS = {"httppost", "httpput", "httppatch", "httpget", "httpdelete", "acceptverbs"}
_MAX_DEPTH = 3


def _simple(name: str | None) -> str:
    """`System.Data.Entity.DbSet<Order>` style text -> last dotted segment without generics."""
    return re.sub(r"<.*$|\(.*$", "", (name or "").strip()).split(".")[-1]


def _dbset_map(model: ProjectModel) -> dict[str, str]:
    """Lowered DbSet property name -> entity simple name, over every DbContext subclass."""
    cached = model.cache.get("object_dbsets")
    if cached is None:
        cached = {}
        for t in model.types():
            if not model.derives_from(t, _CONTEXT_BASES):
                continue
            for p in t.properties:
                m = _DBSET.search(p.type or "")
                if m:
                    cached[p.name.lower()] = _simple(m.group(1) or m.group(2))
        model.cache["object_dbsets"] = cached
    return cached


def entity_types(model: ProjectModel) -> set[str]:
    """Simple names of entity types: `DbSet<T>` / `IDbSet<T>` element types on DbContext /
    ObjectContext subclasses, plus types with a [Table] attribute or a [Key] property."""
    out = set(_dbset_map(model).values())
    for t in model.types():
        if has_attr(t.attributes, "Table") or any(has_attr(p.attributes, "Key") for p in t.properties):
            out.add(t.name.split(".")[-1])
    return out


# -- helpers over the IR --------------------------------------------------

def _names(node) -> set[str]:
    """Lowered identifiers (`name` nodes) anywhere under node."""
    return {(n.get("id") or "").lower() for n in walk(node) if n.get("k") == "name"}


def _on_dbset(fn: dict, dbsets: dict[str, str]) -> str | None:
    """Entity name when the receiver chain of a call passes through a DbSet property."""
    obj = fn.get("obj") if fn.get("k") == "member" else None
    for n in walk(obj):
        nm = n.get("name") if n.get("k") == "member" else n.get("id") if n.get("k") == "name" else None
        if nm and nm.lower() in dbsets:
            return dbsets[nm.lower()]
    return None



def _segs(txt: str) -> list[str]:
    return re.findall(r"\w+", txt.lower())


def _has_marker(txt: str) -> bool:
    """A user marker as whole dotted segments (so `Membership.GetUser` never matches `GetUsers`)."""
    # `GetUserIdAsync` is the same marker as `GetUserId`.
    segs = [x[:-5] if x.endswith("async") and len(x) > 5 else x for x in _segs(txt)]
    return any(segs[i:i + len(mk)] == list(mk) for mk in _USER_MARKERS for i in range(len(segs)))


def _user_ref(node, uvars: frozenset = frozenset()) -> bool:
    """True when the subtree references the signed-in identity (not just IsAuthenticated), a local
    assigned from it (`uvars`), or a session value keyed like a user id."""
    if isinstance(node, list):
        return any(_user_ref(x, uvars) for x in node)
    if not isinstance(node, dict):
        return False
    k = node.get("k")
    if k == "member" and (node.get("name") or "").lower() in _NOT_IDENTITY:
        return False
    if k == "name" and (node.get("id") or "").lower() in uvars:
        return True
    txt = receiver_text(node) if k in ("name", "member") else node.get("text") if isinstance(node.get("text"), str) else ""
    if txt and _has_marker(txt):
        return True
    # Session["UserId"] (C# index) and Session("UserId") (VB default-property call); the receiver
    # must be the Session object itself.
    sess = receiver_text(node.get("obj")) if k == "index" else receiver_text(node.get("fn")) if k == "call" else ""
    if sess.lower() in _SESSIONS and any(
            isinstance(x.get("v"), str) and _SESSION_KEY.match(x["v"]) for x in walk(node) if x.get("k") == "lit"):
        return True
    return any(_user_ref(v, uvars) for v in node.values() if isinstance(v, (dict, list)))


def _rejects(branch) -> bool:
    """Does the branch deny the request: a throw, or a return / call that is a not-found, forbidden,
    unauthorized, redirect or 401/403/404 status result."""
    for n in walk(branch):
        k = n.get("k")
        if k == "throw":
            return True
        if k == "call":
            nm = (call_name(n) or "").lower()
            if nm in _REJECT_CALLS or nm.startswith("redirect"):
                return True
        if k == "new":
            tn = _simple(n.get("type_full") or n.get("type")).lower()
            if any(w in tn for w in ("unauthorized", "notfound", "forbidden", "responseexception")):
                return True
            if tn == "httpstatuscoderesult" and any(
                    x.get("v") in (401, 403, 404, "401", "403", "404")
                    or (x.get("k") == "member" and x.get("name") in ("Unauthorized", "Forbidden", "NotFound"))
                    for x in walk(n.get("args"))):
                return True
    return False


_COMPARE_OPS = {"==", "!=", "=", "<>"}


def _comparisons(cond) -> list[tuple]:
    """(left, right) operand pairs of every comparison (==, !=, Equals, VB = / <>) inside cond."""
    out = []
    for n in walk(cond):
        if n.get("k") == "bin" and n.get("op") in _COMPARE_OPS:
            out.append((n.get("l"), n.get("r")))
        elif n.get("k") == "call" and (call_name(n) or "").lower() == "equals":
            fn = n.get("fn") or {}
            args = n.get("args") or []
            if fn.get("k") == "member" and args:
                out.append((fn.get("obj"), args[0]))
            elif len(args) > 1:
                out.append((args[0], args[1]))
    return out


def _ties_user_to_record(cond, uv: frozenset, record: set[str]) -> bool:
    """A comparison between a user value and something derived from the accessed record (the
    fetched entity or its members, or the id itself). Null, IsAuthenticated and Name-only checks
    never qualify."""
    for left, right in _comparisons(cond):
        for u, o in ((left, right), (right, left)):
            if _user_ref(u, uv) and _names(o) & record:
                return True
    return False


def _guarded(body: list, access: list[dict], alias: set[str]) -> bool:
    """R11-R13: a user reference suppresses IDOR only when it gates the access: it is part of the
    data-access call (an argument, a lambda, an earlier Where in the chain), or an `if` / ternary
    condition compares it with the record being accessed (the fetched entity or one of its members,
    or the id) and the branch rejects the request or holds the access. Comparing the user with an
    unrelated value, a null check or a sign-in check gates nothing."""
    uvars: set[str] = set()
    fetched: set[str] = set()
    for n in walk(body):
        if n.get("k") == "local":
            tgt, init = n.get("name"), n.get("init")
        elif n.get("k") == "assign" and isinstance(n.get("target"), dict) and n["target"].get("k") == "name":
            tgt, init = n["target"].get("id"), n.get("value")
        else:
            continue
        if not tgt or init is None:
            continue
        if _user_ref(init):
            uvars.add(tgt.lower())
        if any(x is c for c in access for x in walk(init)):
            fetched.add(tgt.lower())
    uv = frozenset(uvars)
    if any(_user_ref(c, uv) for c in access):
        return True
    record = set(alias) | fetched
    for n in walk(body):
        if n.get("k") == "if" and _ties_user_to_record(n.get("cond"), uv, record):
            in_then = any(x is c for c in access for x in walk(n.get("then")))
            if in_then or _rejects(n.get("then")) or _rejects(n.get("else")):
                return True
        elif n.get("k") == "cond" and _ties_user_to_record(n.get("c"), uv, record):
            if _rejects(n.get("f")) or _rejects(n.get("t")) or any(x is c for c in access for x in walk(n.get("t"))):
                return True
    return False


def _declaring(model: ProjectModel, t: TypeIR, m: MethodIR) -> TypeIR:
    """The type (the controller or a project base) whose body holds method m."""
    for d in [t] + [bt for b in model.base_chain(t) for bt in model.find_types(b)]:
        if any(x is m for x in d.methods):
            return d
    return t


def _is_vb(model: ProjectModel, t: TypeIR) -> bool:
    f = model.files.get(t.file)
    return bool(f and f.language == "vb")


def _env_types(t: TypeIR, m: MethodIR, vb: bool) -> dict[str, str]:
    # VB identifiers are case-insensitive: lowercase the keys (resolve_call also tries the lowered
    # name). C# stays case-sensitive.
    key = str.lower if vb else (lambda x: x)
    env = {key(f.name): f.type for f in list(t.fields) + list(t.properties) if f.type}
    env.update({key(p.name): p.type for p in m.params if p.type})
    for n in walk(m.body):
        if n.get("k") == "local" and n.get("name"):
            tn = n.get("type_full") if (n.get("type") or "var").lower() in ("var", "") else n.get("type")
            if tn:
                env[key(n["name"])] = tn
    return env


def _aliases(m: MethodIR, pname: str) -> set[str]:
    """The parameter plus locals initialised from an expression that mentions it."""
    out = {pname.lower()}
    for n in walk(m.body):
        if n.get("k") == "local":
            tgt, init = n.get("name"), n.get("init")
        elif n.get("k") == "assign" and isinstance(n.get("target"), dict):
            tgt, init = n["target"].get("id"), n.get("value")
        else:
            continue
        if tgt and init is not None and _names(init) & out:
            out.add(tgt.lower())
    return out


def _ado_access(m: MethodIR, c: dict) -> list[dict]:
    """For `cmd.Parameters.Add*("@x", id)` (the caller checked the id is an argument): when that
    command is executed (`cmd.Execute*`) in the method, the Parameters.Add* and Execute* calls on it
    (so a user-scoped parameter counts as part of the access); else []."""
    fn = c.get("fn") or {}
    if (call_name(c) or "").lower() not in ("addwithvalue", "add") or fn.get("k") != "member":
        return []
    recv = receiver_text(fn.get("obj")).lower()
    if not recv.endswith(".parameters"):
        return []
    cmd = recv[: -len(".parameters")]
    calls = [n for n in walk(m.body) if n.get("k") == "call" and isinstance(n.get("fn"), dict)
             and n["fn"].get("k") == "member"]
    execs = [n for n in calls if receiver_text(n["fn"].get("obj")).lower() == cmd
             and (call_name(n) or "").lower().startswith("execute")]
    adds = [n for n in calls if receiver_text(n["fn"].get("obj")).lower() == recv]
    return adds + execs if execs else []


def _reach(model: ProjectModel, summaries: dict, t: TypeIR, m: MethodIR, pname: str, depth: int,
           seen: set) -> tuple[str | None, list]:
    """(how the parameter reaches a data access or None, [((type, method), access calls)] for the
    methods on the path that actually reaches it, m first)."""
    key = (t.full_name, m.name, m.line)
    if key in seen:
        return None, []
    seen.add(key)
    dbsets = _dbset_map(model)
    alias = _aliases(m, pname)
    env = _env_types(t, m, _is_vb(model, t))
    how: str | None = None
    access: list[dict] = []
    path: list = []
    # The method's own summary: the parameter reaches a SQL sink (new SqlCommand("..." + id), a local
    # `sql` built from it, ...).
    sm = summaries.get(key)
    idx = next((i for i, p in enumerate(m.params) if p.name.lower() == pname.lower()), None)
    if sm and idx is not None and any(h.kind == "sql" for h in sm.param_sinks.get(idx, [])):
        how = f"SQL in {t.name.split('.')[-1]}.{m.name}"
    # `cmd.Parameters.Add("@id", type).Value = id`
    for n in walk(m.body):
        tgt = n.get("target") if n.get("k") == "assign" else None
        if (isinstance(tgt, dict) and tgt.get("k") == "member" and (tgt.get("name") or "").lower() == "value"
                and isinstance(tgt.get("obj"), dict) and tgt["obj"].get("k") == "call"
                and _names(n.get("value")) & alias):
            ado = _ado_access(m, tgt["obj"])
            if ado:
                how = how or "ADO.NET command parameter"
                access.extend(ado)
    for c in walk(m.body):
        if c.get("k") != "call":
            continue
        args = list(c.get("args") or [])
        named = c.get("named") or {}
        if not any(_names(a) & alias for a in args + list(named.values())):
            continue
        name = (call_name(c) or "").lower()
        ado = _ado_access(m, c)
        if ado:
            how = how or "ADO.NET command parameter"
            access.extend(ado)
            continue
        if name in _LOOKUPS and _on_dbset(c.get("fn") or {}, dbsets):
            how = how or f"DbSet.{call_name(c)}"
            access.append(c)
            continue
        if name in _RAW_SQL:
            how = how or f"{call_name(c)}"
            access.append(c)
            continue
        if depth <= 0:
            continue
        idxs = [i for i, a in enumerate(args) if _names(a) & alias]
        for t2, m2 in taint_solver.resolve_call(model, t, c, env):
            # Follow the id into the callee by the name of the parameter that receives it.
            tgt = [m2.params[i].name for i in idxs if i < len(m2.params)]
            tgt += [k for k, v in named.items() if _names(v) & alias]
            for p in tgt:
                sub, vis = _reach(model, summaries, t2, m2, p, depth - 1, seen)
                if sub:
                    how = how or sub
                    access.append(c)
                    path.extend(vis)
    return how, ([((t, m), access, alias)] + path) if how else []


# -- the three rules ------------------------------------------------------

def _idor(model: ProjectModel, summaries: dict, ref: RouteRef, entities: set[str]) -> str | None:
    m = ref.method
    decl = _declaring(model, ref.type, m)
    ents = {e.lower() for e in entities}
    for p in m.params:
        if not _is_id_like(p.name) or _simple(p.type).lower() in ents:
            continue
        how, visited = _reach(model, summaries, decl, m, p.name, _MAX_DEPTH, set())
        if how and not any(_guarded(x.body, acc, al) for (_, x), acc, al in visited):
            return f"'{p.name}' ({how})"
    return None


def _write_verb(ref: RouteRef) -> bool:
    """POST/PUT/PATCH by explicit verb attribute, or by Web API name prefix (MVC defaults to GET+POST,
    which says nothing about intent)."""
    if not set(ref.route.methods) & _WRITE_VERBS:
        return False
    return ref.route.meta.get("kind") == "webapi" or any(attr_key(a.name) in _VERB_ATTRS for a in ref.method.attributes)


def _bind_kind(attrs) -> str:
    """"include" for [Bind(Include=...)] / [Bind("a,b")] (a whitelist), "exclude" for an Exclude-only
    [Bind] (every other field stays bindable, R12), "" for none or `Prefix` alone."""
    kind = ""
    for a in attrs:
        if attr_key(a.name) != "bind":
            continue
        named = {k.lower() for k in a.named}
        if a.args or "include" in named:
            return "include"
        if "exclude" in named:
            kind = "exclude"
    return kind


def _overposted(model: ProjectModel, ref: RouteRef, entities: set[str]) -> tuple[str, bool] | None:
    """(parameter name, only an Exclude list protects it) for the first unprotected entity parameter."""
    if not _write_verb(ref):
        return None
    ents = {e.lower() for e in entities}
    mvc = ref.route.meta.get("kind") == "mvc"        # Web API model binding ignores [Bind]
    for p in ref.method.params:
        # An entity, or a collection / array of them (List<Order>, Order[], IEnumerable<Order>).
        hit = [_simple(tok) for tok in _TOKEN.findall(p.type or "") if _simple(tok).lower() in ents]
        if not hit:
            continue
        # [Bind] on the entity class applies to every use of it.
        kinds = {_bind_kind(p.attributes)} | {_bind_kind(et.attributes) for h in hit for et in model.find_types(h)}
        if mvc and "include" in kinds:
            continue
        return p.name, mvc and "exclude" in kinds
    return None


_NEW_TEXT = re.compile(r"^new\s+(?:\{|([A-Za-z_][\w.]*(?:\s*<[^>]*>)?)\s*[({])")


def _selects_dto(call: dict, ents: set[str]) -> bool:
    """`Select(x => new Dto { .. })` / `Select(x => new { .. })`: a lambda whose body creates an
    object that is neither an entity nor a collection of entities (anonymous types qualify)."""
    for a in call.get("args") or []:
        body = a.get("body") if isinstance(a, dict) and a.get("k") == "lambda" else None
        if not isinstance(body, dict):
            continue
        if body.get("k") == "new":
            text = " ".join(str(body.get(x) or "") for x in ("type", "type_full"))
        elif isinstance(body.get("text"), str) and _NEW_TEXT.match(body["text"].strip()):
            text = _NEW_TEXT.match(body["text"].strip()).group(1) or ""
        else:
            continue
        return not any(_simple(tok).lower() in ents for tok in _TOKEN.findall(text))
    return False


def _entity_valued(expr, ents: set[str], env: dict[str, str], dbsets: dict[str, str], vb: bool) -> bool:
    """Does the expression evaluate to an entity (or a collection of them), via the IR."""
    if not isinstance(expr, dict):
        return False
    k = expr.get("k")
    if k == "name":
        return any(_simple(tok).lower() in ents for tok in _TOKEN.findall(env.get(((expr.get("id") or "").lower() if vb else expr.get("id")) or "", "")))
    if k == "new":
        return _simple(expr.get("type_full") or expr.get("type")).lower() in ents
    if k == "call":
        if (call_name(expr) or "").lower() not in _ENTITY_RESULT or _on_dbset(expr.get("fn") or {}, dbsets) is None:
            return False
        # Walk the call chain down to the DbSet: a Select into a non-entity type on the way makes the
        # result a DTO (GroupBy / OfType / Cast / SelectMany can still yield entities).
        cur = expr
        while isinstance(cur, dict) and cur.get("k") == "call":
            if (call_name(cur) or "").lower() == "select" and _selects_dto(cur, ents):
                return False
            fn = cur.get("fn") or {}
            cur = fn.get("obj") if fn.get("k") == "member" else None
        return True
    return False


def _exposed(model: ProjectModel, ref: RouteRef, entities: set[str]) -> str | None:
    if ref.route.meta.get("kind") != "webapi":
        return None
    m = ref.method
    ents = {e.lower() for e in entities}
    if any(_simple(tok).lower() in ents for tok in _TOKEN.findall(m.return_type or "")):
        return f"declared return type {m.return_type}"
    vb = _is_vb(model, ref.type)
    env = _env_types(ref.type, m, vb)
    dbsets = _dbset_map(model)
    for n in walk(m.body):
        v = n.get("value") if n.get("k") == "return" else None
        if isinstance(v, dict) and (call_name(v) or "").lower() in ("ok", "json") and v.get("args"):
            if _entity_valued(v["args"][0], ents, env, dbsets, vb):
                return f"{call_name(v)}(...) of an entity"
    return None


def check(model: ProjectModel, refs: list[RouteRef]) -> list[Finding]:
    """AUTHZ-005/006/007 findings, at most one per rule and route."""
    if not model.files:
        return []
    entities = entity_types(model)
    summaries = taint_solver.solve(model)
    out: list[Finding] = []
    for ref in refs:
        if ref.method is None or ref.type is None or ref.route.meta.get("kind") not in ("mvc", "webapi"):
            continue
        r = ref.route
        api = bool(r.meta.get("api_surface"))
        hid = r.handler_name
        why = _idor(model, summaries, ref, entities)
        if why:
            out.append(dnl_finding(
                "DNL-AUTHZ-005", "low", "Object-level authorization gap (IDOR)",
                f"Identifier parameter {why} selects a record in {hid}, and nothing in the action or the methods on "
                f"that path ties the lookup to the signed-in user (an ownership condition that rejects the "
                f"request, or a user-scoped query). Any caller who can reach the route may read or change other "
                f"users' objects; verify an ownership check exists.",
                r.file, r.line, route=r, api_surface=api, confidence="REVIEW"))
        over = _overposted(model, ref, entities)
        if over:
            why, excl = over
            note = (" Only a [Bind(Exclude=...)] list is present: every field not excluded stays bindable, so "
                    "switch to an Include whitelist.") if excl else ""
            out.append(dnl_finding(
                "DNL-AUTHZ-006", "medium", "Over-posting (entity bound from request)",
                f"Parameter '{why}' of {hid} is an entity type bound directly from the request with no "
                f"[Bind(Include=...)] list, so a client can set any property (ownership, role, price). "
                f"Bind a view model or whitelist the fields." + note,
                r.file, r.line, route=r, api_surface=api, confidence="REVIEW" if excl else None))
        why = _exposed(model, ref, entities)
        if why:
            out.append(dnl_finding(
                "DNL-AUTHZ-007", "low", "Entity returned from an API (over-exposure)",
                f"{hid} returns a data-model entity ({why}), serializing every property including internal ones. "
                f"Return a DTO that lists only the fields the client needs.",
                r.file, r.line, route=r, api_surface=api))
    return out
