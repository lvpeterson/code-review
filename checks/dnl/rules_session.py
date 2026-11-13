"""Session and authentication code rules: DNL-SESS-006 (logout keeps the session), DNL-SESS-007
(login without session renewal) and DNL-SESS-008 (plaintext password comparison).

SESS-006/007 judge one method at a time but follow resolved project calls: a logout or
login counts as handled when the method, a project method it calls (up to 3 levels) or a
project method calling it (one level) abandons/renews the session. That leans towards "handled"
on a name collision, which is why both are low REVIEW findings. Call names are matched
case-insensitively (VB) and `sym` is used when the helper resolved the call, with a receiver-name
fallback because MVC types are often unresolved. SESS-008 is one finding per comparison
expression, anchored at its line.

A finding is routed when it sits in a route handler's method (MVC / Web API action, or any method
of a WebForms page type); everything else is route-less and the analyzers place it.
"""
from __future__ import annotations

import re

from checks.dnl.findings import dnl_finding
from checks.dnl.ir import call_name, receiver_text, walk
from checks.dnl.typestate import RouteIndex, iter_bodies
from core.models import Finding

_LOGOUT = re.compile(r"(?i)log_?out|log_?off|sign_?out")
_SESSION_ID_COOKIE = "asp.net_sessionid"
_PASS = re.compile(r"(?i)pass(?:word)?|pwd")
# Names that mention a password but are not the secret itself (or are already protected).
_NOT_PW = re.compile(r"(?i)bypass|compass|passed|passes|passing|passenger|passthrough|passport|passive"
                     r"|hash|salt|digest|confirm|retype|repeat|verif|encrypt|cipher"
                     r"|format|length|policy|regex|expir|required|minimum")
# Comparing a password to its confirmation field is input validation, not authentication.
_CONFIRM = re.compile(r"(?i)confirm|retype|repeat")
_HASH_CALL = re.compile(r"(?i)hash|verify|bcrypt|pbkdf|passwordhasher")
_TRANSPARENT = {"trim", "trimstart", "trimend", "tolower", "toupper", "tolowerinvariant", "toupperinvariant",
                "tostring", "normalize"}
_SELF = {"this", "me", "base", "mybase", "myclass"}
_STATIC_RECV = ("string", "system.string", "object", "system.object")


def _tail(fn) -> str:
    """Lowercased last segment of a call's receiver (`a.Authentication.SignOut` -> authentication)."""
    obj = fn.get("obj") if isinstance(fn, dict) else None
    if not isinstance(obj, dict):
        return ""
    k = obj.get("k")
    if k == "name":
        return (obj.get("id") or "").lower()
    if k == "member":
        return (obj.get("name") or "").lower()
    if k == "call":
        return (call_name(obj) or "").lower()
    return ""


def _is(n: dict, name: str, tails: tuple, syms: tuple) -> bool:
    if n.get("k") != "call" or (call_name(n) or "").lower() != name:
        return False
    fn = n.get("fn") or {}
    sym = (n.get("sym") or fn.get("sym") or "").lower()
    return _tail(fn) in tails or any(s in sym for s in syms)


def _signout(n) -> bool:
    return _is(n, "signout", ("formsauthentication", "authenticationmanager", "authentication"),
               ("formsauthentication.", "authenticationmanager."))


def _signin(n) -> bool:
    if n.get("k") == "call" and (call_name(n) or "").lower() in ("setauthcookie", "redirectfromloginpage"):
        return True
    return _is(n, "signin", ("authenticationmanager", "authentication"), ("authenticationmanager.",))


def _abandon(n) -> bool:
    return any(_is(n, nm, ("session",), ("sessionstate",)) for nm in ("abandon", "clear", "removeall"))


def _renew(n) -> bool:
    if n.get("k") == "lit" and isinstance(n.get("v"), str):
        return n["v"].lower() == _SESSION_ID_COOKIE
    if _is(n, "abandon", ("session",), ("sessionstate",)):
        return True
    return n.get("k") == "call" and (call_name(n) or "").lower() in ("createsessionid", "savesessionid")


class _Ctx:
    def __init__(self, model, refs):
        self.model = model
        self.routes = RouteIndex(refs)
        # Call graph over project methods: callee edges (`calls`) and the reverse (`callers`), both
        # keyed by id(method). Edges follow a resolved `sym` exactly, or an unqualified / this / base
        # call into the caller's own base chain; any other receiver is not followed.
        self.calls: dict = {}
        self.callers: dict = {}
        self._decl: dict = {}
        self._chain: dict = {}
        for t in model.types():
            for m in t.methods:
                self._decl.setdefault((t.full_name.lower(), m.name.lower()), []).append(m)
        for t in model.types():
            for m in t.methods:
                targets: list = []
                for n in walk(m.body):
                    if n.get("k") == "call":
                        for c in self._targets(t, n):
                            if all(c is not x for x in targets):
                                targets.append(c)
                self.calls[id(m)] = targets
                for c in targets:
                    self.callers.setdefault(id(c), []).append(m)

    def _own_chain(self, t) -> list:
        """Full names (lowered) of `t` and every project type in its base chain."""
        key = id(t)
        if key not in self._chain:
            names = [t.full_name.lower()]
            for b in self.model.base_chain(t):
                names += [bt.full_name.lower() for bt in self.model.find_types(b)]
            self._chain[key] = names
        return self._chain[key]

    def _targets(self, t, call: dict) -> list:
        nm = (call_name(call) or "").lower()
        if not nm:
            return []
        fn = call.get("fn") or {}
        sym = call.get("sym") or fn.get("sym")
        if sym:
            return list(self._decl.get((sym.rpartition(".")[0].lower(), nm), ()))
        obj = fn.get("obj") if fn.get("k") == "member" else None
        if obj is not None and not (isinstance(obj, dict) and obj.get("k") == "name"
                                    and (obj.get("id") or "").lower() in _SELF):
            return []
        return [c for full in self._own_chain(t) for c in self._decl.get((full, nm), ())]

    def route(self, file: str, line: int):
        return self.routes.route(file, line)

    def _down(self, m, pred, depth: int, seen: set) -> bool:
        if id(m) in seen:
            return False
        seen.add(id(m))
        if any(pred(n) for n in walk(m.body)):
            return True
        if depth == 0:
            return False
        return any(self._down(c, pred, depth - 1, seen) for c in self.calls.get(id(m), ()))

    def handled(self, m, pred) -> bool:
        if self._down(m, pred, 3, set()):
            return True
        return any(self._down(c, pred, 3, set()) for c in self.callers.get(id(m), ()))


def _first(m, pred):
    return next((n for n in walk(m.body) if pred(n)), None)


def _flow(ctx, t, m, n, rule, title, what, confidence="REVIEW") -> Finding:
    line = n.get("line", m.line)
    r = ctx.route(t.file, m.line)
    return dnl_finding(rule, "low", title, f"{t.name}.{m.name} {what} ({t.file}:{line}) (in {t.name}.{m.name}).",
                       t.file, line, route=r, api_surface=bool(r.meta.get("api_surface")) if r else False,
                       confidence=confidence)


def _sess_flows(ctx: _Ctx, out: list) -> None:
    for t in ctx.model.types():
        for m in t.methods:
            if _LOGOUT.search(m.name):
                n = _first(m, _signout)
                if n is not None and not ctx.handled(m, _abandon):
                    out.append(_flow(ctx, t, m, n, "DNL-SESS-006", "Logout does not end the session",
                                     "signs the user out but never calls Session.Abandon or Session.Clear, so "
                                     "server-side session state outlives the logout"))
            n = _first(m, _signin)
            if n is not None and not ctx.handled(m, _renew):
                out.append(_flow(ctx, t, m, n, "DNL-SESS-007", "Login does not renew the session",
                                 "signs the user in without abandoning the session or regenerating the session "
                                 "id, which allows session fixation"))


# -- SESS-008 -------------------------------------------------------------------

def _pw_name(nm: str):
    return nm if _PASS.search(nm) and not _NOT_PW.search(nm) else None


def _operand(e, hashed_locals: set):
    """(password_name_or_None, hashed, literal) for one comparison operand."""
    if not isinstance(e, dict):
        return None, False, None
    k = e.get("k")
    if k == "lit":
        return None, False, ("lit", e.get("v"))
    if k in ("name", "member"):
        nm = (e.get("id") if k == "name" else e.get("name")) or ""
        if k == "member" and receiver_text(e).lower().endswith("string.empty"):
            return None, False, ("lit", "")
        return _pw_name(nm), nm.lower() in hashed_locals or bool(_CONFIRM.search(nm)), None
    if k == "cast":
        return _operand(e.get("e"), hashed_locals)
    if k == "index":
        key = (e.get("args") or [None])[0]
        if isinstance(key, dict) and key.get("k") == "lit" and isinstance(key.get("v"), str):
            return _pw_name(key["v"]), False, None
        return None, False, None
    if k == "call":
        nm = (call_name(e) or "").lower()
        fn = e.get("fn") or {}
        if _HASH_CALL.search(nm) or _HASH_CALL.search(receiver_text(fn.get("obj"))):
            return None, True, None
        if nm in _TRANSPARENT and fn.get("k") == "member":
            return _operand(fn.get("obj"), hashed_locals)
    return None, False, None


def _compare_operands(n: dict):
    """The two operands of a comparison node, or None."""
    k = n.get("k")
    if k == "bin" and n.get("op") in ("==", "!=", "=", "<>"):
        return n.get("l"), n.get("r")
    if k != "call":
        return None
    nm = (call_name(n) or "").lower()
    fn, args = n.get("fn") or {}, n.get("args") or []
    recv = receiver_text(fn.get("obj")).lower()
    static = recv in _STATIC_RECV or recv.startswith(("stringcomparer", "system.stringcomparer"))
    if nm == "equals":
        if fn.get("k") == "name" or static:
            return (args[0], args[1]) if len(args) >= 2 else None
        return (fn.get("obj"), args[0]) if fn.get("obj") is not None and args else None
    if nm in ("compare", "compareordinal") and static and len(args) >= 2:
        return args[0], args[1]
    return None


def _plaintext_compares(nodes: list, hashed_locals: set):
    for n in nodes:
        ops = _compare_operands(n)
        if ops is None:
            continue
        info = [_operand(o, hashed_locals) for o in ops]
        names = [i[0] for i in info if i[0]]
        if not names or any(i[1] for i in info):
            continue
        # `password == null` / `== ""`: an emptiness check, not a secret comparison.
        if any(i[2] is not None and (i[2][1] is None or i[2][1] == "" or not isinstance(i[2][1], str))
               for i in info):
            continue
        yield n, names[0]


def _hashed_locals(nodes: list) -> set:
    out: set = set()
    for n in nodes:
        if n.get("k") == "local" and n.get("name") and isinstance(n.get("init"), dict):
            target, value = n["name"], n["init"]
        elif n.get("k") == "assign" and n.get("op") == "=" and isinstance(n.get("target"), dict):
            target, value = (n["target"].get("id") or n["target"].get("name") or ""), n.get("value")
        else:
            continue
        if target and any(c.get("k") == "call" and _HASH_CALL.search(call_name(c) or "") for c in walk(value)):
            out.add(target.lower())
    return out


def _compares(ctx: _Ctx, out: list) -> None:
    seen: set = set()
    for t in ctx.model.types():
        if t.kind == "enum":
            continue
        for label, _m, body, _scope in iter_bodies(t):
            nodes = [n for n in walk(body) if isinstance(n, dict)]
            for n, name in _plaintext_compares(nodes, _hashed_locals(nodes)):
                line = n.get("line", t.line)
                key = (t.file, line, name.lower())
                if key in seen:
                    continue
                seen.add(key)
                r = ctx.route(t.file, line)
                out.append(dnl_finding(
                    "DNL-SESS-008", "medium", "Plaintext password comparison",
                    f"'{name}' is compared directly ({t.file}:{line}) instead of through a password hash or verify "
                    f"call; stored passwords should be hashed and checked with a constant-time verifier "
                    f"(in {t.name}.{label}).",
                    t.file, line, route=r, api_surface=bool(r.meta.get("api_surface")) if r else False,
                    confidence="REVIEW"))


def check(model, refs=()) -> list:
    """SESS-006..008 findings over every type of the model; `refs` only decide which carry a route."""
    ctx = _Ctx(model, refs)
    out: list = []
    _sess_flows(ctx, out)
    _compares(ctx, out)
    return out
