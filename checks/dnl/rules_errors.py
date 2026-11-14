"""Exception-handling rules: DNL-ERR-001 (fail-open catch around an authorization decision),
DNL-ERR-002 (exception detail returned to the client) and DNL-ERR-003 (swallowed exception).

All three read the `try` statements of the IR (catch type, catch variable, catch body) and need no
taint engine: the exception is not a request source, so ERR-002 runs its own small flow-insensitive
pass inside one catch block and the injection / XSS rules never see it.

ERR-002 starts from the catch variable and follows it through locals (`var msg = ex.Message`), member
reads (`ex.Message`, `ex.InnerException.Message`, `ex.StackTrace`), `ToString()`, string building
(`+`, `&`, interpolation, `String.Format`, `StringBuilder.Append`), object initializers and member
assignments (`model.Detail = ...`) until a response sink: `Content` / `Json` / `View` / `Ok` /
`BadRequest` / `InternalServerError` / `CreateErrorResponse` ..., `Response.Write`, `ViewBag` /
`ViewData` / `TempData`, a control's `.Text`, or a `FaultException` / `HttpResponseException`.
Only the type name (`ex.GetType().Name`) and plain logging are treated as safe. Anything that
mentions the exception anywhere inside a sink argument counts: a false "safe" is worse than noise.

ERR-001 applies to a `try` that is an authorization decision: it sits in a method named like one
(`AuthorizeCore`, `OnAuthorization`, `IsAuthorized` ...), or its body checks a role / authentication
state (`IsInRole`, `IsAuthenticated`, ...) or calls a project method that does (two levels). A catch
there is fail-open when it returns literal true, or neither denies (throw, return of anything but
true, `.Result =`, `HandleUnauthorizedRequest`, ...) nor is followed by a deny-by-default tail (the
statements after the try return false, or a local that starts out false / unset). An empty catch in
such a try is reported as ERR-001 or not at all, never as ERR-003.

ERR-003 reports an empty catch-all (`catch { }`, `catch (Exception) { }`, VB `Catch` / `Catch ex As
Exception` with no statements). An empty catch on a narrow type (`FormatException`) is a deliberate
fallback and is not reported.
"""
from __future__ import annotations

import re

from checks.dnl.findings import dnl_finding
from checks.dnl.flowutil import walk_nl
from checks.dnl.ir import call_name, receiver_text, walk
from checks.dnl.typestate import RouteIndex, iter_bodies, simple
from core.models import Finding

# -- ERR-002 tables ---------------------------------------------------------------

# Members of the exception object that carry detail (everything but GetType()).
_DETAIL = {"message", "stacktrace", "innerexception", "data", "source", "targetsite", "helplink", "tostring",
           "getbaseexception"}
_DETAIL_CALLS = {"tostring", "getbaseexception"}
_SINK_CALLS = {"content", "json", "jsonp", "ok", "badrequest", "internalservererror", "createerrorresponse",
               "createresponse", "view", "partialview", "statuscode", "problem", "notfound", "conflict",
               "unprocessableentity", "unauthorized", "forbid", "addmodelerror", "responsemessage", "negotiated",
               "created", "accepted", "redirect", "redirectpermanent", "redirecttoaction", "redirecttoroute",
               "redirecttoactionpermanent", "appendheader", "addheader"}
_SINK_NEW = {"faultexception", "httpresponseexception", "httpexception", "stringcontent", "jsonresult",
             "contentresult", "httpstatuscoderesult", "httpnotfoundresult", "viewresult"}
_SINK_ROOTS = {"viewbag", "viewdata", "tempdata"}
_SINK_MEMBERS = {"text", "innertext", "innerhtml", "statusdescription"}
_WRITE_CALLS = {"write", "writeline", "binarywrite", "writefile"}
_HEADER_CALLS = {"add", "set", "append"}
_SELF = {"this", "me", "base", "mybase", "myclass"}

# -- ERR-001 tables ---------------------------------------------------------------

_DECISION_NAME = re.compile(r"(?i)authori[sz]e|authori[sz]ation|isauthori|isauthenticated|hasaccess|hasrole|haspermission"
                            r"|canaccess|checkaccess|checkpermission|isallowed|isinrole|userinrole|checkauth")
_MARKER_NAMES = {"isinrole", "isuserinrole", "isauthenticated", "authorizecore", "onauthorization",
                 "onauthorizationasync", "isauthorized", "hasaccess", "validateuser"}
# A refusal outright, versus a redirect: a redirect is a refusal only when it is the first thing that
# runs after the catch (otherwise it is the normal success path of the action).
# Only calls that end the request on their own are refusals as statements. `Challenge()` / `Forbid()` /
# `Unauthorized()` only deny when their result is returned; OWIN `Authentication.Challenge()` / `SignOut()`
# and `CompleteRequest()` let the code carry on.
_REFUSE_CALLS = {"handleunauthorizedrequest", "abort", "end", "transfer"}
_RETURN_DENY_CALLS = _REFUSE_CALLS | {"forbid", "unauthorized", "challenge"}
_REDIRECT_CALLS = {"redirect", "redirectpermanent", "redirecttoaction", "redirecttoactionpermanent",
                   "redirecttoroute", "redirecttoroutepermanent"}
_DENY_MEMBERS = {"result"}
_REFUSE_NEW = {"httpunauthorizedresult", "unauthorizedresult", "forbidresult", "challengeresult",
               "httpstatuscoderesult"}
_REDIRECT_NEW = {"redirectresult", "redirecttorouteresult"}
# Methods whose whole body is an authorization decision whatever the try inside does.
_KNOWN_DECISION = {"authorizecore", "onauthorization", "onauthorizationasync", "isauthorized", "authorize"}
_CATCH_ALL = {"", "exception", "systemexception", "object"}
_BOOLS = {"bool", "boolean", "task<bool>", "task(ofboolean)"}


def _lit(e, value) -> bool:
    return isinstance(e, dict) and e.get("k") == "lit" and e.get("v") is value


def _root(e) -> str:
    """Lowered root name of a member / index chain (`a.b[c].d` -> a); "" for anything else."""
    while isinstance(e, dict):
        k = e.get("k")
        if k == "name":
            return (e.get("id") or "").lower()
        if k in ("member", "index"):
            e = e.get("obj")
        elif k == "cast":
            e = e.get("e")
        else:
            return ""
    return ""


# -- ERR-002 ----------------------------------------------------------------------

class _Flow:
    """The exception-derived names of one catch block."""

    def __init__(self, catch_var: str, body, preset=()):
        self.ex = catch_var
        self.tainted: set = set(preset)
        nodes = [n for n in walk(body)]
        for _ in range(len(nodes) + 1):
            before = len(self.tainted)
            for n in nodes:
                self._learn(n)
            if len(self.tainted) == before:
                break

    def leaks(self, e) -> bool:
        if isinstance(e, list):
            return any(self.leaks(x) for x in e)
        if not isinstance(e, dict):
            return False
        k = e.get("k")
        if k == "call" and (call_name(e) or "").lower() == "getlasterror":
            return True                       # Server.GetLastError(): the unhandled exception
        if k == "name":
            nm = (e.get("id") or "").lower()
            return nm == self.ex or nm in self.tainted
        if k == "member":
            obj = e.get("obj")
            if _root(obj) == self.ex and isinstance(obj, dict) and obj.get("k") == "name":
                return (e.get("name") or "").lower() in _DETAIL
            return self.leaks(obj)
        if k == "call":
            fn = e.get("fn") or {}
            if fn.get("k") == "member":
                obj = fn.get("obj")
                if isinstance(obj, dict) and obj.get("k") == "name" and (obj.get("id") or "").lower() == self.ex:
                    return (fn.get("name") or "").lower() in _DETAIL_CALLS or self.leaks(e.get("args"))
                return self.leaks(obj) or self.leaks(e.get("args"))
            return self.leaks(fn) or self.leaks(e.get("args"))
        return any(self.leaks(v) for v in e.values() if isinstance(v, (dict, list)))

    def _learn(self, n: dict) -> None:
        k = n.get("k")
        if k == "local" and n.get("name") and self.leaks(n.get("init")):
            self.tainted.add(n["name"].lower())
        elif k == "assign" and self.leaks(n.get("value")):
            r = _root(n.get("target"))
            if r and r not in _SELF:
                self.tainted.add(r)
        elif k == "call":
            # `sb.Append(ex.Message)` / `list.Add(ex.Message)`: the receiver now holds the detail.
            fn = n.get("fn") or {}
            if fn.get("k") == "member" and self.leaks(n.get("args")):
                r = _root(fn.get("obj"))
                if r and r not in _SELF:
                    self.tainted.add(r)


def _sinks(flow: _Flow, body: list, routed_return: bool):
    """(line, what) of every place the catch body hands exception detail to the client."""
    for n in walk(body):
        k = n.get("k")
        if k == "call":
            nm = (call_name(n) or "").lower()
            fn = n.get("fn") or {}
            recv = receiver_text(fn.get("obj")).lower()
            if nm in _SINK_CALLS or (nm in _WRITE_CALLS and "response" in recv)                     or (nm in _HEADER_CALLS and "header" in recv):
                if flow.leaks(n.get("args")):
                    yield n.get("line", 0), (call_name(n) or nm)
        elif k == "new":
            if simple(n.get("type")) in _SINK_NEW and flow.leaks([n.get("args"), n.get("init")]):
                yield n.get("line", 0), "new " + simple(n.get("type"))
        elif k == "assign" and flow.leaks(n.get("value")):
            tgt = n.get("target") or {}
            member = (tgt.get("name") or "").lower() if tgt.get("k") == "member" else ""
            if _root(tgt) in _SINK_ROOTS or member in _SINK_MEMBERS:
                yield n.get("line", 0), receiver_text(tgt) or (_root(tgt) + "[...]")
        elif k == "return" and routed_return and flow.leaks(n.get("value")):
            yield n.get("line", 0), "return value"


# -- ERR-001 ----------------------------------------------------------------------

def _is_marker(n: dict) -> bool:
    k = n.get("k")
    if k == "call":
        nm = (call_name(n) or "").lower()
        return nm in _MARKER_NAMES or bool(_DECISION_NAME.search(nm))
    if k == "member":
        return (n.get("name") or "").lower() in _MARKER_NAMES
    return False


class _Auth:
    """Decision methods of the project: named like one, or checking a role / auth state, or calling
    such a method (two levels)."""

    def __init__(self, model):
        self.by_name: dict = {}
        self.owner: dict = {}
        for t in model.types():
            for m in t.methods:
                self.by_name.setdefault(m.name.lower(), []).append((t, m))
                self.owner[id(m)] = t
        self._memo: dict = {}

    def _targets(self, call: dict):
        nm = (call_name(call) or "").lower()
        fn = call.get("fn") or {}
        cands = self.by_name.get(nm, ())
        sym = call.get("sym") or fn.get("sym")
        if sym:
            owner = sym.rpartition(".")[0].lower()
            return [m for t, m in cands if t.full_name.lower() == owner]
        obj = fn.get("obj") if fn.get("k") == "member" else None
        if obj is None or (isinstance(obj, dict) and obj.get("k") == "name"
                           and (obj.get("id") or "").lower() in ("this", "me", "base", "mybase", "myclass")):
            return [m for _t, m in cands]
        return []

    def decides(self, stmts, depth: int = 2, seen: frozenset = frozenset()) -> bool:
        for n in walk(stmts):
            if _is_marker(n):
                return True
        if depth == 0:
            return False
        for n in walk(stmts):
            if n.get("k") == "call":
                for m in self._targets(n):
                    if id(m) in seen:
                        continue
                    key = (id(m), depth)
                    if key not in self._memo:
                        self._memo[key] = (bool(_DECISION_NAME.search(m.name))
                                           or self.decides(m.body, depth - 1, seen | {id(m)}))
                    if self._memo[key]:
                        return True
        return False


_UNKNOWN = {"k": "?"}


def _value_sources(body: list) -> dict:
    """Lowered local name -> [(id of the node, value expr)] for every initializer and every assignment in the
    body. A compound assignment (`|=`) is a source of unknown value; a declaration without an
    initializer is no source (an unset C# local is not false)."""
    out: dict = {}
    for n in walk(body):
        k = n.get("k")
        if k == "local" and n.get("name") and n.get("init") is not None:
            out.setdefault(n["name"].lower(), []).append((id(n), n["init"]))
        elif k == "assign" and (n.get("target") or {}).get("k") == "name":
            val = (n.get("value") if n.get("op") in ("=", None) else None) or _UNKNOWN
            out.setdefault((n["target"].get("id") or "").lower(), []).append((id(n), val))
    return out


_ERROR_STATUS = {"badrequest", "unauthorized", "forbidden", "notfound", "methodnotallowed", "notacceptable",
                 "conflict", "gone", "preconditionfailed", "unsupportedmediatype", "requestentitytoolarge",
                 "toomanyrequests", "internalservererror", "notimplemented", "badgateway", "serviceunavailable",
                 "gatewaytimeout"}
# Returned error results: the protected work did not happen, whatever the status says about why.
_ERROR_RESULT_CALLS = {"internalservererror", "badrequest", "notfound", "conflict", "createerrorresponse",
                       "httpnotfound"}
_STATUS_CALLS = {"statuscode", "createresponse"}


def _status_denies(n: dict) -> bool:
    """A 4xx / 5xx status as the FIRST argument (the status slot): `new HttpStatusCodeResult(403)`,
    `HttpStatusCode.Unauthorized`, `(int)HttpStatusCode.BadRequest`, `StatusCode(500)`. Later
    arguments are payload (`CreateResponse(HttpStatusCode.OK, items.Take(500))`) and never count."""
    args = n.get("args") or []
    named = {str(k).lower(): v for k, v in (n.get("named") or {}).items()}
    slot = [named["statuscode"]] if "statuscode" in named else args[:1]
    for x in walk(slot):
        if x.get("k") == "lit" and isinstance(x.get("v"), int) and 400 <= x["v"] <= 599:
            return True
        nm = (x.get("id") or x.get("name") or "").lower() if x.get("k") in ("name", "member") else ""
        if nm in _ERROR_STATUS:
            return True
    return False


def _deny_value(v, redirect_ok: bool = True) -> bool:
    """A returned value that refuses the request: an unauthorized / 401 / 403 result object or call,
    or (when `redirect_ok`) a redirect. Decided on the top-level shape: casts and `FromResult(..)`
    are transparent, `c ? a : b` and `a ?? b` need both branches to refuse, and a refusal nested
    as an argument of another call (`Ok(Unauthorized())`) does not count."""
    if not isinstance(v, dict):
        return False
    k = v.get("k")
    if k == "cast":
        return _deny_value(v.get("e"), redirect_ok)
    if k == "cond":
        return _deny_value(v.get("t"), redirect_ok) and _deny_value(v.get("f"), redirect_ok)
    if k == "bin" and str(v.get("op") or "") == "??":
        return _deny_value(v.get("l"), redirect_ok) and _deny_value(v.get("r"), redirect_ok)
    if k == "new":
        t = simple(v.get("type"))
        return bool((t in _REFUSE_NEW and (t != "httpstatuscoderesult" or _status_denies(v)))
                    or t == "httpnotfoundresult" or (t == "httpresponsemessage" and _status_denies(v))
                    or (redirect_ok and t in _REDIRECT_NEW))
    if k == "call":
        nm = (call_name(v) or "").lower()
        # Wrappers that hand back the result they are given: `Task.FromResult(x)`, Web API
        # `ResponseMessage(Request.CreateErrorResponse(..))`.
        if nm in ("fromresult", "responsemessage"):
            return _deny_value((v.get("args") or [None])[0], redirect_ok)
        return bool(nm in _RETURN_DENY_CALLS or nm in _ERROR_RESULT_CALLS or (nm in _STATUS_CALLS and _status_denies(v))
                    or (redirect_ok and nm in _REDIRECT_CALLS))
    return False


def _stmt_ends_request(call: dict) -> bool:
    """A statement-level call that ends the request: `Response.End()`, `Server.Transfer(..)`, ...,
    or `Response.Redirect(url)` / `Response.Redirect(url, true)` (not with endResponse false). A bare
    `Redirect(..)` / `RedirectToAction(..)` statement discards its result and ends nothing.
    Differs from flowutil._ends_request: takes the call expr, not the statement, and accepts any receiver."""
    nm = (call_name(call) or "").lower()
    if nm in _REFUSE_CALLS:
        return True
    if nm == "redirect" and "response" in receiver_text((call.get("fn") or {}).get("obj")).lower():
        args = call.get("args") or []
        named = {str(k).lower(): v for k, v in (call.get("named") or {}).items()}
        end = named["endresponse"] if "endresponse" in named else args[1] if len(args) >= 2 else None
        # Only a literal true (or no second argument) ends the request; a variable may be false.
        return end is None or _lit(end, True)
    return False


def _child_blocks(s: dict):
    """The statement lists directly nested in statement `s`."""
    for v in s.values():
        if isinstance(v, list) and v and all(isinstance(x, dict) and "k" in x for x in v):
            yield v
        elif isinstance(v, list):
            for x in v:
                if isinstance(x, dict) and isinstance(x.get("body"), list):
                    yield x["body"]


def _blocks(stmts):
    """Every statement list in `stmts`, nested ones included (not into lambdas)."""
    if isinstance(stmts, list):
        yield stmts
        for s in stmts:
            if isinstance(s, dict) and s.get("k") != "lambda":
                for b in _child_blocks(s):
                    yield from _blocks(b)


def _status_deny_stmt(s: dict, nxt) -> bool:
    """`Response.StatusCode = 401;` counts only when the next statement is a return."""
    if s.get("k") != "assign":
        return False
    tgt = s.get("target") or {}
    return (tgt.get("k") == "member" and (tgt.get("name") or "").lower() == "statuscode"
            and _status_denies({"args": [s.get("value")]}) and isinstance(nxt, dict) and nxt.get("k") == "return")


class _Truth:
    """Resolves an expression to "true" / "false" / "?" : literals, `!x`, locals with a single value
    source, consts, and project methods whose every return agrees."""

    def __init__(self, auth: _Auth, t, m_body: list):
        self.auth = auth
        self.srcs = _value_sources(m_body)
        # Only a const is a fixed value: any other field or property can be changed elsewhere.
        self.fields = {f.name.lower(): f.init for f in t.fields if f.is_const and f.init is not None}
        self.skip: set = set()               # ids of the nodes of the try body being judged

    def _is_decision(self, v) -> bool:
        """The decision call itself (`IsInRole(..)`, `!IsAuthenticated`, a project check method)."""
        while isinstance(v, dict) and (v.get("k") == "cast" or (v.get("k") == "unary"
                                                                 and v.get("op") in ("!", "Not", "not"))):
            v = v.get("e")
        if not isinstance(v, dict) or v.get("k") not in ("call", "member"):
            return False
        return _is_marker(v) or (v.get("k") == "call" and bool(self.auth._targets(v)) and self.auth.decides([v]))

    def of(self, e, depth: int = 2, seen: frozenset = frozenset()) -> str:
        if not isinstance(e, dict):
            return "?"
        k = e.get("k")
        if k == "lit":
            return "true" if e.get("v") is True else "false" if e.get("v") is False else "?"
        if k == "unary" and e.get("op") in ("!", "Not", "not"):
            v = self.of(e.get("e"), depth, seen)
            return {"true": "false", "false": "true"}.get(v, "?")
        if k == "cast":
            return self.of(e.get("e"), depth, seen)
        if k == "cond":
            a, b = self.of(e.get("t"), depth, seen), self.of(e.get("f"), depth, seen)
            return a if a == b else "?"
        if k == "name":
            nm = (e.get("id") or "").lower()
            if nm in seen:
                return "?"
            if nm in self.srcs:
                # A local resolves only with exactly one value source. In the judged try body only the
                # decision itself and assignments of false are left out; any other value the try
                # assigns may still be visible to the catch.
                srcs = [(ln, v) for ln, v in self.srcs[nm]
                        if ln not in self.skip
                        or not (self._is_decision(v) or self.of(v, depth, seen | {nm}) == "false")]
                return self.of(srcs[0][1], depth, seen | {nm}) if len(srcs) == 1 else "?"
            if nm in self.fields:
                return self.of(self.fields[nm], depth, seen | {nm})
            return "?"
        if k == "call" and depth > 0:
            outs = set()
            targets = self.auth._targets(e)
            for m in targets:
                inner = _Truth(self.auth, self.auth.owner[id(m)], m.body)
                rets = [n.get("value") for n in walk(m.body) if n.get("k") == "return" and n.get("value") is not None]
                outs |= {inner.of(r, depth - 1) for r in rets} or {"?"}
            return outs.pop() if len(outs) == 1 and targets else "?"
        return "?"


def _self_member(e) -> bool:
    """`this.X` / `Me.X` / `MyClass.X`."""
    obj = e.get("obj") if isinstance(e, dict) and e.get("k") == "member" else None
    return isinstance(obj, dict) and obj.get("k") == "name" and (obj.get("id") or "").lower() in _SELF


def _as_block(v) -> list:
    return v if isinstance(v, list) else [v] if isinstance(v, dict) else []


def _value_outcome(v, truth: _Truth) -> str:
    tv = truth.of(v)
    return "open" if tv == "true" else "deny" if tv == "false" or _deny_value(v) else "unknown"


def _flow(stmts, truth: _Truth, tail_names: set, mname: str, tail_empty: bool, states: frozenset):
    """Walk a catch block path by path. Returns (outs, falls): the outcomes of the paths that end in a
    return / throw / request end (or an open / unresolvable assignment), and the set of path states
    ("a deny was already set" True/False) of the paths that fall off the end of the block."""
    outs: set = set()
    stmts = _as_block(stmts)
    for i, s in enumerate(stmts):
        k = s.get("k")
        nxt = stmts[i + 1] if i + 1 < len(stmts) else None
        if k == "throw":
            outs.add("deny")
            return outs, frozenset()
        if k == "return":
            v = s.get("value")
            outs.add("pass" if v is None else _value_outcome(v, truth))
            return outs, frozenset()
        if k == "if":
            new: set = set()
            for branch in (s.get("then"), s.get("else")):
                for st in states:
                    o, f = _flow(branch, truth, tail_names, mname, tail_empty, frozenset([st]))
                    outs |= o
                    new |= f
            states = frozenset(new)
            if not states:
                return outs, states
            continue
        if k == "expr" and (s.get("expr") or {}).get("k") == "call" and _stmt_ends_request(s["expr"]):
            outs.add("deny")
            return outs, frozenset()
        if k == "assign":
            tgt = s.get("target") or {}
            if _status_deny_stmt(s, nxt) or (nxt is None and tail_empty and _status_deny_stmt(s, {"k": "return"})):
                outs.add("deny")
                return outs, frozenset()
            if tgt.get("k") == "member" and (tgt.get("name") or "").lower() in _DENY_MEMBERS:
                states = frozenset([True])
            elif (tgt.get("k") == "name" or _self_member(tgt)) and s.get("op") in ("=", None):
                nm = ((tgt.get("id") if tgt.get("k") == "name" else tgt.get("name")) or "").lower()
                if nm in tail_names or nm == mname:
                    o = _value_outcome(s.get("value"), truth)
                    if o == "deny":
                        states = frozenset([True])
                    else:
                        outs.add(o)
            continue
        if k in ("expr", "local", "break", "continue"):
            continue
        # Loops, nested try and the like: a value they return or assign may reach the caller, but a
        # denial inside them is not on every path.
        for n in walk_nl(s):
            nk = n.get("k")
            if nk == "return" and n.get("value") is not None:
                o = _value_outcome(n["value"], truth)
                if o != "deny":
                    outs.add(o)
            elif nk == "assign" and (n.get("target") or {}).get("k") in ("name", "member"):
                tgt = n["target"]
                if (tgt.get("k") == "name" or _self_member(tgt)) and n.get("op") in ("=", None):
                    nm = ((tgt.get("id") if tgt.get("k") == "name" else tgt.get("name")) or "").lower()
                    if nm in tail_names or nm == mname:
                        o = _value_outcome(n.get("value"), truth)
                        if o != "deny":
                            outs.add(o)
    return outs, states


def _classify_catch(cbody: list, truth: _Truth, tail_names: set, mname: str, tail_empty: bool = False) -> str:
    """What a catch does about the decision: "open" (grants access on some path, resolvable),
    "unknown" (a value or assignment that cannot be resolved), "deny" (every path denies) or "none"
    (some path falls through, or ends without denying: judged against the code after the try). An
    assignment only counts when the tail returns that name (or it is the VB function-name result)."""
    outs, falls = _flow(cbody, truth, tail_names, mname, tail_empty, frozenset([False]))
    for v in ("open", "unknown"):
        if v in outs:
            return v
    if "pass" in outs:
        return "none"
    if falls:
        return "deny" if all(falls) else "none"
    return "deny" if "deny" in outs else "none"


def _max_line(node) -> int:
    return max([n.get("line", 0) for n in walk(node) if isinstance(n.get("line"), int)] or [0])


def _tail(m_body: list, try_node: dict) -> list:
    """Every node that runs after the try (its following siblings, then those of the enclosing blocks)."""
    fol = _following(m_body, try_node)
    if fol is None:
        end = _max_line(try_node)
        return [n for n in walk_nl(m_body) if n.get("line", 0) > end]
    return list(walk_nl(fol))


def _following(stmts: list, tr: dict):
    """The statements that run after `tr` in source order: the rest of its own block, then the rest of
    each enclosing block. None when `tr` is not in `stmts`."""
    for i, s in enumerate(stmts):
        if s is tr:
            return stmts[i + 1:]
        for b in _child_blocks(s):
            r = _following(b, tr)
            if r is not None:
                return r + stmts[i + 1:]
    return None


def _refuses(s: dict, first: bool, nxt=None) -> bool:
    """A statement that on its own always refuses the request. A redirect counts only when it is
    the first statement after the catch (`first`)."""
    k = s.get("k")
    if k == "throw":
        return True
    if k == "return":
        return s.get("value") is not None and _deny_value(s["value"], first)
    if k == "expr":
        e = s.get("expr") or {}
        return e.get("k") == "call" and _stmt_ends_request(e) and (first or (call_name(e) or "").lower() != "redirect")
    if k == "assign":
        tgt = s.get("target") or {}
        nm = (tgt.get("name") or "").lower() if tgt.get("k") == "member" else ""
        return nm == "result" or _status_deny_stmt(s, nxt)
    return False


def _tail_verdict(follow: list, after: list, truth: _Truth, bool_like: bool, fn_vals: list) -> str:
    """What follows a catch that falls through: "open", "safe" or "unknown". `fn_vals` are the values
    assigned to the VB function name outside the try (they are the result when nothing returns)."""
    if not bool_like:
        # An action / handler: walk what runs after the try in order, descending into nested
        # blocks. A success return reachable before the first unconditional refusal means the
        # catch lets the request through; a refusal inside an `if` is conditional.
        for i, s in enumerate(follow):
            if _refuses(s, i == 0, follow[i + 1] if i + 1 < len(follow) else None):
                return "safe"
            for n in walk_nl(s):
                if n.get("k") == "return" and not (n.get("value") is not None and _deny_value(n["value"], False)):
                    return "open"
        return "open"
    rets = [n["value"] for n in after if n.get("k") == "return" and n.get("value") is not None]
    if not rets and not fn_vals:
        return "safe"          # Exit Function / end of function with nothing assigned: stays False
    verdicts = set()
    for r in rets:
        tv = truth.of(r)
        verdicts.add("open" if tv == "true" else "safe" if tv == "false" or _deny_value(r, False) else "unknown")
    for v in fn_vals:
        tv = truth.of(v)
        verdicts.add("open" if tv == "true" else "safe" if tv == "false" else "unknown")
    return "open" if "open" in verdicts else "unknown" if "unknown" in verdicts else "safe"


# -- driver -----------------------------------------------------------------------

class _Ctx:
    def __init__(self, model, refs):
        self.model = model
        self.routes = RouteIndex(refs)
        self.auth = _Auth(model)
        self._src: dict = {}

    def lines(self, file: str) -> list:
        if file not in self._src:
            try:
                self._src[file] = (self.model.root / file).read_text(encoding="utf-8-sig", errors="replace").splitlines()
            except OSError:
                self._src[file] = []
        return self._src[file]

    def catch_lines(self, file: str, try_node: dict) -> list:
        """Source line of each `catch` keyword of a try (the IR keeps no line for a catch). Several
        catches may share a line, so the scan continues after the previous match on that line. Falls
        back to the try line when the text does not show one."""
        src = self.lines(file)
        vb = file.lower().endswith(".vb")
        ln, col = max(_max_line(try_node.get("body")), try_node.get("line", 1)), 0
        out = []
        for c in try_node.get("catches") or []:
            found = None
            for i in range(ln, min(len(src), ln + 400) + 1):
                text = src[i - 1].split("'" if vb else "//")[0]
                m = re.compile(r"(?i)\bcatch\b").search(text, col if i == ln else 0)
                if m:
                    found, ln, col = i, i, m.end()
                    break
            out.append(found or try_node.get("line", 1))
            body_end = _max_line(c.get("body"))
            if found and body_end > found:
                ln, col = body_end, 0
        return out


def _finding(ctx, t, label, rule, sev, title, what, line, confidence=None) -> Finding:
    r = ctx.routes.route(t.file, line)
    return dnl_finding(rule, sev, title, f"{what} ({t.file}:{line}) (in {t.name}.{label}).", t.file, line,
                       route=r, api_surface=bool(r.meta.get("api_surface")) if r else False, confidence=confidence)


def _tries(body):
    return [n for n in walk(body) if n.get("k") == "try" and n.get("catches")]


_E1_TEXT = {
    "open": ("returns or assigns a value that grants access, so a failure while deciding lets the request "
             "through", None),
    "unknown": ("returns or assigns a value that is not clearly a denial, so it may let the request through",
                "REVIEW"),
    "fall": ("neither denies nor returns false and the code after it proceeds to the success path", "REVIEW"),
}


def _decision_verdict(c, tr, body, label, truth, bool_like, mname):
    """(text, confidence) when the catch `c` of the decision try `tr` is fail-open, else None."""
    after = _tail(body, tr)
    tail_names = {(x.get("id") or "").lower() for r in after if r.get("k") == "return"
                  for x in walk(r.get("value")) if x.get("k") == "name"}
    tail_names |= {(x.get("name") or "").lower() for r in after if r.get("k") == "return"
                   for x in walk(r.get("value")) if _self_member(x)}
    v = _classify_catch(c.get("body") or [], truth, tail_names, mname, not after)
    if v in ("open", "unknown"):
        return _E1_TEXT[v]
    if v == "deny":
        return None
    in_try = {id(n) for n in walk(tr)}
    fn_vals = [n.get("value") or _UNKNOWN for n in walk_nl(body)
               if n.get("k") == "assign" and (n.get("target") or {}).get("k") == "name"
               and (n["target"].get("id") or "").lower() == mname and n.get("op") in ("=", None)
               and id(n) not in in_try]
    tv = _tail_verdict(_following(body, tr) or [], after, truth, bool_like, fn_vals)
    return _E1_TEXT["fall"] if tv == "open" else _E1_TEXT["unknown"] if tv == "unknown" else None


def check(model, refs=()) -> list:
    ctx = _Ctx(model, refs)
    out: list = []
    seen: set = set()

    def emit(f: Finding):
        key = (f.check_id, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)

    def leak(t, label, line, sink, who):
        emit(_finding(ctx, t, label, "DNL-ERR-002", "medium", "Exception detail returned to the client",
                      f"Detail of {who} (message, stack trace or the exception itself) reaches {sink}, which "
                      f"sends it to the client", line))

    for t in model.types():
        if t.kind == "enum":
            continue
        for label, m, body, _scope in iter_bodies(t):
            bool_like = m is None or (m.return_type or "").replace(" ", "").lower() in _BOOLS
            truth = _Truth(ctx.auth, t, body)
            mname = (m.name if m else label).lower()
            for tr in _tries(body):
                truth.skip = {id(n) for n in walk(tr.get("body"))}
                known = label.lower() in _KNOWN_DECISION
                named = bool(_DECISION_NAME.search(label)) and bool_like
                decision = known or named or ctx.auth.decides(tr.get("body"))
                lines = ctx.catch_lines(t.file, tr)
                after = _tail(body, tr)
                for c, line in zip(tr["catches"], lines):
                    cbody = c.get("body") or []
                    ctype = simple(c.get("type"))
                    verdict = _decision_verdict(c, tr, body, label, truth, bool_like, mname) if decision else None
                    if verdict:
                        emit(_finding(ctx, t, label, "DNL-ERR-001", "medium",
                                      "Fail-open catch around an authorization decision",
                                      f"The catch ({ctype or 'all exceptions'}) around an authorization decision "
                                      f"{verdict[0]}", line, verdict[1]))
                    elif not cbody and ctype in _CATCH_ALL:
                        # An empty catch-all always yields ERR-001 or ERR-003, never neither.
                        emit(_finding(ctx, t, label, "DNL-ERR-003", "low", "Swallowed exception",
                                      "An empty catch block discards the exception without logging or handling it",
                                      line))
                    var = (c.get("name") or "").lower()
                    if var:
                        flow = _Flow(var, cbody)
                        routed = ctx.routes.route(t.file, line) is not None
                        who = f"the caught exception '{c.get('name')}'"
                        for sline, sink in _sinks(flow, cbody, routed):
                            leak(t, label, sline, sink, who)
                        # Detail kept in a variable the catch assigns and sunk after the try.
                        declared = {(n.get("name") or "").lower() for n in walk(cbody) if n.get("k") == "local"}
                        carriers = flow.tainted - declared - {var}
                        if carriers:
                            late = _Flow("\0", after, carriers)
                            for sline, sink in _sinks(late, after, routed):
                                leak(t, label, sline, sink, who)
            # Server.GetLastError() (Application_Error) written to the response.
            if any(n.get("k") == "call" and (call_name(n) or "").lower() == "getlasterror" for n in walk(body)):
                flow = _Flow("\0", body)
                for sline, sink in _sinks(flow, body, False):
                    leak(t, label, sline, sink, "Server.GetLastError()")
    return out
