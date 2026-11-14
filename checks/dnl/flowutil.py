"""Shared plumbing for the logging, business-flow, resource and API-consumption rules
(rules_logging, rules_flows, rules_resources).

The one idea they share is "does this statement run on every normal request?". A protection
(lockout, throttle, size check, paging) suppresses a finding only when it is certain to apply, so
`uncond_nodes` yields only the expressions that are evaluated whatever the input: the top-level
statements, the conditions of `if`s, the bodies of `try` / `using` / `with`, loop headers, and the
branch of an `if` that is the normal path of a plain validity guard (`ModelState.IsValid`, a null
check). A branch behind any other condition (`if (debug)`, `if (false)`, a flag) is not yielded.

Everything here reads source-written names and is case-insensitive where VB is.
"""
from __future__ import annotations

import re
from typing import Iterator

from checks.dnl import taint_solver
from checks.dnl.findings import dnl_finding
from checks.dnl.ir import MethodIR, TypeIR, call_name, receiver_text
from checks.dnl.rules_object import _env_types
from checks.dnl.typestate import RouteIndex
from core.models import Finding

_TOKEN = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|[0-9]+")
_AND = {"&&", "andalso", "and"}
_STMT_KINDS = {"local", "assign", "expr", "return", "throw", "if", "loop", "try", "using", "with", "other"}


def tokens(name: str) -> list[str]:
    """Lowered camel / snake tokens of an identifier: `btnLogin_Click` -> btn, login, click."""
    return [t.lower() for t in _TOKEN.findall(name or "")]


def is_vb(file: str) -> bool:
    return (file or "").lower().endswith(".vb")


def walk_nl(node) -> Iterator[dict]:
    """Pre-order over the dicts of an expression, not into lambdas (a lambda body is not run in line)."""
    if isinstance(node, dict):
        yield node
        if node.get("k") == "lambda":
            return
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from walk_nl(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_nl(v)


_SHORT = {"&&", "||", "andalso", "orelse", "??"}


def walk_u(node) -> Iterator[dict]:
    """`walk_nl` that also skips what a request may not evaluate: the right operand of a short-circuit
    operator (`&&`, `||`, `??`) and both branches of a ternary (its condition is kept)."""
    if isinstance(node, dict):
        yield node
        k = node.get("k")
        if k == "lambda":
            return
        for key, v in node.items():
            if not isinstance(v, (dict, list)):
                continue
            if (k == "bin" and key == "r" and str(node.get("op") or "").lower() in _SHORT)                     or (k == "cond" and key in ("t", "f")):
                continue
            yield from walk_u(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk_u(v)


def lit_bool(e):
    """True / False for a literal boolean expression (parentheses are already transparent), else None."""
    if isinstance(e, dict):
        if e.get("k") == "lit" and isinstance(e.get("v"), bool):
            return e["v"]
        if e.get("k") == "unary" and e.get("op") in ("!", "Not", "not"):
            v = lit_bool(e.get("e"))
            return None if v is None else not v
    return None


def _is_null(e) -> bool:
    if not isinstance(e, dict):
        return False
    if e.get("k") == "lit":
        return e.get("v") is None
    return e.get("k") == "name" and (e.get("id") or "").lower() in ("null", "nothing")


def _leaf_branch(c) -> str | None:
    """Which branch of `if (leaf)` is the normal path, for the validity guards we accept."""
    if not isinstance(c, dict):
        return None
    k = c.get("k")
    if k == "bin":
        op = str(c.get("op") or "").lower()
        if op in ("!=", "<>", "isnot") and (_is_null(c.get("l")) or _is_null(c.get("r"))):
            return "then"
        if op in ("==", "=", "is") and (_is_null(c.get("l")) or _is_null(c.get("r"))):
            return "else"
        return None
    if k == "member" and (c.get("name") or "").lower() == "isvalid" and "modelstate" in receiver_text(c.get("obj")).lower():
        return "then"
    if k == "call":
        nm = (call_name(c) or "").lower()
        if nm == "isvalid" and "modelstate" in receiver_text((c.get("fn") or {}).get("obj")).lower():
            return "then"
        if nm in ("isnullorempty", "isnullorwhitespace"):
            return "else"
        if nm == "isvalid":
            return None
    return None


def normal_branch(cond) -> str | None:
    """"then" / "else" when `cond` is a plain validity guard whose named branch is the normal path
    (ModelState.IsValid, `x != null`, `!string.IsNullOrEmpty(x)`, `&&` of those); None for any other
    condition, whose branches are therefore conditional."""
    flip = False
    while isinstance(cond, dict) and cond.get("k") == "unary" and cond.get("op") in ("!", "Not", "not"):
        cond, flip = cond.get("e"), not flip
    if isinstance(cond, dict) and cond.get("k") == "bin" and str(cond.get("op") or "").lower() in _AND:
        if flip:
            return None
        parts = [normal_branch(cond.get("l")), normal_branch(cond.get("r"))]
        return "then" if all(p == "then" for p in parts) else None
    b = _leaf_branch(cond)
    if b is None:
        return None
    if flip:
        return "else" if b == "then" else "then"
    return b


def _collect(stmts, out: list) -> bool:
    """Append the statements run on every normal run of `stmts`; True when control never falls out of the
    list. After an `if` whose branch ends the flow (return / throw / Response.End) every later statement is
    conditional on that branch not being taken, so collecting stops -- except when the condition is a plain
    request-validity guard (`ModelState.IsValid`, a null check) and the ending branch is its failing side:
    `if (!ModelState.IsValid) return View(m);` is how every request that gets further is shaped."""
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        out.append(s)
        k = s.get("k")
        if k == "if":
            cond = s.get("cond")
            lit = lit_bool(cond)
            if lit is True:
                if _collect(s.get("then"), out):
                    return True
            elif lit is False:
                if _collect(s.get("else"), out):
                    return True
            else:
                nb = normal_branch(cond)
                if nb == "then" and _collect(s.get("then"), out):
                    return True
                if nb == "else" and _collect(s.get("else"), out):
                    return True
                if nb is None and (terminates(s.get("then")) or terminates(s.get("else"))):
                    return True
        elif k in ("return", "throw"):
            return True
        elif k == "try":
            stopped = _collect(s.get("body"), out)
            _collect(s.get("finally"), out)
            if stopped:
                return True
        elif k in ("using", "with"):
            _collect(s.get("resource"), out)
            if _collect(s.get("body"), out):
                return True
    return False


def uncond_stmts(stmts) -> list:
    """Statements (containers included) evaluated on every normal run of `stmts` (see `_collect`)."""
    out: list = []
    _collect(stmts, out)
    return out


def stmt_nodes(s: dict) -> Iterator[dict]:
    """The expression nodes a statement itself evaluates (an `if` its condition, a loop its header)."""
    k = s.get("k")
    if k == "if":
        yield from walk_u(s.get("cond"))
    elif k in ("expr", "local", "assign", "return", "throw"):
        for key in ("expr", "init", "target", "value"):
            yield from walk_u(s.get(key))
    elif k in ("using", "with"):
        yield from walk_u(s.get("target"))
    elif k == "loop":
        yield from walk_u(s.get("header"))


def uncond_nodes(stmts) -> Iterator[dict]:
    """Every expression node evaluated on every normal run of `stmts` (see module doc)."""
    for s in uncond_stmts(stmts):
        yield from stmt_nodes(s)


def _ends_request(s: dict) -> bool:
    """`Response.End()` / `Response.Redirect(url)` as a statement: the request ends there."""
    e = s.get("expr") if s.get("k") == "expr" else None
    if not isinstance(e, dict) or e.get("k") != "call":
        return False
    nm = (call_name(e) or "").lower()
    recv = receiver_text((e.get("fn") or {}).get("obj")).lower()
    return "response" in recv and (nm in ("end", "transfer") or (nm == "redirect" and len(e.get("args") or []) <= 1))


def terminates(stmts) -> bool:
    """The list always leaves the enclosing flow: a top-level return / throw / continue / break / exit."""
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        k = s.get("k")
        if k in ("return", "throw"):
            return True
        if k == "other" and re.match(r"(?i)\s*(continue|break|exit\s+(sub|function|property|for|do|while))\b",
                                     s.get("text") or ""):
            return True
        if k == "expr" and _ends_request(s):
            return True
        if k in ("using", "with") and terminates(s.get("body")):
            return True
        if k == "if":
            lit = lit_bool(s.get("cond"))
            if (lit is True and terminates(s.get("then"))) or (lit is False and terminates(s.get("else"))) \
                    or (lit is None and s.get("else") and terminates(s.get("then")) and terminates(s.get("else"))):
                return True
    return False


def own_level(stmts) -> Iterator[dict]:
    """Statements of one branch at its own level: try / using / with bodies are inlined, nested
    if / loop bodies are not entered."""
    for s in stmts or []:
        if not isinstance(s, dict):
            continue
        if s.get("k") in ("try",):
            yield from own_level(s.get("body"))
            yield from own_level(s.get("finally"))
        elif s.get("k") in ("using", "with"):
            yield from own_level(s.get("body"))
        else:
            yield s


def stmt_exprs(s: dict) -> Iterator[dict]:
    """Expression nodes of one statement's own expressions (an `if` contributes its condition only)."""
    k = s.get("k")
    if k == "if":
        yield from walk_nl(s.get("cond"))
    elif k in ("expr", "local", "assign", "return", "throw"):
        for key in ("expr", "init", "target", "value"):
            yield from walk_nl(s.get(key))


def child_lists(s: dict) -> Iterator[list]:
    """Statement lists directly nested in a statement (if branches, loop / try / using bodies, catches)."""
    for key in ("then", "else", "body", "finally"):
        v = s.get(key)
        if isinstance(v, list) and v and isinstance(v[0], dict) and v[0].get("k") in _STMT_KINDS:
            yield v
    for c in s.get("catches") or []:
        if isinstance(c, dict) and isinstance(c.get("body"), list):
            yield c["body"]


def all_lists(stmts) -> Iterator[list]:
    """Every statement list in `stmts`, nested ones included (not into lambdas)."""
    if isinstance(stmts, list):
        yield stmts
        for s in stmts:
            if isinstance(s, dict):
                for sub in child_lists(s):
                    yield from all_lists(sub)


class Ctx:
    """Per-scan context: route lookup, finding construction and project-call resolution."""

    def __init__(self, model, refs=()):
        self.model = model
        self.routes = RouteIndex(refs)
        self.refs = list(refs or ())
        self._env: dict = {}

    def finding(self, t: TypeIR, label: str, rule: str, sev: str, title: str, what: str, line: int,
                confidence: str | None = None, file: str | None = None) -> Finding:
        f = file or t.file
        r = self.routes.route(f, line)
        return dnl_finding(rule, sev, title, f"{what} ({f}:{line}) (in {t.name}.{label}).", f, line, route=r,
                           api_surface=bool(r.meta.get("api_surface")) if r else False, confidence=confidence)

    def env(self, t: TypeIR, m: MethodIR) -> dict:
        key = (id(t), id(m))
        if key not in self._env:
            self._env[key] = _env_types(t, m, is_vb(t.file))
        return self._env[key]

    def targets(self, t: TypeIR, m: MethodIR, call: dict) -> list[tuple[TypeIR, MethodIR]]:
        """Project (type, method) candidates of a call inside method `m` of `t`; [] for external calls."""
        try:
            return [(d, x) for d, x in taint_solver.resolve_call(self.model, t, call, self.env(t, m)) if x.body]
        except Exception:
            return []


def attrs_of(model, t: TypeIR, m: MethodIR | None) -> list:
    """Attributes on the action, its controller and every project base controller."""
    out = list(m.attributes) if m is not None else []
    out.extend(t.attributes)
    for b in model.base_chain(t):
        for bt in model.find_types(b):
            out.extend(bt.attributes)
    return out


_LOGIN_STEM = {"login", "logon", "auth", "authenticate", "authentication", "token", "tokens", "signin"}
_CRED_PARAM = {"password", "pwd", "credentials", "credential", "login", "logon", "signin"}


def login_by_context(t: TypeIR, m: MethodIR) -> bool:
    """Actions that log a user in without saying so in their own name: `Post` / `Index` / `Create` /
    `Token` on a controller named Login* / Auth* / Token*, or `Post` taking credentials on Account*;
    and the OWIN `GrantResourceOwnerCredentials` override."""
    low = m.name.lower()
    if low == "grantresourceownercredentials":
        return True
    short = t.name.split(".")[-1]
    stem = set(tokens(short[: -len("Controller")] if short.lower().endswith("controller") else short))
    if stem & _LOGIN_STEM and low in ("post", "index", "create", "token", "put"):
        return True
    if "account" in stem and low == "post":
        return any(set(tokens(p.name)) & _CRED_PARAM or set(tokens(p.type or "")) & _CRED_PARAM for p in m.params)
    return False
