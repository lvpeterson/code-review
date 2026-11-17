"""Option reader for ASP.NET Core configuration rules.

Turns option lambdas (`o => { o.Password.RequiredLength = 4; }`) and object initializers
(`new TokenValidationParameters { ValidateIssuer = false, Nested = { A = 1 } }`) found in a
`PipeCall.node` into flat (dotted path, value, line) assignments, and evaluates the few kinds of
value the rules care about (literals, enum members, TimeSpans, `_ => true` callbacks).

Anything that is not a compile-time value reads as UNKNOWN, never as a default: a rule treats
UNKNOWN as REVIEW, so an option set from configuration or a flag is not silently clean.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .ir import call_name, receiver_text, walk


class _Unknown:
    def __repr__(self) -> str:
        return "UNKNOWN"

    def __bool__(self) -> bool:
        return False


# Sentinel: not a compile-time value.
UNKNOWN = _Unknown()


@dataclass
class Opt:
    path: str        # dotted, relative to the lambda parameter or initializer root: "Password.RequiredLength"
    value: dict      # the assigned Expr
    line: int
    # True when the assignment sits under an if / else (switch lowers to if), a loop, a ternary or a
    # catch handler inside the lambda: it may not run, so it can neither clear nor prove a value.
    conditional: bool = False


def lambda_args(call: dict) -> list[dict]:
    """Lambda expressions among a call's arguments, positional and named."""
    args = list(call.get("args") or []) + list((call.get("named") or {}).values())
    return [a for a in args if isinstance(a, dict) and a.get("k") == "lambda"]


# -- assignments ------------------------------------------------------------

def _chain(target) -> list[str] | None:
    """[root, A, B] for `root.A.B`; None for anything else (index, call, ...)."""
    names: list[str] = []
    n = target
    while isinstance(n, dict) and n.get("k") == "member":
        names.append(n.get("name") or "")
        n = n.get("obj")
    if isinstance(n, dict) and n.get("k") == "name" and n.get("id") and all(names):
        return [n["id"]] + names[::-1]
    return None


def _split_top(text: str) -> list[str]:
    """Split on commas outside brackets and string literals."""
    parts, depth, cur, quote = [], 0, [], None
    for i, ch in enumerate(text):
        if quote:
            cur.append(ch)
            if ch == quote and text[i - 1] != "\\":
                quote = None
            continue
        if ch in "\"'":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur))
    return parts


_NUM = re.compile(r"^-?\d+(\.\d+)?$")


def _text_expr(text: str, line: int) -> dict:
    """A value written inside an unlowered initializer block: literals are recovered, the rest is unknown."""
    t = text.strip()
    if t in ("true", "false"):
        return {"k": "lit", "v": t == "true", "t": "bool", "line": line}
    if t == "null":
        return {"k": "lit", "v": None, "t": "null", "line": line}
    if _NUM.match(t):
        return {"k": "lit", "v": float(t) if "." in t else int(t), "t": "number", "line": line}
    if len(t) >= 2 and t[0] == t[-1] == '"' and '"' not in t[1:-1]:
        return {"k": "lit", "v": t[1:-1], "t": "string", "line": line}
    return {"k": "unknown", "text": t, "line": line}


def _block_entries(text: str, prefix: str, line: int, out: list[Opt]) -> bool:
    """Parse `{ A = 1, B = { C = true } }` (the helper lowers a nested object initializer as unknown text)
    into assignments. False when the text is not such a block."""
    t = text.strip()
    if not (t.startswith("{") and t.endswith("}")):
        return False
    for part in _split_top(t[1:-1]):
        m = re.match(r"^\s*([A-Za-z_]\w*)\s*=\s*(.*)$", part, re.S)
        if not m:
            continue  # a collection element or indexer: not an option assignment
        path = f"{prefix}.{m.group(1)}" if prefix else m.group(1)
        if not _block_entries(m.group(2), path, line, out):
            out.append(Opt(path, _text_expr(m.group(2), line), line))
    return True


# Statement / expression kinds whose children may not run (`try` is special: only its catches).
_BRANCH_KINDS = frozenset({"if", "loop", "cond"})


def child_conditional(node: dict, key: str, cond: bool) -> bool:
    """Whether the child under `key` of an IR node is conditional, given the node's own state."""
    k = node.get("k")
    return cond or k in _BRANCH_KINDS or (k == "try" and key == "catches")


def walk_conditional(node, cond: bool = False):
    """Pre-order like ir.walk, yielding (node, conditional): conditional is True below an if / else,
    loop, ternary or catch handler. A lambda keeps the state of where it is written."""
    if isinstance(node, dict):
        yield node, cond
        for key, v in node.items():
            if isinstance(v, (dict, list)):
                yield from walk_conditional(v, child_conditional(node, key, cond))
    elif isinstance(node, list):
        for v in node:
            yield from walk_conditional(v, cond)


def _scan(node, params: frozenset, prefix: str, out: list[Opt], cond: bool = False) -> None:
    if isinstance(node, list):
        for x in node:
            _scan(x, params, "", out, cond)
        return
    if not isinstance(node, dict):
        return
    k = node.get("k")
    if k == "lambda":
        _scan(node.get("body"), params | {p for p in node.get("params") or [] if isinstance(p, str)}, "", out, cond)
        return
    if k == "assign" and node.get("op") == "=":
        chain = _chain(node.get("target"))
        if chain and chain[0] in params and len(chain) > 1:
            path = ".".join(chain[1:])
            out.append(Opt(path, node.get("value"), node.get("line") or 0, cond))
            _scan(node.get("value"), params, path, out, cond)
        else:
            _scan(node.get("value"), params, "", out, cond)
        return
    if k == "new":
        line = node.get("line") or 0
        for a in node.get("args") or []:
            _scan(a, params, "", out, cond)
        for e in node.get("init") or []:
            if not (isinstance(e, dict) and "name" in e and "value" in e):
                _scan(e, params, "", out, cond)  # a collection element
                continue
            path = f"{prefix}.{e['name']}" if prefix else e["name"]
            v = e["value"]
            vline = (v.get("line") if isinstance(v, dict) else None) or line
            if isinstance(v, dict) and v.get("k") == "unknown" and _block_entries(v.get("text") or "", path, vline, out):
                if cond:
                    for o in out:
                        o.conditional = o.conditional or (o.path.startswith(path + ".") and o.line == vline)
                continue
            # An untyped `new` with named entries is a nested object initializer (`Nested = { A = 1 }`).
            nested = (isinstance(v, dict) and v.get("k") == "new" and not v.get("type")
                      and any(isinstance(x, dict) and "name" in x for x in v.get("init") or []))
            if not nested:
                out.append(Opt(path, v, vline, cond))
            _scan(v, params, path, out, cond)
        return
    for key, v in node.items():
        if isinstance(v, (dict, list)):
            _scan(v, params, "", out, child_conditional(node, key, cond))


def assignments(node: dict) -> list[Opt]:
    """Every `p.A.B = v` in a lambda body (any depth: nested lambdas, if / else) where `p` is a lambda
    parameter, plus the entries of every `new T { A = v, B = { C = v } }` initializer, in source order.
    Initializer paths are prefixed by the member they sit under (`Params = new T { X = 1 }` gives
    `Params` and `Params.X`)."""
    out: list[Opt] = []
    _scan(node, frozenset(), "", out)
    return out


def options_of(call: dict) -> list[Opt]:
    """Assignments over every lambda argument and every `new` argument of a call."""
    out: list[Opt] = []
    for a in list(call.get("args") or []) + list((call.get("named") or {}).values()):
        if isinstance(a, dict) and a.get("k") in ("lambda", "new"):
            out += assignments(a)
    return out


def opt(opts: list[Opt], path: str) -> Opt | None:
    """The last assignment whose path equals `path`, ignoring case (later assignments win). It ignores
    `Opt.conditional`, so a conditional good value can mask an earlier bad one: a rule about a
    security-relevant path must use `verdict` instead (opt is fine for "is this option set at all")."""
    want = path.lower()
    return next((o for o in reversed(opts) if o.path.lower() == want), None)


def verdict(opts: list[Opt], path: str, bad=None) -> tuple[Opt | None, bool]:
    """(effective assignment, uncertain) for `path`. `uncertain` is True when any assignment to the path
    is conditional: the caller must then downgrade a finding to REVIEW. The effective assignment is the
    last one; when `bad` (a predicate over an Opt) is given and the path is uncertain, it is the last
    assignment that satisfies `bad`, so a conditional good value never clears a bad one."""
    want = path.lower()
    same = [o for o in opts if o.path.lower() == want]
    if not same:
        return None, False
    uncertain = any(o.conditional for o in same)
    if uncertain and bad is not None:
        bads = [o for o in same if bad(o)]
        if bads:
            return bads[-1], True
    return same[-1], uncertain


# -- values -----------------------------------------------------------------

def const(expr: dict | None):
    """A compile-time value: bool | int | float | str | None (literal null). Enum members give
    "Type.Member" text (`CookieSecurePolicy.None`). Anything else is UNKNOWN."""
    if not isinstance(expr, dict):
        return UNKNOWN
    k = expr.get("k")
    if k == "lit":
        return expr.get("v")
    if k == "member" and expr.get("name"):
        text = receiver_text(expr)
        # Only a member of a plain name chain: `a.b().C` has no text and stays unknown.
        # and only when it starts like a type name (PascalCase, or a PascalCase namespace): a variable,
        # field or `this` member (`settings.Policy`, `_p.Value`) is a runtime value, not an enum member.
        if text and "." in text and text[0].isupper():
            return ".".join(text.split(".")[-2:])
    return UNKNOWN


def always_true(expr: dict | None) -> bool:
    """A callback that accepts everything: `_ => true`, `(a, b) => true`, `x => { return true; }`."""
    if not (isinstance(expr, dict) and expr.get("k") == "lambda"):
        return False
    body = expr.get("body")
    if isinstance(body, dict):
        return body.get("k") == "lit" and body.get("v") is True
    rets = [n for n in walk(body) if n.get("k") == "return"]
    return bool(rets) and all(
        isinstance(r.get("value"), dict) and r["value"].get("k") == "lit" and r["value"].get("v") is True
        for r in rets)


_SPAN_FACTORY = {"fromminutes": 1.0, "fromhours": 60.0, "fromdays": 1440.0, "fromseconds": 1 / 60,
                 "frommilliseconds": 1 / 60000}


def _num(e) -> float | None:
    v = const(e)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def _minutes(x: float) -> float | int:
    return int(x) if x == int(x) else x


def timespan_minutes(expr: dict | None) -> float | None:
    """Length in minutes of `TimeSpan.FromMinutes/Hours/Days/Seconds(literal)` or `new TimeSpan(...)` with
    literal arguments; None for anything else."""
    if not isinstance(expr, dict):
        return None
    if expr.get("k") == "call":
        factor = _SPAN_FACTORY.get((call_name(expr) or "").lower())
        fn = expr.get("fn") or {}
        args = expr.get("args") or []
        if (factor is None or fn.get("k") != "member" or len(args) != 1
                or receiver_text(fn.get("obj")).split(".")[-1] != "TimeSpan"):
            return None
        n = _num(args[0])
        return None if n is None else _minutes(n * factor)
    if expr.get("k") == "new" and (expr.get("type") or "").split(".")[-1] == "TimeSpan":
        nums = [_num(a) for a in expr.get("args") or []]
        if not nums or None in nums:
            return None
        if len(nums) == 1:    # ticks
            return _minutes(nums[0] / 600_000_000)
        if len(nums) == 2:    # hours, minutes
            return _minutes(nums[0] * 60 + nums[1])
        if len(nums) == 3:    # hours, minutes, seconds
            return _minutes(nums[0] * 60 + nums[1] + nums[2] / 60)
        if len(nums) == 4:    # days, hours, minutes, seconds
            return _minutes(nums[0] * 1440 + nums[1] * 60 + nums[2] + nums[3] / 60)
    return None
