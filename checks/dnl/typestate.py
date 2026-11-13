"""Small helpers shared by the rules that track objects held in fields, properties and locals
(rules_crypto: ciphers; rules_deser_xml: serializer settings and XML parsers).

They read source-written names first because third-party types (Json.NET, MVC) usually do not
resolve against the reference set the Roslyn helper compiles with.
"""
from __future__ import annotations

import re
from typing import Iterator

from checks.dnl.ir import MethodIR, TypeIR, call_name


def simple(name: str | None) -> str:
    """`System.Security.Cryptography.Aes[]` / `Foo<T>` / `Foo(Of T)` -> `aes`: lowered last segment."""
    s = re.sub(r"<.*$|\(.*$|\[.*$", "", (name or "").strip())
    return s.split(".")[-1].lower()


def tail(expr) -> str:
    """Lowered last name of a name / member chain ("" when the expression is something else)."""
    if isinstance(expr, dict):
        if expr.get("k") == "name":
            return (expr.get("id") or "").lower()
        if expr.get("k") == "member":
            return (expr.get("name") or "").lower()
    return ""


def type_of(type_text: str | None, type_full: str | None = None, init=None) -> str:
    """Lowered simple type name for a declaration: the resolved type, the written type
    (unless `var`), else what the initializer creates (`new T`, `T.Create()`)."""
    if type_full:
        return simple(type_full)
    if type_text and type_text.strip().lower() not in ("var", "object"):
        return simple(type_text)
    if isinstance(init, dict):
        if init.get("k") == "new":
            return simple(init.get("type_full") or init.get("type"))
        if init.get("k") == "call" and (call_name(init) or "").lower() == "create":
            return tail((init.get("fn") or {}).get("obj"))
    return ""


def is_null(expr) -> bool:
    """A literal null / VB Nothing."""
    if not isinstance(expr, dict):
        return False
    if expr.get("k") == "lit":
        return expr.get("v") is None
    return expr.get("k") == "name" and (expr.get("id") or "").lower() in ("null", "nothing")


def iter_bodies(t: TypeIR) -> Iterator[tuple[str, MethodIR | None, list, tuple]]:
    """(label, method or None, statements, scope key) for every body of a type: methods, property
    get/set accessors, property initializers and field initializers. The scope key identifies the body
    inside its type (kind, name, line)."""
    for m in t.methods:
        yield ("constructor" if m.name == ".ctor" else m.name), m, m.body, ("m", m.name, m.line)
    for p in t.properties:
        for acc, tag in ((p.get, "get"), (p.set, "set")):
            if acc:
                yield p.name, None, acc, ("p", p.name, tag, p.line)
        if p.init is not None:
            yield p.name, None, [p.init], ("pi", p.name, p.line)
    for f in t.fields:
        if f.init is not None:
            yield f.name, None, [f.init], ("fi", f.name, f.line)


class RouteIndex:
    """Which route a (file, line) belongs to. A method route covers the method's line range in the
    file that declares it; a route with no method (a WebForms page) covers the whole code-behind
    type, so its methods, accessors and field initializers all carry the page route."""

    def __init__(self, refs=()):
        self._ranges: dict[str, list[tuple[int, int, object]]] = {}
        for r in refs or ():
            if r.type is None:
                continue
            if r.method is not None:
                self._add(r.route.file or r.type.file, r.method.line, r.method.end_line or r.method.line, r.route)
            else:
                end = max([r.type.end_line or 0, r.type.line] + [m.end_line or 0 for m in r.type.methods])
                self._add(r.type.file, r.type.line, end, r.route)

    def _add(self, file: str, lo: int, hi: int, route) -> None:
        self._ranges.setdefault(file, []).append((lo, hi, route))

    def route(self, file: str, line: int):
        for lo, hi, r in self._ranges.get(file, ()):
            if lo <= line <= hi:
                return r
        return None
