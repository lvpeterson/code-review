"""Python mirror of the roslyn-ir schema 1 plus small helpers for walking it.

Types, methods and members are dataclasses; statements and expressions stay
plain dicts (`{"k": kind, "line": n, ...}`) because they are deeply nested and
rules only ever pattern-match on a few keys.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class Attr:
    name: str
    args: list = field(default_factory=list)
    named: dict = field(default_factory=dict)
    line: int = 0


@dataclass
class ParamIR:
    name: str
    type: str | None = None
    attributes: list[Attr] = field(default_factory=list)


@dataclass
class FieldIR:
    name: str
    type: str | None = None
    line: int = 0
    init: dict | None = None
    is_const: bool = False


@dataclass
class PropertyIR:
    name: str
    type: str | None = None
    attributes: list[Attr] = field(default_factory=list)
    line: int = 0


@dataclass
class MethodIR:
    name: str
    modifiers: list[str] = field(default_factory=list)
    return_type: str | None = None
    params: list[ParamIR] = field(default_factory=list)
    attributes: list[Attr] = field(default_factory=list)
    handles: list = field(default_factory=list)
    body: list = field(default_factory=list)
    line: int = 0
    end_line: int = 0


@dataclass
class TypeIR:
    name: str
    namespace: str
    kind: str
    modifiers: list[str]
    bases: list[str]
    attributes: list[Attr]
    fields: list[FieldIR]
    properties: list[PropertyIR]
    methods: list[MethodIR]
    line: int
    end_line: int
    file: str = ""

    @property
    def full_name(self) -> str:
        return f"{self.namespace}.{self.name}" if self.namespace else self.name


@dataclass
class FileIR:
    path: str
    language: str
    project: str
    parse_errors: int
    types: list[TypeIR]


# -- loading --------------------------------------------------------------

def _attr(d: dict) -> Attr:
    return Attr(d.get("name", ""), d.get("args") or [], d.get("named") or {}, d.get("line", 0))


def _attrs(lst) -> list[Attr]:
    return [_attr(a) for a in lst or []]


def _method(d: dict) -> MethodIR:
    return MethodIR(
        name=d.get("name", ""), modifiers=d.get("modifiers") or [], return_type=d.get("return_type"),
        params=[ParamIR(p.get("name", ""), p.get("type"), _attrs(p.get("attributes"))) for p in d.get("params") or []],
        attributes=_attrs(d.get("attributes")), handles=d.get("handles") or [],
        body=d.get("body") or [], line=d.get("line", 0), end_line=d.get("end_line", 0),
    )


def _type(d: dict, path: str) -> TypeIR:
    return TypeIR(
        name=d.get("name", ""), namespace=d.get("namespace") or "", kind=d.get("kind", "class"),
        modifiers=d.get("modifiers") or [], bases=d.get("bases") or [], attributes=_attrs(d.get("attributes")),
        fields=[FieldIR(f.get("name", ""), f.get("type"), f.get("line", 0), f.get("init"), bool(f.get("is_const")))
                for f in d.get("fields") or []],
        properties=[PropertyIR(p.get("name", ""), p.get("type"), _attrs(p.get("attributes")), p.get("line", 0))
                    for p in d.get("properties") or []],
        methods=[_method(m) for m in d.get("methods") or []],
        line=d.get("line", 0), end_line=d.get("end_line", 0), file=path,
    )


def load_file_ir(obj: dict) -> FileIR | None:
    """Decode one helper JSON line; None for per-file error records."""
    if "error" in obj or "types" not in obj:
        return None
    path = obj.get("path", "")
    return FileIR(path, obj.get("language", ""), obj.get("project", ""), obj.get("parse_errors", 0),
                  [_type(t, path) for t in obj["types"]])


# -- expression helpers ---------------------------------------------------

def walk(node: Any) -> Iterator[dict]:
    """Pre-order over every dict nested in node (dicts and lists), node first."""
    if isinstance(node, dict):
        yield node
        for v in node.values():
            if isinstance(v, (dict, list)):
                yield from walk(v)
    elif isinstance(node, list):
        for v in node:
            yield from walk(v)


def call_name(expr: Any) -> str | None:
    """Method name of a call expr: `x.Filters.Add(..)` -> "Add", `MapRoute(..)` -> "MapRoute"."""
    if not isinstance(expr, dict) or expr.get("k") != "call":
        return None
    fn = expr.get("fn")
    if not isinstance(fn, dict):
        return None
    if fn.get("k") == "member":
        return fn.get("name")
    if fn.get("k") == "name":
        return fn.get("id")
    return None


def receiver_text(expr: Any) -> str:
    """Dotted text of a name/member chain; "" when the chain has other nodes."""
    if not isinstance(expr, dict):
        return ""
    k = expr.get("k")
    if k == "name":
        return expr.get("id") or ""
    if k == "member":
        left = receiver_text(expr.get("obj"))
        name = expr.get("name") or ""
        return f"{left}.{name}" if left else name
    return ""


def literal_str(expr: Any) -> str | None:
    """The value of a string literal expr, else None."""
    if isinstance(expr, dict) and expr.get("k") == "lit" and isinstance(expr.get("v"), str):
        return expr["v"]
    return None


def const_str(expr: Any) -> str | None:
    """A compile-time string: a literal, `nameof(X.Y)` ("Y"), or a `+` / VB `&`
    concatenation of those. None for anything else."""
    s = literal_str(expr)
    if s is not None or not isinstance(expr, dict):
        return s
    k = expr.get("k")
    if k == "call" and (call_name(expr) or "").lower() == "nameof" and len(expr.get("args") or []) == 1:
        text = receiver_text(expr["args"][0])
        return text.split(".")[-1] or None
    if k == "bin" and expr.get("op") in ("+", "&", "concat"):
        left, right = const_str(expr.get("l")), const_str(expr.get("r"))
        return left + right if left is not None and right is not None else None
    return None


def attr_simple(name: str) -> str:
    """`System.Web.Mvc.AuthorizeAttribute` -> `Authorize`: qualifier, generic
    args and the `Attribute` suffix dropped, case kept. The helper already
    strips these, but only case-sensitively (VB `<Fooattribute>` keeps it)."""
    simple = name.split("<")[0].split("(")[0].strip().split(".")[-1]
    if len(simple) > len("attribute") and simple.lower().endswith("attribute"):
        simple = simple[: -len("attribute")]
    return simple


def attr_key(name: str) -> str:
    """Comparison key for attribute / filter type names (attr_simple, lowered)."""
    return attr_simple(name).lower()


def has_attr(attrs: list[Attr], *names: str) -> Attr | None:
    """First attribute whose name matches any of names, ignoring case,
    namespace qualifier and `Attribute` suffix."""
    wanted = {attr_key(n) for n in names}
    return next((a for a in attrs if attr_key(a.name) in wanted), None)
