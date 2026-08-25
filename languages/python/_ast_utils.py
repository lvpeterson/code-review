"""Shared `ast`-walking helpers used by the flask/fastapi/django analyzers.

All three deal with the same two questions -- "what decorators does this
def/class have, and what were they called with" -- so that logic lives here
once instead of being reimplemented per framework.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Any

FunctionLike = ast.FunctionDef | ast.AsyncFunctionDef
DecoratedNode = ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef


@dataclass
class DecoratorInfo:
    """A parsed decorator: `@a.b.c(arg1, kw=val)` -> dotted="a.b.c", name="c"."""

    dotted: str
    name: str
    args: list[Any] = field(default_factory=list)
    kwargs: dict[str, Any] = field(default_factory=dict)
    node: ast.AST = None


def dotted_name(node: ast.AST) -> str | None:
    """Resolve a Name/Attribute chain (e.g. `app.route`) to a dotted string."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def literal(node: ast.AST) -> Any:
    """Best-effort literal value of an AST node (string/number/list/dict/...).
    Returns None for anything that isn't a compile-time constant (a variable,
    a function call, an f-string, etc) -- those just get skipped.
    """
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError, SyntaxError):
        return None


def parse_decorators(node: DecoratedNode) -> list[DecoratorInfo]:
    infos: list[DecoratorInfo] = []
    for deco in node.decorator_list:
        call = deco if isinstance(deco, ast.Call) else None
        target = call.func if call else deco
        dotted = dotted_name(target)
        if dotted is None:
            continue
        name = dotted.rsplit(".", 1)[-1]
        args = [literal(a) for a in call.args] if call else []
        kwargs = {kw.arg: literal(kw.value) for kw in call.keywords if kw.arg} if call else {}
        infos.append(DecoratorInfo(dotted=dotted, name=name, args=args, kwargs=kwargs, node=deco))
    return infos


def iter_functions(tree: ast.AST):
    """Yield every (sync or async) function/method def in the tree."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def parse_source(text: str, filename: str) -> ast.AST | None:
    try:
        return ast.parse(text, filename=filename)
    except SyntaxError:
        return None


def mock_import_names(tree: ast.AST) -> set[str]:
    """Local names bound to `unittest.mock` (module or its `patch`), so
    route-decorator matching can tell `@patch(...)` / `@mock.patch(...)`
    test mocks apart from real `@app.patch(...)` routes -- both parse to a
    decorator literally named "patch", and mock.patch is one of the most
    common decorators in any Flask/FastAPI test suite.
    """
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module in ("unittest.mock", "mock"):
                names.update(alias.asname or alias.name for alias in node.names)
            elif node.module == "unittest":
                names.update(alias.asname or alias.name for alias in node.names if alias.name == "mock")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in ("unittest.mock", "mock"):
                    # `import unittest.mock` (no `as`) binds the name
                    # "unittest", not "mock" -- only `as` rebinds the leaf.
                    names.add(alias.asname or alias.name.split(".")[0])
    return names


def source_range(node: DecoratedNode) -> tuple[int, int]:
    """Full (start_line, end_line), 1-indexed inclusive, covering this
    def/class's decorators (if any) through its last line -- what an HTML
    report would want to show as "the code for this handler".
    """
    start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
    end = node.end_lineno if node.end_lineno is not None else node.lineno
    return start, end
