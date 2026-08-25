"""Deep-dive analyzer for Express targets.

Uses tree-sitter to parse a real JS/TS AST instead of regex + manual
paren-balancing -- route calls are matched as actual call_expression /
member_expression nodes, so inline arrow/anonymous-function handlers,
nested calls, and template-literal-free string args are all handled
correctly instead of by counting brackets.

For a *named* handler (`router.get('/x', controller.getOrders)`), the
handler's actual body lives in a different call_expression entirely -- so
this also builds a small project-wide index of every function
declaration/expression it can find (by name) and resolves named handlers
against it, the same way the Django analyzer resolves urls.py entries
against views.py.
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.registry import register

_JS_LANGUAGE = Language(tsjs.language())
_TS_LANGUAGE = Language(tsts.language_typescript())

# Variable names treated as an Express app/router instance. Doesn't (yet)
# trace `const foo = express.Router()` to catch arbitrary variable names --
# extend this set, or resolve it dynamically, if this codebase uses
# something other than the conventional app/router.
_ROUTER_OBJECT_NAMES = {"app", "router"}

_METHOD_TO_HTTP = {
    "get": ["GET"],
    "post": ["POST"],
    "put": ["PUT"],
    "patch": ["PATCH"],
    "delete": ["DELETE"],
    "all": ["GET", "POST", "PUT", "PATCH", "DELETE"],
}

KNOWN_AUTH_INDICATORS = {
    "requireAuth",
    "isAuthenticated",
    "authenticate",
    "authMiddleware",
    "verifyToken",
    "ensureLoggedIn",
}

_INLINE_HANDLER_TYPES = {"arrow_function", "function", "function_expression"}

# supertest's persistent-agent API (`supertest.agent(app)`) is called
# directly as `agent.get('/path')` -- if someone names that agent "app" or
# "router" (both plausible in a test file that also imports the real app
# under that name), it parses identically to a real route registration.
# Only test files pay the cost of this extra check: skip a match when the
# base name isn't a *confirmed* express()/Router() object AND the file
# imports supertest.
_SUPERTEST_IMPORT_MARKERS = (
    "require('supertest')", 'require("supertest")',
    "from 'supertest'", 'from "supertest"',
)


def _parser_for(path: Path) -> Parser:
    return Parser(_TS_LANGUAGE) if path.suffix == ".ts" else Parser(_JS_LANGUAGE)


def _imports_supertest(text: str) -> bool:
    return any(marker in text for marker in _SUPERTEST_IMPORT_MARKERS)


def _node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _string_value(node: Node, src: bytes) -> str | None:
    if node.type != "string":
        return None
    fragment = next((c for c in node.named_children if c.type == "string_fragment"), None)
    return _node_text(fragment, src) if fragment else ""


def _describe_arg(node: Node, src: bytes) -> str:
    if node.type in _INLINE_HANDLER_TYPES:
        return "<inline handler>"
    return _node_text(node, src)


def _iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _extract_route_call(node: Node, src: bytes) -> tuple[str, str, str, list[str]] | None:
    """Return (object_name, verb, path, [middleware/handler arg descriptions])
    if `node` is an `app.<verb>(path, ...)` / `router.<verb>(path, ...)` call.
    """
    if node.type != "call_expression":
        return None

    func = node.child_by_field_name("function")
    if func is None or func.type != "member_expression":
        return None

    obj = func.child_by_field_name("object")
    prop = func.child_by_field_name("property")
    if obj is None or prop is None or obj.type != "identifier":
        return None
    obj_name = _node_text(obj, src)
    if obj_name not in _ROUTER_OBJECT_NAMES:
        return None

    verb = _node_text(prop, src)
    if verb not in _METHOD_TO_HTTP:
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None
    args = args_node.named_children
    if not args or args[0].type != "string":
        return None

    path = _string_value(args[0], src) or ""
    return obj_name, verb, path, [_describe_arg(a, src) for a in args[1:]]


def _is_express_constructor_call(node: Node, src: bytes) -> bool:
    """True for `express()` or `<anything>.Router(...)` -- covers
    `require('express')()` under any import alias.
    """
    if node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    if func is None:
        return False
    text = _node_text(func, src)
    return text == "express" or text.endswith(".Router")


def _locally_declared_names(root: Node, src: bytes) -> dict[str, bool]:
    """Map every name this *one file* declares via `const/let/var name = ...`
    to whether that declaration is an express()/Router() constructor call.

    Deliberately per-file, not project-wide: JS variable binding is scoped
    per file, so if this file shadows "app" with something else (e.g. a
    supertest agent), that's what matters here -- not what "app" happens to
    resolve to in some other file entirely.
    """
    declared: dict[str, bool] = {}
    for node in _iter_nodes(root):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None or name_node.type != "identifier":
            continue
        declared[_node_text(name_node, src)] = _is_express_constructor_call(value_node, src)
    return declared


def _iter_named_function_defs(root: Node, src: bytes):
    """Yield (name, node) for every named function this file defines:
    `function foo() {}`, `const foo = () => {}` / `= function () {}`, and
    `exports.foo = (...) => {}` / `obj.foo = function () {}`.
    """
    for node in _iter_nodes(root):
        if node.type == "function_declaration":
            name_node = node.child_by_field_name("name")
            if name_node:
                yield _node_text(name_node, src), node

        elif node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node and value_node is not None and value_node.type in _INLINE_HANDLER_TYPES:
                yield _node_text(name_node, src), node

        elif node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None or right.type not in _INLINE_HANDLER_TYPES:
                continue
            if left.type == "member_expression":
                prop = left.child_by_field_name("property")
                if prop:
                    yield _node_text(prop, src), node
            elif left.type == "identifier":
                yield _node_text(left, src), node


def _detect_global_use_middleware(target_path: Path) -> tuple[str, int, str] | None:
    """`app.use(authMiddleware)` / `router.use(authMiddleware)` applies to
    every route registered after it (or matching its path prefix, if one is
    given) -- restricted to names matching KNOWN_AUTH_INDICATORS since
    app.use() is also how cors()/helmet()/bodyParser()/morgan() etc get
    registered, and those would otherwise swamp this with noise.
    """
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None or func.type != "member_expression":
                continue
            obj = func.child_by_field_name("object")
            prop = func.child_by_field_name("property")
            if obj is None or prop is None or obj.type != "identifier":
                continue
            if _node_text(obj, src) not in _ROUTER_OBJECT_NAMES or _node_text(prop, src) != "use":
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            for arg in args_node.named_children:
                if arg.type != "identifier":
                    continue
                name = _node_text(arg, src)
                if name in KNOWN_AUTH_INDICATORS:
                    relative_file = str(src_file.relative_to(target_path))
                    line = node.start_point[0] + 1
                    return relative_file, line, f"{_node_text(obj, src)}.use({name})"
    return None


def _build_handler_index(target_path: Path) -> dict[str, tuple[str, int, int]]:
    """Project-wide map of function name -> (file, start_line, end_line),
    used to resolve a named handler passed by reference to its real body.
    """
    index: dict[str, tuple[str, int, int]] = {}
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))
        for name, node in _iter_named_function_defs(tree.root_node, src):
            index[name] = (relative_file, node.start_point[0] + 1, node.end_point[0] + 1)
    return index


@register("javascript", "express")
class ExpressAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        handler_index = _build_handler_index(self.target_path)

        for src_file in iter_files(self.target_path, (".js", ".ts")):
            text = read_text_safe(src_file)
            if not text:
                continue
            src = text.encode("utf-8")
            imports_supertest = _imports_supertest(text)

            tree = _parser_for(src_file).parse(src)
            locally_declared = _locally_declared_names(tree.root_node, src)

            for node in _iter_nodes(tree.root_node):
                extracted = _extract_route_call(node, src)
                if extracted is None:
                    continue
                obj_name, verb, path, rest_args = extracted

                # Only skip when this *same file* shadows the name with
                # something that's provably not an express()/Router() AND
                # the file imports supertest. A name this file doesn't
                # declare at all (imported from elsewhere, the common
                # cross-file app pattern) is still claimed by default.
                declared_as_express = locally_declared.get(obj_name)
                if declared_as_express is False and imports_supertest:
                    continue

                handler_name = rest_args[-1] if rest_args else "?"
                middleware_names = rest_args[:-1]

                source_file = source_start = source_end = None
                if handler_name != "<inline handler>":
                    lookup_key = handler_name.rsplit(".", 1)[-1]
                    resolved = handler_index.get(lookup_key)
                    if resolved:
                        source_file, source_start, source_end = resolved

                route_line = node.start_point[0] + 1
                if handler_name == "<inline handler>":
                    # The call itself already spans the whole inline body.
                    source_file = str(src_file.relative_to(self.target_path))
                    source_start = route_line
                    source_end = node.end_point[0] + 1

                routes.append(
                    Route(
                        path=path,
                        methods=_METHOD_TO_HTTP[verb],
                        handler_name=handler_name,
                        file=str(src_file.relative_to(self.target_path)),
                        line=route_line,
                        auth_decorators=middleware_names,
                        raw_snippet=_node_text(node, src)[:120],
                        source_file=source_file,
                        source_start_line=source_start,
                        source_end_line=source_end,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Express-specific checks -- e.g. cors() with no origin
        # restriction, missing helmet(), body-parser without size limits.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_use_middleware(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
