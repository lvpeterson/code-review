"""Deep-dive analyzer for Express targets.

Uses tree-sitter to parse a real JS/TS AST instead of regex + manual
paren-balancing -- route calls are matched as actual call_expression /
member_expression nodes, so inline arrow/anonymous-function handlers,
nested calls, and template-literal-free string args are all handled
correctly instead of by counting brackets.
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
from core.models import Finding, Route
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


def _parser_for(path: Path) -> Parser:
    return Parser(_TS_LANGUAGE) if path.suffix == ".ts" else Parser(_JS_LANGUAGE)


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


def _extract_route_call(node: Node, src: bytes) -> tuple[str, str, list[str]] | None:
    """Return (verb, path, [middleware/handler arg descriptions]) if `node`
    is an `app.<verb>(path, ...)` / `router.<verb>(path, ...)` call.
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
    if _node_text(obj, src) not in _ROUTER_OBJECT_NAMES:
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
    return verb, path, [_describe_arg(a, src) for a in args[1:]]


@register("javascript", "express")
class ExpressAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for src_file in iter_files(self.target_path, (".js", ".ts")):
            src = read_text_safe(src_file).encode("utf-8")
            if not src:
                continue

            tree = _parser_for(src_file).parse(src)

            for node in _iter_nodes(tree.root_node):
                extracted = _extract_route_call(node, src)
                if extracted is None:
                    continue
                verb, path, rest_args = extracted

                handler_name = rest_args[-1] if rest_args else "?"
                middleware_names = rest_args[:-1]

                routes.append(
                    Route(
                        path=path,
                        methods=_METHOD_TO_HTTP[verb],
                        handler_name=handler_name,
                        file=str(src_file.relative_to(self.target_path)),
                        line=node.start_point[0] + 1,
                        auth_decorators=middleware_names,
                        raw_snippet=_node_text(node, src)[:120],
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
