"""Deep-dive analyzer for Gin (gin-gonic) Go targets.

Uses tree-sitter to parse a real Go AST -- route calls are matched as
`selector_expression` call_expressions, the same shape as Express's
`member_expression` pattern (object.METHOD(path, handlers...)). Since Go
handlers are almost always declared as separate top-level functions rather
than passed inline, this also builds a project-wide function-name index
(mirroring Express's handler-resolution index) to locate each handler's
body for auth/query-param scanning and the HTML report's code view.
"""
from __future__ import annotations

from pathlib import Path

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.bodyscan import extract_request_field_names
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route
from core.registry import register
from languages.go._ts_utils import iter_nodes, node_text, parser, string_value

_METHOD_NAMES = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

# Function/middleware names that plausibly indicate auth enforcement.
# Extend this to match whatever this codebase's auth middleware is called.
KNOWN_AUTH_INDICATORS = {
    "authMiddleware",
    "AuthMiddleware",
    "requireAuth",
    "AuthRequired",
    "JWTAuth",
}

_INLINE_HANDLER_TYPES = {"func_literal"}


def _is_gin_constructor(node, src: bytes) -> bool:
    if node.type != "call_expression":
        return False
    func = node.child_by_field_name("function")
    return func is not None and node_text(func, src) in ("gin.Default", "gin.New")


def _build_gin_router_names(target_path: Path) -> set[str]:
    """Variable names confirmed to be assigned `gin.Default()`/`gin.New()`
    -- only route calls on a *confirmed* gin object get claimed, the same
    veto-by-proof pattern used for Flask/FastAPI/Express, since arbitrary
    Go identifiers could otherwise have their own unrelated `.GET`/`.POST`
    methods (a custom HTTP client wrapper, for instance).
    """
    names: set[str] = set()
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        for node in iter_nodes(tree.root_node):
            if node.type != "short_var_declaration":
                continue
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is None or right is None:
                continue
            for name_node, value_node in zip(left.named_children, right.named_children):
                if name_node.type == "identifier" and _is_gin_constructor(value_node, src):
                    names.add(node_text(name_node, src))
    return names


def _build_function_index(target_path: Path) -> dict[str, tuple[str, int, int, str]]:
    """function name -> (file, start_line, end_line, body_text)."""
    index: dict[str, tuple[str, int, int, str]] = {}
    for go_file in iter_files(target_path, (".go",)):
        src = read_text_safe(go_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)
        relative_file = str(go_file.relative_to(target_path))
        for node in iter_nodes(tree.root_node):
            if node.type != "function_declaration":
                continue
            name_node = node.child_by_field_name("name")
            if name_node is None:
                continue
            index[node_text(name_node, src)] = (
                relative_file,
                node.start_point[0] + 1,
                node.end_point[0] + 1,
                node_text(node, src),
            )
    return index


def _describe_arg(node, src: bytes) -> str:
    if node.type in _INLINE_HANDLER_TYPES:
        return "<inline handler>"
    return node_text(node, src)


def _extract_gin_call(node, src: bytes, gin_names: set[str]):
    if node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    if func is None or func.type != "selector_expression":
        return None
    operand = func.child_by_field_name("operand")
    field = func.child_by_field_name("field")
    if operand is None or field is None or operand.type != "identifier":
        return None
    if node_text(operand, src) not in gin_names:
        return None
    verb = node_text(field, src)
    if verb not in _METHOD_NAMES:
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None
    args = list(args_node.named_children)
    if not args:
        return None
    path = string_value(args[0], src)
    if path is None:
        return None
    return verb, path, args[1:]


@register("go", "gin")
class GinAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        gin_names = _build_gin_router_names(self.target_path)
        function_index = _build_function_index(self.target_path)

        for go_file in iter_files(self.target_path, (".go",)):
            src = read_text_safe(go_file).encode("utf-8")
            if not src:
                continue
            tree = parser().parse(src)
            relative_file = str(go_file.relative_to(self.target_path))

            for node in iter_nodes(tree.root_node):
                extracted = _extract_gin_call(node, src, gin_names)
                if extracted is None:
                    continue
                verb, path, rest_args = extracted

                handler_name = _describe_arg(rest_args[-1], src) if rest_args else "?"
                middleware_names = [_describe_arg(a, src) for a in rest_args[:-1]]

                source_file = source_start = source_end = None
                extra_params: list[str] = []
                auth_from_body: list[str] = []
                resolved = function_index.get(handler_name)
                if resolved:
                    source_file, source_start, source_end, body_text = resolved
                    extra_params = extract_request_field_names(body_text)
                    auth_from_body = [n for n in KNOWN_AUTH_INDICATORS if f"{n}(" in body_text]

                routes.append(
                    Route(
                        path=path,
                        methods=[verb],
                        handler_name=handler_name,
                        file=relative_file,
                        line=node.start_point[0] + 1,
                        auth_decorators=middleware_names + auth_from_body,
                        raw_snippet=node_text(node, src)[:120],
                        source_file=source_file,
                        source_start_line=source_start,
                        source_end_line=source_end,
                        extra_param_names=extra_params,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Gin-specific checks -- e.g. router.Use(cors.Default()) with
        # no origin restriction, .Group() prefix composition (not yet
        # resolved -- routes on a sub-router report their bare sub-path).
        return findings
