"""Deep-dive analyzer for Next.js API routes.

Fundamentally different shape from every other analyzer here: Next.js uses
*file-based* routing, not a registration call like `app.get(path, handler)`
-- the route's URL comes from the file's own path in the tree, not from
anything textually inside the file. Two conventions are supported:

  App Router   app/**/route.{js,ts}       -- named exports GET/POST/PUT/...
  Pages Router pages/api/**/*.{js,ts}      -- one default-export handler that
                                               typically branches on
                                               `req.method`

Dynamic segments (`[id]`, `[...slug]`, `[[...slug]]`) become path params;
route groups (`(group)`) are stripped since they don't appear in the URL.
"""
from __future__ import annotations

import re
from pathlib import Path

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.bodyscan import extract_request_field_names
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.paths import join_path_segments
from core.registry import register

_JS_LANGUAGE = Language(tsjs.language())
_TS_LANGUAGE = Language(tsts.language_typescript())

_APP_ROUTE_FILENAMES = {"route.js", "route.ts", "route.jsx", "route.tsx"}
_HTTP_METHOD_NAMES = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_INLINE_HANDLER_TYPES = {"arrow_function", "function", "function_expression"}

# Next.js has no decorators, so "auth" only ever shows up as a function call
# somewhere in the handler body. Extend this to match whatever auth
# library/helper this codebase actually uses.
KNOWN_AUTH_INDICATORS = {
    "getServerSession",
    "getToken",
    "auth",
    "currentUser",
    "requireAuth",
    "verifySession",
}

_CATCH_ALL = re.compile(r"^\[\.{3}(\w+)\]$")
_OPTIONAL_CATCH_ALL = re.compile(r"^\[\[\.{3}(\w+)\]\]$")
_DYNAMIC_PARAM = re.compile(r"^\[(\w+)\]$")
_ROUTE_GROUP = re.compile(r"^\((\w+)\)$")
_METHOD_CHECK = re.compile(r"req\.method\s*===?\s*['\"](\w+)['\"]")

# Textual markers inside middleware.ts's exported `middleware` function that
# plausibly mean it's enforcing auth -- same shallow presence check as
# Flask's before_request detection, see checks/auth.py:apply_global_auth_note.
_GLOBAL_AUTH_BODY_MARKERS = ("redirect", "Unauthorized", "401", *KNOWN_AUTH_INDICATORS)


def _parser_for(path: Path) -> Parser:
    return Parser(_TS_LANGUAGE) if path.suffix in (".ts", ".tsx") else Parser(_JS_LANGUAGE)


def _node_text(node: Node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def _iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _segment_to_url_part(segment: str) -> str | None:
    """One folder/file-stem name -> its URL representation, or None if it's
    a route group (parenthesized -- doesn't appear in the URL at all)."""
    if _ROUTE_GROUP.match(segment):
        return None
    m = _OPTIONAL_CATCH_ALL.match(segment) or _CATCH_ALL.match(segment) or _DYNAMIC_PARAM.match(segment)
    if m:
        return f":{m.group(1)}"
    return segment


def _derive_url_path(segments: list[str]) -> str:
    parts = [p for p in (_segment_to_url_part(s) for s in segments) if p]
    return join_path_segments(*parts)


def _app_router_dir_segments(file_path: Path, target_path: Path) -> list[str] | None:
    parts = file_path.relative_to(target_path).parts[:-1]  # drop route.js itself
    if "app" not in parts:
        return None
    return list(parts[parts.index("app") + 1:])


def _pages_api_segments(file_path: Path, target_path: Path) -> list[str] | None:
    parts = file_path.relative_to(target_path).parts
    for i in range(len(parts) - 1):
        if parts[i] == "pages" and parts[i + 1] == "api":
            *dirs, filename = parts[i + 2:]
            stem = Path(filename).stem
            return list(dirs) if stem == "index" else [*dirs, stem]
    return None


def _app_router_exports(root: Node, src: bytes) -> list[tuple[str, Node]]:
    """Yield (METHOD_NAME, function_node) for each exported HTTP-method
    handler: `export async function GET(...)` or `export const GET = ...`.
    """
    results = []
    for node in _iter_nodes(root):
        if node.type != "export_statement":
            continue
        declaration = node.child_by_field_name("declaration")
        if declaration is None:
            continue

        if declaration.type == "function_declaration":
            name_node = declaration.child_by_field_name("name")
            if name_node and _node_text(name_node, src) in _HTTP_METHOD_NAMES:
                results.append((_node_text(name_node, src), declaration))

        elif declaration.type == "lexical_declaration":
            for child in declaration.children:
                if child.type != "variable_declarator":
                    continue
                name_node = child.child_by_field_name("name")
                value_node = child.child_by_field_name("value")
                if not name_node or value_node is None or value_node.type not in _INLINE_HANDLER_TYPES:
                    continue
                name = _node_text(name_node, src)
                if name in _HTTP_METHOD_NAMES:
                    results.append((name, value_node))
    return results


def _pages_router_default_handler(root: Node, src: bytes) -> Node | None:
    for node in _iter_nodes(root):
        if node.type != "export_statement":
            continue
        if not any(c.type == "default" for c in node.children):
            continue
        declaration = node.child_by_field_name("declaration")
        if declaration is not None and declaration.type in ("function_declaration", *_INLINE_HANDLER_TYPES):
            return declaration
    return None


def _pages_router_methods(body_text: str) -> list[str]:
    found = {m.upper() for m in _METHOD_CHECK.findall(body_text) if m.upper() in _HTTP_METHOD_NAMES}
    # No explicit req.method branching found -- Pages API routes accept any
    # method by default, so list the common ones rather than under-report.
    return sorted(found) if found else ["GET", "POST", "PUT", "PATCH", "DELETE"]


def _auth_calls_in_body(body_text: str) -> list[str]:
    return [name for name in KNOWN_AUTH_INDICATORS if f"{name}(" in body_text]


def _detect_global_middleware_auth(target_path: Path) -> tuple[str, int, str] | None:
    for candidate in ("middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"):
        middleware_path = target_path / candidate
        if not middleware_path.exists():
            continue
        text = read_text_safe(middleware_path)
        src = text.encode("utf-8")
        tree = _parser_for(middleware_path).parse(src)

        for node in _iter_nodes(tree.root_node):
            if node.type != "export_statement":
                continue
            declaration = node.child_by_field_name("declaration")
            if declaration is None:
                continue
            is_middleware_fn = (
                declaration.type == "function_declaration"
                and declaration.child_by_field_name("name") is not None
                and _node_text(declaration.child_by_field_name("name"), src) == "middleware"
            )
            if not is_middleware_fn:
                continue
            body_text = _node_text(declaration, src)
            if any(marker in body_text for marker in _GLOBAL_AUTH_BODY_MARKERS):
                return candidate, node.start_point[0] + 1, "middleware.ts exports a `middleware` function that appears to check auth"
    return None


@register("javascript", "nextjs")
class NextJSAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for src_file in iter_files(self.target_path, (".js", ".ts", ".jsx", ".tsx")):
            if src_file.name in _APP_ROUTE_FILENAMES:
                segments = _app_router_dir_segments(src_file, self.target_path)
                if segments is None:
                    continue
                text = read_text_safe(src_file)
                src = text.encode("utf-8")
                tree = _parser_for(src_file).parse(src)
                path = _derive_url_path(segments)
                relative_file = str(src_file.relative_to(self.target_path))

                for method, func_node in _app_router_exports(tree.root_node, src):
                    body_text = _node_text(func_node, src)
                    routes.append(
                        Route(
                            path=path,
                            methods=[method],
                            handler_name=method,
                            file=relative_file,
                            line=func_node.start_point[0] + 1,
                            auth_decorators=_auth_calls_in_body(body_text),
                            raw_snippet=f"export async function {method}(...) {{ ... }}",
                            source_file=relative_file,
                            source_start_line=func_node.start_point[0] + 1,
                            source_end_line=func_node.end_point[0] + 1,
                            extra_param_names=extract_request_field_names(body_text),
                        )
                    )

            elif src_file.suffix in (".js", ".ts"):
                segments = _pages_api_segments(src_file, self.target_path)
                if segments is None:
                    continue
                text = read_text_safe(src_file)
                src = text.encode("utf-8")
                tree = _parser_for(src_file).parse(src)
                handler = _pages_router_default_handler(tree.root_node, src)
                if handler is None:
                    continue

                path = _derive_url_path(segments)
                relative_file = str(src_file.relative_to(self.target_path))
                body_text = _node_text(handler, src)

                routes.append(
                    Route(
                        path=path,
                        methods=_pages_router_methods(body_text),
                        handler_name="handler",
                        file=relative_file,
                        line=handler.start_point[0] + 1,
                        auth_decorators=_auth_calls_in_body(body_text),
                        raw_snippet="export default function handler(req, res) { ... }",
                        source_file=relative_file,
                        source_start_line=handler.start_point[0] + 1,
                        source_end_line=handler.end_point[0] + 1,
                        extra_param_names=extract_request_field_names(body_text),
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Next.js-specific checks -- e.g. missing `export const runtime`
        # segment config review, CORS headers set via next.config.js
        # `headers()` with a wildcard origin.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_middleware_auth(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
