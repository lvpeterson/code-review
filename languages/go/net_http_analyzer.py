"""Deep-dive analyzer for plain net/http Go targets.

`mux.HandleFunc(path, handler)` doesn't encode an HTTP method in the call at
all -- either the path itself carries one via Go 1.22+'s "METHOD /path"
syntax, or (older style, still extremely common) the handler branches on
`r.Method` internally, the same shape as Next.js Pages Router's
`req.method` sniffing. Handlers are resolved via the same project-wide
function-name index as gin_analyzer.py.
"""
from __future__ import annotations

import re
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
_METHOD_PATH_PREFIX = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$")
_METHOD_CHECK = re.compile(r"\.Method\s*==\s*['\"](\w+)['\"]")

# Function/middleware names that plausibly indicate auth enforcement.
# Extend this to match whatever this codebase's auth middleware is called.
KNOWN_AUTH_INDICATORS = {
    "authMiddleware",
    "AuthMiddleware",
    "requireAuth",
    "AuthRequired",
    "JWTAuth",
}


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


def _extract_handlefunc_call(node, src: bytes) -> tuple[str, str] | None:
    """Return (raw_path, handler_name) for `X.HandleFunc(path, handler)` or
    the package-level `http.HandleFunc(path, handler)`.
    """
    if node.type != "call_expression":
        return None
    func = node.child_by_field_name("function")
    if func is None or func.type != "selector_expression":
        return None
    field = func.child_by_field_name("field")
    if field is None or node_text(field, src) != "HandleFunc":
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None:
        return None
    args = list(args_node.named_children)
    if len(args) < 2:
        return None
    raw_path = string_value(args[0], src)
    if raw_path is None:
        return None
    return raw_path, node_text(args[1], src)


@register("go", "net_http")
class NetHTTPAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        function_index = _build_function_index(self.target_path)

        for go_file in iter_files(self.target_path, (".go",)):
            src = read_text_safe(go_file).encode("utf-8")
            if not src:
                continue
            tree = parser().parse(src)
            relative_file = str(go_file.relative_to(self.target_path))

            for node in iter_nodes(tree.root_node):
                extracted = _extract_handlefunc_call(node, src)
                if extracted is None:
                    continue
                raw_path, handler_name = extracted

                prefix_match = _METHOD_PATH_PREFIX.match(raw_path)
                path = prefix_match.group(2) if prefix_match else raw_path
                methods = [prefix_match.group(1)] if prefix_match else None

                source_file = source_start = source_end = None
                extra_params: list[str] = []
                auth_from_body: list[str] = []
                resolved = function_index.get(handler_name)
                if resolved:
                    source_file, source_start, source_end, body_text = resolved
                    extra_params = extract_request_field_names(body_text)
                    auth_from_body = [n for n in KNOWN_AUTH_INDICATORS if f"{n}(" in body_text]
                    if methods is None:
                        found = {m.upper() for m in _METHOD_CHECK.findall(body_text) if m.upper() in _METHOD_NAMES}
                        methods = sorted(found) if found else None

                if methods is None:
                    # No Go 1.22+ method prefix and no r.Method branching
                    # found -- this handler accepts any method as far as we
                    # can tell, so list the common ones rather than under-report.
                    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]

                routes.append(
                    Route(
                        path=path,
                        methods=methods,
                        handler_name=handler_name,
                        file=relative_file,
                        line=node.start_point[0] + 1,
                        auth_decorators=auth_from_body,
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
        # TODO: net/http-specific checks -- e.g. middleware chains built via
        # manual `http.Handler` wrapping aren't traced back to the route the
        # way gin's inline chain args are.
        return findings
