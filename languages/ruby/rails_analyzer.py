"""Deep-dive analyzer for Ruby on Rails targets.

Routes live in config/routes.rb as a DSL (`get`/`resources`/`namespace`),
not a registration call per-route the way every other analyzer here works
with -- `resources :orders` alone expands to 7 RESTful routes, and
`namespace`/`scope` blocks add a path prefix to everything nested inside
them (walked recursively, tracking an accumulated prefix stack).

v1 scope: routes.rb extraction (named routes + `resources` expansion +
namespace/scope prefixes) and a project-wide `before_action` auth check on
ApplicationController. Deliberately does NOT resolve each route's
controller#action to its actual source file/line yet (unlike Django's
urls.py -> views.py resolution) -- every route here reports the routes.rb
registration line only.
"""
from __future__ import annotations

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.paths import join_path_segments
from core.registry import register
from languages.ruby._ts_utils import iter_nodes, node_text, parser, string_or_symbol_value

_NAMED_ROUTE_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE"}

# The 7 standard RESTful actions `resources :name` expands to: (http
# method, path suffix, action name).
_RESOURCEFUL_ACTIONS = [
    ("GET", "", "index"),
    ("GET", "new", "new"),
    ("POST", "", "create"),
    ("GET", ":id", "show"),
    ("GET", ":id/edit", "edit"),
    ("PATCH", ":id", "update"),
    ("DELETE", ":id", "destroy"),
]

KNOWN_AUTH_INDICATORS = {
    "authenticate_user!",
    "authenticate!",
    "require_login",
    "login_required",
}


def _extract_to_target(args_node, src: bytes) -> str | None:
    for child in args_node.named_children:
        if child.type != "pair":
            continue
        key_node = child.child_by_field_name("key")
        value_node = child.child_by_field_name("value")
        if key_node is None or value_node is None or node_text(key_node, src) != "to":
            continue
        return string_or_symbol_value(value_node, src) or node_text(value_node, src).strip("'\"")
    return None


def _iter_route_calls(block_body, src: bytes, prefix_parts: list[str], routes_out: list[tuple]) -> None:
    if block_body is None:
        return
    for node in block_body.named_children:
        if node.type != "call":
            continue
        method_node = node.child_by_field_name("method")
        if method_node is None:
            continue
        method_name = node_text(method_node, src)
        args_node = node.child_by_field_name("arguments")

        if method_name in _NAMED_ROUTE_METHODS:
            if args_node is None or not args_node.named_children:
                continue
            sub_path = string_or_symbol_value(args_node.named_children[0], src)
            if sub_path is None:
                continue
            handler_name = _extract_to_target(args_node, src) or method_name
            full_path = join_path_segments(*prefix_parts, sub_path)
            routes_out.append((full_path, [_NAMED_ROUTE_METHODS[method_name]], handler_name, node.start_point[0] + 1))

        elif method_name == "resources":
            if args_node is None or not args_node.named_children:
                continue
            resource_name = string_or_symbol_value(args_node.named_children[0], src)
            if resource_name is None:
                continue
            for http_method, action_path, action_name in _RESOURCEFUL_ACTIONS:
                full_path = join_path_segments(*prefix_parts, resource_name, action_path)
                routes_out.append(
                    (full_path, [http_method], f"{resource_name}#{action_name}", node.start_point[0] + 1)
                )

        elif method_name in ("namespace", "scope"):
            new_prefix_parts = prefix_parts
            if args_node is not None and args_node.named_children:
                prefix_value = string_or_symbol_value(args_node.named_children[0], src)
                if prefix_value:
                    new_prefix_parts = [*prefix_parts, prefix_value]
            block_node = node.child_by_field_name("block")
            if block_node is not None:
                _iter_route_calls(block_node.child_by_field_name("body"), src, new_prefix_parts, routes_out)


def _find_routes_draw_block_body(tree_root, src: bytes):
    for node in iter_nodes(tree_root):
        if node.type != "call":
            continue
        method_node = node.child_by_field_name("method")
        if method_node is None or node_text(method_node, src) != "draw":
            continue
        block_node = node.child_by_field_name("block")
        if block_node is None:
            continue
        return block_node.child_by_field_name("body")
    return None


def _detect_global_before_action_auth(target_path) -> tuple[str, int, str] | None:
    """`before_action :authenticate_user!` on ApplicationController applies
    to every controller that inherits from it -- effectively every action
    in the app -- unless overridden with `skip_before_action` elsewhere.
    """
    for rb_file in iter_files(target_path, (".rb",)):
        if rb_file.name != "application_controller.rb":
            continue
        src = read_text_safe(rb_file).encode("utf-8")
        if not src:
            continue
        tree = parser().parse(src)

        for node in iter_nodes(tree.root_node):
            if node.type != "call":
                continue
            method_node = node.child_by_field_name("method")
            if method_node is None or node_text(method_node, src) != "before_action":
                continue
            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            arg_text = node_text(args_node, src)
            if any(marker in arg_text for marker in KNOWN_AUTH_INDICATORS):
                relative_file = str(rb_file.relative_to(target_path))
                return relative_file, node.start_point[0] + 1, f"ApplicationController before_action {arg_text.strip()}"
    return None


@register("ruby", "rails")
class RailsAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for rb_file in iter_files(self.target_path, (".rb",)):
            if rb_file.name != "routes.rb":
                continue
            src = read_text_safe(rb_file).encode("utf-8")
            if not src:
                continue
            tree = parser().parse(src)
            relative_file = str(rb_file.relative_to(self.target_path))

            body = _find_routes_draw_block_body(tree.root_node, src)
            if body is None:
                continue

            raw_routes: list[tuple] = []
            _iter_route_calls(body, src, [], raw_routes)
            for path, methods, handler_name, line in raw_routes:
                routes.append(
                    Route(
                        path=path,
                        methods=methods,
                        handler_name=handler_name,
                        file=relative_file,
                        line=line,
                        raw_snippet=f"{methods[0]} {path} -> {handler_name}",
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: resolve each route's controller#action to its actual source
        # file/line, mirroring Django's urls.py -> views.py resolution --
        # v1 only reports the routes.rb registration line.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_before_action_auth(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
