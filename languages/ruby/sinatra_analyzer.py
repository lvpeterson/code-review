"""Deep-dive analyzer for Sinatra targets.

`get '/path' do ... end` (and post/put/patch/delete) parse to a `call` node
with a `do_block` -- there's no separate handler function to resolve the
way Express/Go need, since the block itself *is* the handler body.
"""
from __future__ import annotations

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route
from core.registry import register
from languages.ruby._ts_utils import iter_nodes, node_text, parser, string_or_symbol_value

_ROUTE_METHODS = {"get": "GET", "post": "POST", "put": "PUT", "patch": "PATCH", "delete": "DELETE"}

# Helper/method names that plausibly indicate auth enforcement. Extend this
# to match whatever this codebase's auth helper is actually called.
KNOWN_AUTH_INDICATORS = {
    "authenticate!",
    "require_login",
    "authorize!",
    "protected!",
}


def _extract_sinatra_call(node, src: bytes):
    if node.type != "call":
        return None
    method_node = node.child_by_field_name("method")
    if method_node is None or method_node.type != "identifier":
        return None
    verb = _ROUTE_METHODS.get(node_text(method_node, src))
    if verb is None:
        return None

    args_node = node.child_by_field_name("arguments")
    if args_node is None or not args_node.named_children:
        return None
    path = string_or_symbol_value(args_node.named_children[0], src)
    if path is None:
        return None

    return verb, path, node.child_by_field_name("block")


def _auth_calls_in_block(block, src: bytes) -> list[str]:
    if block is None:
        return []
    body_text = node_text(block, src)
    return [name for name in KNOWN_AUTH_INDICATORS if name in body_text]


@register("ruby", "sinatra")
class SinatraAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for rb_file in iter_files(self.target_path, (".rb",)):
            src = read_text_safe(rb_file).encode("utf-8")
            if not src:
                continue
            tree = parser().parse(src)
            relative_file = str(rb_file.relative_to(self.target_path))

            for node in iter_nodes(tree.root_node):
                extracted = _extract_sinatra_call(node, src)
                if extracted is None:
                    continue
                verb, path, block = extracted

                source_start = source_end = None
                if block is not None:
                    source_start = node.start_point[0] + 1
                    source_end = block.end_point[0] + 1

                routes.append(
                    Route(
                        path=path,
                        methods=[verb],
                        handler_name=f"{verb.lower()} '{path}'",
                        file=relative_file,
                        line=node.start_point[0] + 1,
                        auth_decorators=_auth_calls_in_block(block, src),
                        raw_snippet=node_text(node, src)[:120],
                        source_file=relative_file,
                        source_start_line=source_start,
                        source_end_line=source_end,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        return findings
