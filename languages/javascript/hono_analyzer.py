"""Deep-dive analyzer for Hono targets (including the @hono/node-server
Node adapter -- Hono's own routing/middleware API is identical regardless
of which runtime adapter serves it, so nothing here is Node-specific).

Same tree-sitter approach as express_analyzer.py, with the differences
Hono's API actually has:

  - A router object comes from `new Hono()` (a constructor call), not
    Express's `express()`/`.Router()` factory calls.
  - Sub-apps mount via `app.route('/prefix', subApp)`, a dedicated method
    distinct from `.use()` (which is middleware-only in Hono, never a
    router mount) -- Express conflates both into `.use()`.
  - Hono's own official auth middleware (`hono/jwt`, `hono/basic-auth`,
    `hono/bearer-auth`) is used as a *call* -- `app.use('/api/*',
    jwt({ secret }))` -- not a bare reference like Express's
    `app.use(authMiddleware)`. Argument description below special-cases a
    call_expression to capture just the callee name, so both the
    global-middleware detector and each route's own auth_decorators list
    actually match `KNOWN_AUTH_INDICATORS`.
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Node, Parser

from checks import auth as auth_checks
from checks import config as config_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.bodyscan import extract_request_field_names
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.paths import join_path_segments, resolve_mount_prefix
from core.registry import register
from languages.javascript.dangerous_sinks import detect_dangerous_sinks

_JS_LANGUAGE = Language(tsjs.language())
_TS_LANGUAGE = Language(tsts.language_typescript())

_METHOD_TO_HTTP = {
    "get": ["GET"],
    "post": ["POST"],
    "put": ["PUT"],
    "patch": ["PATCH"],
    "delete": ["DELETE"],
    "all": ["GET", "POST", "PUT", "PATCH", "DELETE"],
}

# Hono's own official auth middleware (called, not referenced bare -- see
# module docstring) plus the same generic custom-name conventions
# express_analyzer.py uses.
KNOWN_AUTH_INDICATORS = {
    "jwt",
    "bearerAuth",
    "basicAuth",
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
    if node.type == "call_expression":
        # `jwt({ secret })` -> "jwt" -- the callee name is what actually
        # needs to match KNOWN_AUTH_INDICATORS, not the whole call text.
        func = node.child_by_field_name("function")
        if func is not None:
            return _node_text(func, src)
    return _node_text(node, src)


def _iter_nodes(node: Node):
    yield node
    for child in node.children:
        yield from _iter_nodes(child)


def _is_hono_constructor_call(node: Node, src: bytes) -> bool:
    """True for `new Hono(...)` under any import alias/namespace
    (`new hono.Hono(...)`)."""
    if node.type != "new_expression":
        return False
    constructor = node.child_by_field_name("constructor")
    if constructor is None:
        return False
    text = _node_text(constructor, src)
    return text == "Hono" or text.endswith(".Hono")


def _locally_declared_names(root: Node, src: bytes) -> dict[str, bool]:
    declared: dict[str, bool] = {}
    for node in _iter_nodes(root):
        if node.type != "variable_declarator":
            continue
        name_node = node.child_by_field_name("name")
        value_node = node.child_by_field_name("value")
        if name_node is None or value_node is None or name_node.type != "identifier":
            continue
        declared[_node_text(name_node, src)] = _is_hono_constructor_call(value_node, src)
    return declared


def _build_router_mounts(target_path: Path) -> dict[str, tuple[str, str]]:
    """Map sub-app variable name -> (parent object name, prefix) from every
    `parent.route('/prefix', subApp)` call in the project. Distinct from
    Express's version: Hono keeps mounting (`.route()`) and middleware
    (`.use()`) as two separate methods, so this only has to look at one of
    them -- no need to disambiguate a router-mount from a middleware call
    by argument shape.
    """
    mounts: dict[str, tuple[str, str]] = {}
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
            if obj is None or prop is None or obj.type != "identifier" or _node_text(prop, src) != "route":
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            args = args_node.named_children
            if len(args) < 2 or args[0].type != "string" or args[1].type != "identifier":
                continue

            prefix = _string_value(args[0], src) or ""
            mounts[_node_text(args[1], src)] = (_node_text(obj, src), prefix)
    return mounts


def _extract_route_call(node: Node, src: bytes, router_names: set[str]) -> tuple[str, str, str, list[str]] | None:
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
    if obj_name not in router_names:
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


def _detect_global_use_middleware(target_path: Path) -> tuple[str, int, str] | None:
    """`app.use(jwt({...}))` / `app.use('/api/*', jwt({...}))` applies to
    every route registered after it (or matching its path prefix, if one is
    given) -- restricted to KNOWN_AUTH_INDICATORS for the same reason as
    Express's version: `.use()` is also how `cors()`/logging/other
    middleware gets registered, and those would otherwise swamp this with
    noise. Unlike Express, an arg here can be a bare identifier OR a call
    expression (`jwt(...)`) -- see module docstring -- so both are checked.
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
            if _node_text(prop, src) != "use":
                continue

            args_node = node.child_by_field_name("arguments")
            if args_node is None:
                continue
            for arg in args_node.named_children:
                name = None
                if arg.type == "identifier":
                    name = _node_text(arg, src)
                elif arg.type == "call_expression":
                    arg_func = arg.child_by_field_name("function")
                    if arg_func is not None:
                        name = _node_text(arg_func, src)
                if name in KNOWN_AUTH_INDICATORS:
                    relative_file = str(src_file.relative_to(target_path))
                    line = node.start_point[0] + 1
                    call_text = _node_text(arg, src)[:60]
                    return relative_file, line, f"{_node_text(obj, src)}.use({call_text})"
    return None


def _detect_cors_wildcards(target_path: Path) -> list[Finding]:
    """A bare `cors()` call (no options object) defaults to allowing any
    origin -- same shape as `hono/cors`'s own `cors({ origin: '*' })`.
    """
    findings: list[Finding] = []
    for src_file in iter_files(target_path, (".js", ".ts")):
        src = read_text_safe(src_file).encode("utf-8")
        if not src:
            continue
        tree = _parser_for(src_file).parse(src)
        relative_file = str(src_file.relative_to(target_path))

        for node in _iter_nodes(tree.root_node):
            if node.type != "call_expression":
                continue
            func = node.child_by_field_name("function")
            if func is None or _node_text(func, src) != "cors":
                continue

            args_node = node.child_by_field_name("arguments")
            args = args_node.named_children if args_node else []
            line = node.start_point[0] + 1

            if not args:
                findings.append(config_checks.cors_wildcard_finding(relative_file, line, "cors() called with no options"))
                continue

            call_text = _node_text(node, src)
            if "origin:" in call_text and ("'*'" in call_text or '"*"' in call_text or "origin: true" in call_text):
                findings.append(config_checks.cors_wildcard_finding(relative_file, line, call_text[:120]))
    return findings


@register("javascript", "hono")
class HonoAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        router_mounts = _build_router_mounts(self.target_path)

        for src_file in iter_files(self.target_path, (".js", ".ts")):
            text = read_text_safe(src_file)
            if not text:
                continue
            src = text.encode("utf-8")

            tree = _parser_for(src_file).parse(src)
            locally_declared = _locally_declared_names(tree.root_node, src)
            router_names = {name for name, is_hono in locally_declared.items() if is_hono} or {"app"}

            for node in _iter_nodes(tree.root_node):
                extracted = _extract_route_call(node, src, router_names)
                if extracted is None:
                    continue
                obj_name, verb, sub_path, rest_args = extracted
                mount_prefix = resolve_mount_prefix(obj_name, router_mounts)
                path = join_path_segments(mount_prefix, sub_path)

                handler_name = rest_args[-1] if rest_args else "?"
                middleware_names = rest_args[:-1]

                route_line = node.start_point[0] + 1
                source_file = source_start = source_end = None
                extra_params: list[str] = []
                if handler_name == "<inline handler>":
                    source_file = str(src_file.relative_to(self.target_path))
                    source_start = route_line
                    source_end = node.end_point[0] + 1
                    extra_params = extract_request_field_names(_node_text(node, src))

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
                        extra_param_names=extra_params,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        findings += _detect_cors_wildcards(self.target_path)
        findings += detect_dangerous_sinks(self.target_path)
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_use_middleware(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
