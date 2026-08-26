"""Deep-dive analyzer for Flask targets.

Uses Python's stdlib `ast` module to parse real decorator/call nodes instead
of regex line-windows -- handles multi-line decorators, arbitrary decorator
order, and Flask 2.x shortcut decorators (@app.get/@app.post/...) for free.
"""
from __future__ import annotations

import ast

from checks import auth as auth_checks
from checks import config as config_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.bodyscan import extract_request_field_names
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.paths import join_path_segments
from core.registry import register
from languages.python._app_index import build_app_object_index
from languages.python._ast_utils import (
    dotted_name,
    iter_functions,
    literal,
    mock_import_names,
    parse_decorators,
    parse_source,
    source_range,
)

# For `@app.route(...)`, methods come from the `methods=` kwarg (default
# GET). The shortcut decorators fix the method outright.
_ROUTE_DECORATOR_METHODS = {
    "route": None,
    "get": ["GET"],
    "post": ["POST"],
    "put": ["PUT"],
    "patch": ["PATCH"],
    "delete": ["DELETE"],
}

# Decorators that plausibly indicate auth enforcement. Extend this list to
# match whatever this codebase actually uses (custom decorators,
# flask-login, flask-jwt-extended, etc).
KNOWN_AUTH_INDICATORS = {
    "login_required",
    "jwt_required",
    "auth_required",
    "permission_required",
    "roles_required",
}

# Textual markers inside a @before_request body that plausibly mean it's
# enforcing auth rather than e.g. opening a DB connection or logging. This
# is a presence check, not real behavioral analysis -- see
# checks/auth.py:apply_global_auth_note for why it stays that shallow.
_GLOBAL_AUTH_BODY_MARKERS = (
    "abort(401", "abort(403", "current_user.is_authenticated", "g.user",
    "unauthorized", "Unauthorized", *KNOWN_AUTH_INDICATORS,
)


def _detect_global_before_request_auth(target_path) -> tuple[str, int, str] | None:
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue
        lines = text.split("\n")

        for func in iter_functions(tree):
            if not any(d.name == "before_request" for d in parse_decorators(func)):
                continue
            start, end = source_range(func)
            body_text = "\n".join(lines[start - 1:end])
            if any(marker in body_text for marker in _GLOBAL_AUTH_BODY_MARKERS):
                relative_file = str(py_file.relative_to(target_path))
                return relative_file, func.lineno, f"@before_request '{func.name}', which appears to check auth"
    return None


def _build_blueprint_prefixes(target_path) -> dict[str, str]:
    """Map blueprint variable name -> url_prefix, from either the
    `Blueprint(..., url_prefix="...")` constructor call or a later
    `app.register_blueprint(bp, url_prefix="...")` (which takes precedence
    if both are present, matching Flask's own behavior). Without this, every
    route on a blueprint mounted under a prefix reports its bare path.
    """
    prefixes: dict[str, str] = {}

    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            constructor = dotted_name(node.value.func)
            if constructor is None or constructor.rsplit(".", 1)[-1] != "Blueprint":
                continue
            prefix = next((literal(kw.value) for kw in node.value.keywords if kw.arg == "url_prefix"), None)
            if prefix:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        prefixes[target.id] = prefix

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_dotted = dotted_name(node.func)
            if func_dotted is None or not func_dotted.endswith(".register_blueprint") or not node.args:
                continue
            bp_name = dotted_name(node.args[0])
            if bp_name is None:
                continue
            prefix = next((literal(kw.value) for kw in node.keywords if kw.arg == "url_prefix"), None)
            if prefix:
                prefixes[bp_name] = prefix

    return prefixes


def _detect_debug_mode(target_path) -> list[Finding]:
    """`app.run(debug=True)` or `app.debug = True` -- Flask's dev server
    debug mode, which exposes the interactive Werkzeug debugger/stack
    traces to anyone who can trigger a 500.
    """
    findings: list[Finding] = []
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue
        relative_file = str(py_file.relative_to(target_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_dotted = dotted_name(node.func)
                if func_dotted and func_dotted.rsplit(".", 1)[-1] == "run":
                    for kw in node.keywords:
                        if kw.arg == "debug" and literal(kw.value) is True:
                            findings.append(
                                config_checks.debug_mode_finding(relative_file, node.lineno, f"{func_dotted}(debug=True)")
                            )
            elif isinstance(node, ast.Assign):
                for target in node.targets:
                    target_dotted = dotted_name(target)
                    if target_dotted and target_dotted.rsplit(".", 1)[-1] == "debug" and literal(node.value) is True:
                        findings.append(
                            config_checks.debug_mode_finding(relative_file, node.lineno, f"{target_dotted} = True")
                        )
    return findings


@register("python", "flask")
class FlaskAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        app_index = build_app_object_index(self.target_path)
        blueprint_prefixes = _build_blueprint_prefixes(self.target_path)

        for py_file in iter_files(self.target_path, (".py",)):
            text = read_text_safe(py_file)
            tree = parse_source(text, str(py_file))
            if tree is None:
                continue
            mock_names = mock_import_names(tree)

            for func in iter_functions(tree):
                decorators = parse_decorators(func)
                route_deco = next(
                    (d for d in decorators if d.name in _ROUTE_DECORATOR_METHODS and d.args),
                    None,
                )
                if route_deco is None:
                    continue

                base_name = route_deco.dotted.split(".", 1)[0]

                # `@patch(...)` / `@mock.patch(...)` from unittest.mock parse
                # identically to a bare "patch" route decorator -- extremely
                # common in test files, so exclude anything bound to
                # unittest.mock before it's ever treated as a route.
                if base_name in mock_names:
                    continue

                # Flask's @app.get/@app.post shortcuts are syntactically
                # identical to FastAPI's -- only skip when we can prove this
                # object is actually a FastAPI/APIRouter instance. Leave it
                # claimed if unresolved (e.g. `app` imported from elsewhere).
                if app_index.get(base_name) == "fastapi":
                    continue

                sub_path = route_deco.args[0] if isinstance(route_deco.args[0], str) else "?"
                prefix = blueprint_prefixes.get(base_name, "")
                path = join_path_segments(prefix, sub_path) if sub_path != "?" else sub_path
                fixed_methods = _ROUTE_DECORATOR_METHODS[route_deco.name]
                methods = fixed_methods or route_deco.kwargs.get("methods") or ["GET"]

                auth_decorators = [d.name for d in decorators if d is not route_deco]
                start_line, end_line = source_range(func)
                body_text = "\n".join(text.split("\n")[start_line - 1:end_line])
                extra_params = extract_request_field_names(body_text)

                routes.append(
                    Route(
                        path=path,
                        methods=list(methods),
                        handler_name=func.name,
                        file=str(py_file.relative_to(self.target_path)),
                        line=route_deco.node.lineno,
                        auth_decorators=auth_decorators,
                        raw_snippet=f"@{route_deco.dotted}(...) def {func.name}(...)",
                        source_start_line=start_line,
                        source_end_line=end_line,
                        extra_param_names=extra_params,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        findings += _detect_debug_mode(self.target_path)
        # TODO: Flask-specific checks -- e.g. flag routes using
        # request.args/json values directly in raw SQL, or missing CSRF
        # protection on state-changing routes.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_before_request_auth(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
