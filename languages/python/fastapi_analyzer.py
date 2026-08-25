"""Deep-dive analyzer for FastAPI targets.

Uses Python's stdlib `ast` module. Auth in FastAPI is normally expressed as
a `Depends(something)` default value on a handler parameter rather than a
stacked decorator, so route decorators are read the same way as Flask's
shortcuts while auth detection walks the function's parameter defaults.
"""
from __future__ import annotations

import ast

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route
from core.registry import register
from languages.python._app_index import build_app_object_index
from languages.python._ast_utils import (
    dotted_name,
    iter_functions,
    parse_decorators,
    parse_source,
    source_range,
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

# Dependency callables that plausibly indicate auth enforcement. Extend this
# list to match whatever this codebase's auth dependency is actually called.
KNOWN_AUTH_INDICATORS = {
    "get_current_user",
    "require_auth",
    "verify_token",
    "oauth2_scheme",
    "get_current_active_user",
}


def _depends_targets(func) -> list[str]:
    """Return the callable name inside every `Depends(...)` default value on
    this function's parameters (positional, keyword-only, or annotated
    `= Depends(...)` defaults all show up in args.defaults/kw_defaults).
    """
    targets: list[str] = []
    for default in [*func.args.defaults, *func.args.kw_defaults]:
        if not isinstance(default, ast.Call):
            continue
        if dotted_name(default.func) != "Depends" or not default.args:
            continue
        dep_name = dotted_name(default.args[0])
        if dep_name:
            targets.append(dep_name)
    return targets


@register("python", "fastapi")
class FastAPIAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        app_index = build_app_object_index(self.target_path)

        for py_file in iter_files(self.target_path, (".py",)):
            text = read_text_safe(py_file)
            tree = parse_source(text, str(py_file))
            if tree is None:
                continue

            for func in iter_functions(tree):
                decorators = parse_decorators(func)
                route_deco = next(
                    (d for d in decorators if d.name in _HTTP_METHODS and d.args),
                    None,
                )
                if route_deco is None:
                    continue

                # FastAPI's @app.get/@app.post are syntactically identical to
                # Flask's 2.x shortcuts -- only skip when we can prove this
                # object is actually a Flask/Blueprint instance. Leave it
                # claimed if unresolved (e.g. `app` imported from elsewhere).
                base_name = route_deco.dotted.split(".", 1)[0]
                if app_index.get(base_name) == "flask":
                    continue

                path = route_deco.args[0] if isinstance(route_deco.args[0], str) else "?"
                auth_decorators = _depends_targets(func)
                start_line, end_line = source_range(func)

                routes.append(
                    Route(
                        path=path,
                        methods=[route_deco.name.upper()],
                        handler_name=func.name,
                        file=str(py_file.relative_to(self.target_path)),
                        line=route_deco.node.lineno,
                        auth_decorators=auth_decorators,
                        raw_snippet=f"@{route_deco.dotted}(...) def {func.name}(...)",
                        source_start_line=start_line,
                        source_end_line=end_line,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: FastAPI-specific checks -- e.g. Pydantic models that accept
        # extra/unvalidated fields, response_model leaking sensitive fields.
        return findings
