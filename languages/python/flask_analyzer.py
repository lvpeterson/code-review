"""Deep-dive analyzer for Flask targets.

Uses Python's stdlib `ast` module to parse real decorator/call nodes instead
of regex line-windows -- handles multi-line decorators, arbitrary decorator
order, and Flask 2.x shortcut decorators (@app.get/@app.post/...) for free.
"""
from __future__ import annotations

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route
from core.registry import register
from languages.python._app_index import build_app_object_index
from languages.python._ast_utils import iter_functions, parse_decorators, parse_source, source_range

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


@register("python", "flask")
class FlaskAnalyzer(BaseFrameworkAnalyzer):
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
                    (d for d in decorators if d.name in _ROUTE_DECORATOR_METHODS and d.args),
                    None,
                )
                if route_deco is None:
                    continue

                # Flask's @app.get/@app.post shortcuts are syntactically
                # identical to FastAPI's -- only skip when we can prove this
                # object is actually a FastAPI/APIRouter instance. Leave it
                # claimed if unresolved (e.g. `app` imported from elsewhere).
                base_name = route_deco.dotted.split(".", 1)[0]
                if app_index.get(base_name) == "fastapi":
                    continue

                path = route_deco.args[0] if isinstance(route_deco.args[0], str) else "?"
                fixed_methods = _ROUTE_DECORATOR_METHODS[route_deco.name]
                methods = fixed_methods or route_deco.kwargs.get("methods") or ["GET"]

                auth_decorators = [d.name for d in decorators if d is not route_deco]
                start_line, end_line = source_range(func)

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
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Flask-specific checks -- e.g. flag routes using
        # request.args/json values directly in raw SQL, or debug=True in
        # app.run(), or missing CSRF protection on state-changing routes.
        return findings
