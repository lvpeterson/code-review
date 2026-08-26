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
from core.models import Finding, Route, ScanResult
from core.paths import extract_path_param_names, join_path_segments, resolve_mount_prefix
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


def _detect_global_dependencies(target_path) -> tuple[str, int, str] | None:
    """FastAPI/APIRouter's `dependencies=[Depends(x), ...]` constructor
    kwarg applies to every route registered on that app/router -- unlike
    Flask's before_request, this is structurally explicit (no body-sniffing
    needed), so it's a precise presence signal.
    """
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            constructor = dotted_name(node.func)
            if constructor is None or constructor.rsplit(".", 1)[-1] not in ("FastAPI", "APIRouter"):
                continue

            for kw in node.keywords:
                if kw.arg != "dependencies" or not isinstance(kw.value, (ast.List, ast.Tuple)):
                    continue
                dep_names = []
                for elt in kw.value.elts:
                    if isinstance(elt, ast.Call) and dotted_name(elt.func) == "Depends" and elt.args:
                        dep_name = dotted_name(elt.args[0])
                        if dep_name:
                            dep_names.append(dep_name)
                if dep_names:
                    relative_file = str(py_file.relative_to(target_path))
                    return relative_file, node.lineno, f"dependencies={dep_names} passed to {constructor}(...)"
    return None


def _build_router_mounts(target_path) -> dict[str, tuple[str, str]]:
    """Map child router variable name -> (parent object name, prefix) from
    every `parent.include_router(child, prefix="...")` call in the project.

    Without this, a route declared on a sub-router (`items_router.get(...)`)
    that gets mounted elsewhere (`app.include_router(items_router,
    prefix="/api/v1")`, often in a different file) would report its bare
    "/items/{id}" path instead of the real "/api/v1/items/{id}" -- a very
    common FastAPI pattern for versioning/module organization.
    """
    mounts: dict[str, tuple[str, str]] = {}
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func_dotted = dotted_name(node.func)
            if func_dotted is None or not func_dotted.endswith(".include_router"):
                continue
            if not node.args:
                continue
            child_name = dotted_name(node.args[0])
            if child_name is None:
                continue

            prefix = ""
            for kw in node.keywords:
                if kw.arg == "prefix":
                    prefix = literal(kw.value) or ""

            parent_name = func_dotted.rsplit(".", 1)[0]
            mounts[child_name] = (parent_name, prefix)
    return mounts


def _params_with_depends_default(func) -> set[str]:
    depends_names: set[str] = set()
    positional = func.args.posonlyargs + func.args.args
    for arg, default in zip(reversed(positional), reversed(func.args.defaults)):
        if isinstance(default, ast.Call) and dotted_name(default.func) == "Depends":
            depends_names.add(arg.arg)
    for arg, default in zip(func.args.kwonlyargs, func.args.kw_defaults):
        if default is not None and isinstance(default, ast.Call) and dotted_name(default.func) == "Depends":
            depends_names.add(arg.arg)
    return depends_names


def _extra_param_names(func, path: str) -> list[str]:
    """Handler parameters that are neither path params nor `Depends(...)`
    injections -- FastAPI binds these from the query string (simple types)
    or the JSON body (Pydantic model params), so an id-like one here is just
    as much an IDOR candidate as one in the URL path.
    """
    path_names = set(extract_path_param_names(path))
    depends_names = _params_with_depends_default(func)
    all_names = [a.arg for a in (func.args.posonlyargs + func.args.args + func.args.kwonlyargs)]
    return [n for n in all_names if n not in path_names and n not in depends_names and n != "self"]


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
        router_mounts = _build_router_mounts(self.target_path)

        for py_file in iter_files(self.target_path, (".py",)):
            text = read_text_safe(py_file)
            tree = parse_source(text, str(py_file))
            if tree is None:
                continue
            mock_names = mock_import_names(tree)

            for func in iter_functions(tree):
                decorators = parse_decorators(func)
                route_deco = next(
                    (d for d in decorators if d.name in _HTTP_METHODS and d.args),
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

                # FastAPI's @app.get/@app.post are syntactically identical to
                # Flask's 2.x shortcuts -- only skip when we can prove this
                # object is actually a Flask/Blueprint instance. Leave it
                # claimed if unresolved (e.g. `app` imported from elsewhere).
                if app_index.get(base_name) == "flask":
                    continue

                sub_path = route_deco.args[0] if isinstance(route_deco.args[0], str) else "?"
                mount_prefix = resolve_mount_prefix(base_name, router_mounts)
                path = join_path_segments(mount_prefix, sub_path) if sub_path != "?" else sub_path
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
                        extra_param_names=_extra_param_names(func, path),
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

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_dependencies(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
