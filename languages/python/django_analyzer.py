"""Deep-dive analyzer for Django targets.

Routes live in urlpatterns (urls.py) but auth is usually declared over in
views.py (@login_required, permission_classes, LoginRequiredMixin, ...), so
this analyzer does two passes: extract urlpatterns entries via `ast`, then
build an index of every function/class def in the codebase (also via `ast`,
so decorators/base classes/class attributes are resolved precisely instead
of by guessing at a line-number window) and look up each view by name.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass, field

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.registry import register
from languages.python._ast_utils import dotted_name, literal, parse_decorators, parse_source, source_range

_URL_FUNCS = {"path", "re_path", "url"}

KNOWN_AUTH_INDICATORS = {
    "login_required",
    "permission_required",
    "staff_member_required",
    "LoginRequiredMixin",
    "IsAuthenticated",
    "permission_classes",
}


@dataclass
class _ViewInfo:
    """Where a view function/class actually lives, for the HTML report's
    code view -- urls.py only has the registration, not the implementation.
    """

    file: str
    start_line: int
    end_line: int
    auth_tokens: list[str] = field(default_factory=list)


def _describe_view(node: ast.AST) -> tuple[str, str]:
    """Return (display_name, lookup_key) for a urlpatterns view argument --
    handles `views.foo`, `views.Foo.as_view()`, and bare `foo`.
    """
    if isinstance(node, ast.Call):
        return _describe_view(node.func)
    if isinstance(node, ast.Attribute):
        if node.attr == "as_view":
            return _describe_view(node.value)
        dotted = dotted_name(node) or node.attr
        return dotted, node.attr
    if isinstance(node, ast.Name):
        return node.id, node.id
    return "?", ""


def _build_view_index(target_path) -> dict[str, _ViewInfo]:
    """Map view function/class name -> where it's defined + auth-related
    tokens found on it (decorators, base classes, or a
    `permission_classes = [...]` attribute).
    """
    index: dict[str, _ViewInfo] = {}

    for py_file in iter_files(target_path, (".py",)):
        if py_file.name == "urls.py":
            continue
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue
        relative_file = str(py_file.relative_to(target_path))

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                tokens = [d.name for d in parse_decorators(node) if d.name in KNOWN_AUTH_INDICATORS]
                start_line, end_line = source_range(node)
                index[node.name] = _ViewInfo(relative_file, start_line, end_line, tokens)

            elif isinstance(node, ast.ClassDef):
                tokens = [d.name for d in parse_decorators(node) if d.name in KNOWN_AUTH_INDICATORS]

                for base in node.bases:
                    base_name = (dotted_name(base) or "").rsplit(".", 1)[-1]
                    if base_name in KNOWN_AUTH_INDICATORS:
                        tokens.append(base_name)

                for stmt in node.body:
                    if not isinstance(stmt, ast.Assign):
                        continue
                    if not any(isinstance(t, ast.Name) and t.id == "permission_classes" for t in stmt.targets):
                        continue
                    values = literal(stmt.value)
                    if isinstance(values, (list, tuple)):
                        tokens.append("permission_classes")

                start_line, end_line = source_range(node)
                index[node.name] = _ViewInfo(relative_file, start_line, end_line, tokens)

    return index


def _permission_names(node: ast.AST) -> list[str]:
    """Extract permission class names whether they're written as string
    paths (`'rest_framework.permissions.IsAuthenticated'`, the usual style
    in settings.py) or bare class references (`permissions.IsAuthenticated`).
    """
    if not isinstance(node, (ast.List, ast.Tuple)):
        return []
    names = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            names.append(elt.value)
        else:
            name = dotted_name(elt)
            if name:
                names.append(name)
    return names


def _detect_drf_default_permissions(target_path) -> tuple[str, int, str] | None:
    """DRF's REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"] in settings.py
    applies to every DRF view by default unless a view overrides it --
    doesn't require any per-view decorator, so it's invisible to the
    per-view auth-decorator scan above.
    """
    for py_file in iter_files(target_path, (".py",)):
        if py_file.name != "settings.py":
            continue
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not any(isinstance(t, ast.Name) and t.id == "REST_FRAMEWORK" for t in node.targets):
                continue
            if not isinstance(node.value, ast.Dict):
                continue
            for key_node, val_node in zip(node.value.keys, node.value.values):
                if not (isinstance(key_node, ast.Constant) and key_node.value == "DEFAULT_PERMISSION_CLASSES"):
                    continue
                perms = _permission_names(val_node)
                if perms and any("AllowAny" not in p for p in perms):
                    relative_file = str(py_file.relative_to(target_path))
                    return relative_file, node.lineno, f"REST_FRAMEWORK DEFAULT_PERMISSION_CLASSES={perms}"
    return None


@register("python", "django")
class DjangoAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []
        view_index = _build_view_index(self.target_path)

        for py_file in iter_files(self.target_path, (".py",)):
            if py_file.name != "urls.py":
                continue
            text = read_text_safe(py_file)
            tree = parse_source(text, str(py_file))
            if tree is None:
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func_name = dotted_name(node.func)
                if func_name is None or func_name.rsplit(".", 1)[-1] not in _URL_FUNCS:
                    continue
                if len(node.args) < 2:
                    continue

                path = literal(node.args[0])
                if not isinstance(path, str):
                    continue

                handler_name, lookup_key = _describe_view(node.args[1])
                view_info = view_index.get(lookup_key)

                routes.append(
                    Route(
                        path=path,
                        methods=["GET", "POST"],  # Django views often accept both; refine per-view if needed.
                        handler_name=handler_name,
                        file=str(py_file.relative_to(self.target_path)),
                        line=node.lineno,
                        auth_decorators=view_info.auth_tokens if view_info else [],
                        raw_snippet=f"{func_name}({path!r}, {handler_name})",
                        source_file=view_info.file if view_info else None,
                        source_start_line=view_info.start_line if view_info else None,
                        source_end_line=view_info.end_line if view_info else None,
                    )
                )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Django-specific checks -- e.g. DEBUG=True in settings.py,
        # missing @csrf_protect on state-changing views, raw SQL via .raw()/
        # extra() with unsanitized input.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_drf_default_permissions(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
