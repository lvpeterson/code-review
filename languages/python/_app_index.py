"""Resolves which framework a decorated `app`/`router`-style object actually
belongs to.

Flask's shortcut decorators (`@app.get(...)`, `@app.post(...)`, added in
Flask 2.x) are syntactically identical to FastAPI's. Without this, a
codebase running both frameworks side by side would get every FastAPI route
double-counted by the Flask analyzer too (and vice versa). This scans for
the actual constructor call (`Flask(...)`, `FastAPI(...)`, etc) each name is
assigned to, so each analyzer can veto a match it can prove isn't its own.
"""
from __future__ import annotations

import ast
from pathlib import Path

from core.fsutil import iter_files, read_text_safe
from languages.python._ast_utils import dotted_name, parse_source

# Blueprint/APIRouter count too -- `@bp.route(...)` and `@router.get(...)`
# are just as diagnostic of which framework owns an object as the top-level
# app instance is.
_CONSTRUCTORS = {
    "Flask": "flask",
    "Blueprint": "flask",
    "FastAPI": "fastapi",
    "APIRouter": "fastapi",
}


def build_app_object_index(target_path: Path) -> dict[str, str]:
    """Map variable name -> "flask" | "fastapi" by scanning every module for
    `name = Flask(...)` / `Blueprint(...)` / `FastAPI(...)` / `APIRouter(...)`
    assignments.

    A name not found here is left unresolved on purpose -- e.g. an app
    object imported from another module (`from myapp import app`) rather
    than constructed locally. Callers should treat "unresolved" as "claim by
    default", not "skip": vetoing needs positive proof of the *other*
    framework, since the common blueprint-across-files pattern would
    otherwise cause real routes to go silently unreported.
    """
    index: dict[str, str] = {}

    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        tree = parse_source(text, str(py_file))
        if tree is None:
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            constructor = dotted_name(node.value.func)
            if constructor is None:
                continue
            framework = _CONSTRUCTORS.get(constructor.rsplit(".", 1)[-1])
            if framework is None:
                continue
            for target in node.targets:
                if isinstance(target, ast.Name):
                    index[target.id] = framework

    return index
