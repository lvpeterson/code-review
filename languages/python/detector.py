"""Language + framework detection for Python targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe

_LANGUAGE_SIGNAL_FILES = ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, *_LANGUAGE_SIGNAL_FILES):
        return True
    return any(True for _ in iter_files(target_path, (".py",)))


def detect_framework(target_path: Path) -> str | None:
    """Return "flask" | "fastapi" | "django" | None.

    Checks dependency manifests first (cheap, high-confidence), then falls
    back to scanning source for import statements.
    """
    manifest_text = ""
    for name in _LANGUAGE_SIGNAL_FILES:
        manifest_text += read_text_safe(target_path / name).lower()

    if "django" in manifest_text or any_file_exists(target_path, "manage.py"):
        return "django"
    if "fastapi" in manifest_text:
        return "fastapi"
    if "flask" in manifest_text:
        return "flask"

    # Manifest didn't tell us -- fall back to scanning source for imports.
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        if "django" in text and ("django.db" in text or "django.urls" in text or "settings" in py_file.name):
            return "django"
        if "from fastapi" in text or "import fastapi" in text:
            return "fastapi"
        if "from flask" in text or "import flask" in text:
            return "flask"

    return None
