"""Language + framework detection for Python targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe

_LANGUAGE_SIGNAL_FILES = ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile")


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, *_LANGUAGE_SIGNAL_FILES):
        return True
    return any(True for _ in iter_files(target_path, (".py",)))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework this Python codebase appears to use -- a repo
    migrating from Flask to FastAPI (or otherwise running both) reports both,
    so each gets its own deep-dive instead of one silently winning and the
    other's routes going unscanned.
    """
    manifest_text = ""
    for name in _LANGUAGE_SIGNAL_FILES:
        manifest_text += read_text_safe(target_path / name).lower()

    found: set[str] = set()
    if "django" in manifest_text or any_file_exists(target_path, "manage.py"):
        found.add("django")
    if "fastapi" in manifest_text:
        found.add("fastapi")
    if "flask" in manifest_text:
        found.add("flask")

    if found:
        return sorted(found)

    # Manifest didn't tell us anything -- fall back to scanning source for
    # imports (slower, so only done when the manifest was no help at all).
    for py_file in iter_files(target_path, (".py",)):
        text = read_text_safe(py_file)
        if "django" in text and ("django.db" in text or "django.urls" in text or "settings" in py_file.name):
            found.add("django")
        if "from fastapi" in text or "import fastapi" in text:
            found.add("fastapi")
        if "from flask" in text or "import flask" in text:
            found.add("flask")

    return sorted(found)
