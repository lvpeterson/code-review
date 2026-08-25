"""Language + framework detection for Go targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, "go.mod"):
        return True
    return any(True for _ in iter_files(target_path, (".go",)))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework detected: "gin" and/or "net_http".

    TODO: this is a stub -- only distinguishes gin vs stdlib net/http via
    go.mod. Add gorilla/mux, echo, fiber, etc following this same pattern.
    """
    mod_text = read_text_safe(target_path / "go.mod").lower()
    if "gin-gonic/gin" in mod_text:
        return ["gin"]
    if any(True for _ in iter_files(target_path, (".go",))):
        return ["net_http"]
    return []
