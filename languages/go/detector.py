"""Language + framework detection for Go targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, "go.mod"):
        return True
    return any(True for _ in iter_files(target_path, (".go",)))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework detected: "gin" and/or "net_http" -- not
    mutually exclusive, since a real app can use gin for its main API and
    still register a raw net/http handler somewhere (a health check, a
    pprof endpoint, ...).

    TODO: add gorilla/mux, echo, fiber, etc following this same pattern.
    """
    found: set[str] = set()

    mod_text = read_text_safe(target_path / "go.mod").lower()
    if "gin-gonic/gin" in mod_text:
        found.add("gin")

    for go_file in iter_files(target_path, (".go",)):
        text = read_text_safe(go_file)
        if ".HandleFunc(" in text or "http.NewServeMux" in text:
            found.add("net_http")
            break

    return sorted(found)
