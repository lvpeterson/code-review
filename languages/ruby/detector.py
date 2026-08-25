"""Language + framework detection for Ruby targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, "Gemfile"):
        return True
    return any(True for _ in iter_files(target_path, (".rb",)))


def detect_frameworks(target_path: Path) -> list[str]:
    """Return every framework detected: "rails" and/or "sinatra"."""
    gemfile_text = read_text_safe(target_path / "Gemfile").lower()
    found: list[str] = []
    if "rails" in gemfile_text or any_file_exists(target_path, "config/routes.rb"):
        found.append("rails")
    if "sinatra" in gemfile_text:
        found.append("sinatra")
    return found
