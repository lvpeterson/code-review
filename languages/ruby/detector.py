"""Language + framework detection for Ruby targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import any_file_exists, iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any_file_exists(target_path, "Gemfile"):
        return True
    return any(True for _ in iter_files(target_path, (".rb",)))


def detect_framework(target_path: Path) -> str | None:
    """Return "rails" | "sinatra" | None."""
    gemfile_text = read_text_safe(target_path / "Gemfile").lower()
    if "rails" in gemfile_text or any_file_exists(target_path, "config/routes.rb"):
        return "rails"
    if "sinatra" in gemfile_text:
        return "sinatra"
    return None
