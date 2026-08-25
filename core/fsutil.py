"""Small filesystem helpers shared by detectors and analyzers."""
from __future__ import annotations

from pathlib import Path
from typing import Iterator

# Directories not worth walking into -- keeps detection/analysis fast on
# real-world repos with vendored deps, build output, VCS metadata, etc.
_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "vendor", "venv", ".venv",
    "__pycache__", "dist", "build", "target", ".mypy_cache", ".pytest_cache",
    "bin", "obj",
}


def iter_files(root: Path, extensions: tuple[str, ...]) -> Iterator[Path]:
    """Yield files under root matching any of extensions, skipping noise dirs."""
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.suffix in extensions:
            yield path


def read_text_safe(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def any_file_exists(root: Path, *names: str) -> bool:
    return any((root / name).exists() for name in names)
