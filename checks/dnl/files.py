"""File walking, case-insensitive path resolution and source decoding for the
legacy .NET analyzer.

.NET Framework projects come from Windows: csproj paths use backslashes and
casing is sloppy (`homeController.cs` pointing at `HomeController.cs`). All
helpers here work on Linux too, so nothing relies on filesystem case folding.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

# Build output, NuGet restore, VCS / VS state and JS deps. Deliberately not the
# shared core/fsutil set: `Vendor`, `Build`, `Dist` and `Target` are ordinary
# folder names in .NET apps and hold real pages and configs. Anything starting
# with "precompiled" is also skipped (see _skip).
_DNL_SKIP_DIRS = {"bin", "obj", "packages", ".git", ".hg", ".svn", ".vs", "node_modules",
                  "__pycache__", "venv", ".venv"}


def _skip(dirname: str) -> bool:
    low = dirname.lower()
    return low in _DNL_SKIP_DIRS or low.startswith("precompiled")


def iter_dnl_files(root: Path, extensions: tuple[str, ...]) -> Iterator[Path]:
    """Yield files under root whose suffix (case-insensitive) is in
    extensions (lowercase, with dot), pruning skip dirs during the walk."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not _skip(d))
        for name in sorted(filenames):
            if Path(name).suffix.lower() in extensions:
                yield Path(dirpath) / name


def resolve_ci(base: Path, rel: str) -> Path | None:
    """Resolve a `\\` or `/` separated relative path under base, matching each
    segment case-insensitively. Returns the existing path or None."""
    cur = base
    for seg in rel.replace("\\", "/").split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            cur = cur.parent
            continue
        if not cur.is_dir():
            return None
        # List the dir rather than trusting exists(): on case-insensitive
        # filesystems exists() succeeds but keeps the caller's spelling.
        low = seg.lower()
        try:
            names = sorted(c.name for c in cur.iterdir())
        except OSError:
            return None
        match = seg if seg in names else next((n for n in names if n.lower() == low), None)
        if match is None:
            return None
        cur = cur / match
    return cur if cur.exists() else None


def read_source(path: Path) -> str:
    """Decode source as UTF-8 (BOM stripped), falling back to cp1252."""
    data = path.read_bytes()
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def is_legacy_project(text: str) -> bool:
    """True for old-style (non-SDK) project files."""
    if "<Project Sdk=" in text:
        return False
    return "ToolsVersion=" in text or "<TargetFrameworkVersion>v" in text
