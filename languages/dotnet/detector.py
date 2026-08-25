"""Language + framework detection for .NET (C#) targets."""
from __future__ import annotations

from pathlib import Path

from core.fsutil import iter_files, read_text_safe


def detect_language(target_path: Path) -> bool:
    if any(True for _ in iter_files(target_path, (".csproj",))):
        return True
    return any(True for _ in iter_files(target_path, (".cs",)))


def detect_framework(target_path: Path) -> str | None:
    """Return "aspnet" | None.

    TODO: this is a stub -- doesn't yet distinguish ASP.NET MVC vs Web API
    vs Minimal API conventions. All three currently map to "aspnet".
    """
    for csproj in iter_files(target_path, (".csproj",)):
        text = read_text_safe(csproj)
        if "Microsoft.AspNetCore" in text or "Microsoft.NET.Sdk.Web" in text:
            return "aspnet"

    for cs_file in iter_files(target_path, (".cs",)):
        text = read_text_safe(cs_file)
        if "Microsoft.AspNetCore" in text:
            return "aspnet"

    return None
