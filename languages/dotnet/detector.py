"""Language + framework detection for modern .NET (ASP.NET Core) targets.

Text scans only (no helper): the project files decide ownership (checks.dnl.project.load_projects, the
same logic the model uses), then the C# / Razor sources of those projects are searched for the
framework markers. .NET Framework projects belong to dotnet_legacy.
"""
from __future__ import annotations

import re
from pathlib import Path

from checks.dnl import project
from checks.dnl.files import iter_dnl_files, read_source

_FRAMEWORK_ORDER = ["controllers", "razorpages", "minimalapi", "config"]
# `[ApiController]`, `[ApiController, Route(..)]`, `[Route(..), ApiController]`; the base-list form allows a
# primary constructor (`class T(ILogger<T> log) : ControllerBase`).
_CONTROLLER = re.compile(r"[\[,]\s*(?:[\w.]+\.)?(?:ApiController|Controller)(?:Attribute)?\s*[\],(]"
                         r"|\bclass\s+\w+(?:<[^>]*>)?(?:\s*\([^)]*\))?\s*:[^{;]*?\b(?:Controller|ControllerBase)\b")
# Any endpoint-builder Map call (MapGet, MapGroup, MapHub, MapBlazorHub, MapRazorComponents, MapOpenApi,
# MapFallbackToFile, MapHealthChecks, ...) or `.Map("...")`. MapControllers / MapRazorPages and the
# conventional controller routes only enable the styles detected separately.
_MINIMAL = re.compile(r"\.Map(?!Controllers|ControllerRoute|DefaultControllerRoute|AreaControllerRoute"
                      r"|RazorPages|When)[A-Z]\w*\s*[(<]|\.Map\(\s*[$@]*\"")
_PAGE_DIRECTIVE = re.compile(r"\A\s*(?:@\*.*?\*@\s*)*@page\b", re.S)


def _read(path: Path) -> str:
    try:
        return read_source(path)
    except OSError:
        return ""


def _core_projects(target: Path) -> list[project.Project]:
    return [p for p in project.load_projects(target.resolve()) if p.profile == "netcore" and p.language == "cs"]


def detect_language(target_path: Path) -> bool:
    return bool(_core_projects(target_path))


def _owning(projects: list[project.Project], path: Path) -> project.Project | None:
    """The deepest real project directory holding path, else the loose project."""
    here = path.resolve()
    hits = [p for p in projects if p.path is not None and here.is_relative_to(p.dir.resolve())]
    if hits:
        return max(hits, key=lambda p: len(p.dir.resolve().parts))
    return next((p for p in projects if p.path is None), None)


def detect_frameworks(target_path: Path) -> list[str]:
    target = target_path.resolve()
    all_projects = project.load_projects(target)
    core = [p for p in all_projects if p.profile == "netcore" and p.language == "cs"]
    if not core:
        return []
    found = {"config"}
    for p in core:
        for f in p.compile_files:
            text = _read(f)
            if "Controller" in text and _CONTROLLER.search(text):
                found.add("controllers")
            if ".Map" in text and _MINIMAL.search(text):
                found.add("minimalapi")
    core_dirs = {id(p) for p in core}
    for f in iter_dnl_files(target, (".cshtml",)):
        if "razorpages" in found:
            break
        if "pages" not in {part.lower() for part in f.relative_to(target).parts[:-1]}:
            continue
        owner = _owning(all_projects, f)
        if owner is not None and id(owner) in core_dirs and _PAGE_DIRECTIVE.match(_read(f)):
            found.add("razorpages")
    return [f for f in _FRAMEWORK_ORDER if f in found]
