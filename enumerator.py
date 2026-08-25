"""Top-level enumeration: figure out what languages/frameworks a target
uses, and dispatch to the matching deep-dive analyzer for each.
"""
from __future__ import annotations

from pathlib import Path

import languages  # noqa: F401  (import triggers analyzer registration)
from core.models import ScanResult
from core.registry import get_analyzer
from languages import dotnet, go, java, javascript, python, ruby

# Maps a language name to its package (which exposes .detector).
# Add an entry here whenever you add a new languages/<name>/ package.
LANGUAGE_MODULES = {
    "python": python,
    "java": java,
    "javascript": javascript,
    "go": go,
    "ruby": ruby,
    "dotnet": dotnet,
}


def enumerate_target(
    target_path: Path,
    force_language: str | None = None,
    force_framework: str | None = None,
) -> list[ScanResult]:
    """Detect language(s)/framework(s) present in target_path and run the
    matching deep-dive analyzer for each. A codebase can trip more than one
    language (e.g. a Python backend + a JS frontend) -- all matches run.
    """
    results: list[ScanResult] = []

    if force_language:
        module = LANGUAGE_MODULES.get(force_language)
        if module is None:
            raise ValueError(f"Unknown --language '{force_language}'. Known: {', '.join(LANGUAGE_MODULES)}")
        framework = force_framework or module.detector.detect_framework(target_path)
        _run_one(target_path, force_language, framework, results)
        return results

    for language_name, module in LANGUAGE_MODULES.items():
        if not module.detector.detect_language(target_path):
            continue
        framework = module.detector.detect_framework(target_path)
        _run_one(target_path, language_name, framework, results)

    return results


def _run_one(target_path: Path, language_name: str, framework: str | None, results: list[ScanResult]) -> None:
    if framework is None:
        print(f"[{language_name}] language detected but no known framework matched -- skipping deep-dive")
        return

    analyzer_cls = get_analyzer(language_name, framework)
    if analyzer_cls is None:
        print(f"[{language_name}/{framework}] detected but no analyzer registered yet")
        return

    analyzer = analyzer_cls(target_path)
    results.append(analyzer.analyze())
