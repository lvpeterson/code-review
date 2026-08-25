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
    language (e.g. a Python backend + a JS frontend), and more than one
    framework within a language (e.g. a Flask app growing FastAPI services
    alongside it) -- all matches run, each as its own ScanResult.
    """
    results: list[ScanResult] = []

    if force_language:
        module = LANGUAGE_MODULES.get(force_language)
        if module is None:
            raise ValueError(f"Unknown --language '{force_language}'. Known: {', '.join(LANGUAGE_MODULES)}")
        frameworks = [force_framework] if force_framework else module.detector.detect_frameworks(target_path)
        _run_frameworks(target_path, force_language, frameworks, results)
        return results

    for language_name, module in LANGUAGE_MODULES.items():
        if not module.detector.detect_language(target_path):
            continue
        frameworks = module.detector.detect_frameworks(target_path)
        _run_frameworks(target_path, language_name, frameworks, results)

    return results


def _run_frameworks(target_path: Path, language_name: str, frameworks: list[str], results: list[ScanResult]) -> None:
    if not frameworks:
        print(f"[{language_name}] language detected but no known framework matched -- skipping deep-dive")
        return

    for framework in frameworks:
        analyzer_cls = get_analyzer(language_name, framework)
        if analyzer_cls is None:
            print(f"[{language_name}/{framework}] detected but no analyzer registered yet")
            continue

        analyzer = analyzer_cls(target_path)
        results.append(analyzer.analyze())
