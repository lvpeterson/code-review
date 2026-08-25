"""Registry mapping (language, framework) -> analyzer class.

Each framework analyzer module registers itself via the @register decorator
at import time. enumerator.py imports languages/__init__.py, which imports
every language subpackage, which imports every analyzer module, so by the
time enumerate_target() runs, the registry is fully populated.
"""
from __future__ import annotations

from typing import Type

from core.base import BaseFrameworkAnalyzer

_REGISTRY: dict[tuple[str, str], Type[BaseFrameworkAnalyzer]] = {}


def register(language: str, framework: str):
    def decorator(cls: Type[BaseFrameworkAnalyzer]) -> Type[BaseFrameworkAnalyzer]:
        cls.language = language
        cls.framework = framework
        _REGISTRY[(language, framework)] = cls
        return cls

    return decorator


def get_analyzer(language: str, framework: str) -> Type[BaseFrameworkAnalyzer] | None:
    return _REGISTRY.get((language, framework))


def all_registered() -> list[tuple[str, str]]:
    return sorted(_REGISTRY.keys())
