"""Shared data models passed between detectors, analyzers, and checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Route:
    """A single route/endpoint discovered in the target codebase."""

    path: str
    methods: list[str]
    handler_name: str
    file: str
    line: int
    auth_decorators: list[str] = field(default_factory=list)
    raw_snippet: str = ""

    # Freeform bucket for framework-specific extras (e.g. Spring class-level
    # @RequestMapping prefix, Django view class name, etc). Deep-dive
    # analyzers can stash whatever they need here without changing the schema.
    meta: dict = field(default_factory=dict)


@dataclass
class Finding:
    """A baseline observation surfaced for manual auditor triage.

    These are NOT confirmed vulnerabilities -- they are heuristic pointers
    ("this route takes an id-like param and has no visible auth decorator")
    meant to help a human reviewer prioritize where to look first.
    """

    check_id: str
    severity: str  # info | low | medium | high
    title: str
    description: str
    file: str
    line: int
    route: Optional[Route] = None


@dataclass
class ScanResult:
    """Output of one analyzer run against the target."""

    language: str
    framework: str
    routes: list[Route] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
