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

    # Best-effort names of query-string/body/form parameters the handler
    # reads (FastAPI: extra signature params; Spring: @RequestParam/
    # @RequestBody fields; Flask/Express/Django: request.args/request.json/
    # req.query/req.body accesses in the handler body). Path params are
    # tracked separately via `path` itself (core/paths.py extracts them) --
    # this exists so checks/idor.py can also catch an id-like value passed
    # via query string or JSON body, not just in the URL path.
    extra_param_names: list[str] = field(default_factory=list)

    # Full source range of the handler implementation, for the HTML report's
    # expandable code view. `source_file` defaults to `file` when unset --
    # only set it when the handler lives elsewhere (e.g. Django's urls.py
    # registration vs. the view function's actual file in views.py).
    # Left as None when an analyzer couldn't resolve the handler's body
    # (e.g. an Express route passed a handler name it couldn't trace) --
    # the report then falls back to showing just the registration line.
    source_file: Optional[str] = None
    source_start_line: Optional[int] = None
    source_end_line: Optional[int] = None

    # Freeform bucket for framework-specific extras (e.g. Spring class-level
    # @RequestMapping prefix, Django view class name, etc). Deep-dive
    # analyzers can stash whatever they need here without changing the schema.
    meta: dict = field(default_factory=dict)

    # Bean Validation (JSR 380) constraint annotations found on each
    # @PathVariable/@RequestParam of the handler, keyed by param name --
    # e.g. {"orderId": ["Positive"], "email": []}. An empty list means the
    # param was seen but carries no recognized constraint annotation. Only
    # populated by analyzers that support per-parameter validation
    # annotations (currently just Spring); empty dict elsewhere.
    param_validations: dict[str, list[str]] = field(default_factory=dict)

    # Whether the containing class carries @Validated. Spring only enforces
    # @PathVariable/@RequestParam constraint annotations (@NotBlank,
    # @Digits, etc) when the controller itself is @Validated -- without it
    # those annotations are silently never checked. None when the analyzer
    # has no such concept (non-Spring frameworks).
    class_validated: Optional[bool] = None


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

    # Where a detected global auth mechanism (Flask before_request, a Spring
    # SecurityFilterChain bean, etc) actually lives, so the HTML report can
    # render a real "open in editor" link to it instead of just naming it in
    # text. None when no such mechanism was detected in this scan.
    global_auth_source: Optional[tuple[str, int, str]] = None  # (file, line, description)

    # Framework runtime version detected from the target's build file (e.g.
    # Spring Boot's version from pom.xml/build.gradle), so the HTML report
    # can flag an obviously outdated/EOL version. `framework_version_label`
    # distinguishes what was actually pinned (e.g. "Spring Boot" vs the bare
    # "Spring Framework"), since they have separate support timelines. None
    # when no build file / version declaration was found.
    framework_version: Optional[str] = None
    framework_version_label: Optional[str] = None
    framework_version_source: Optional[tuple[str, int, str]] = None  # (file, line, description)
