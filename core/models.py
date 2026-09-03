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

    # An explicit, deliberate access declaration (JSR-250) -- "PermitAll"
    # (developer documented this route as intentionally public) or
    # "DenyAll" (documented as unreachable by anyone). Deliberately
    # separate from auth_decorators: these mean the opposite of a
    # protective control, so merging them in would render as if the route
    # were protected when @PermitAll is actually a developer confirming
    # it's exactly the kind of intentionally-public route AUTH-001 asks a
    # reviewer to check for -- flagging it anyway would be a false
    # positive against a route that's already been explicitly documented.
    # None when neither annotation is present, or the analyzer has no such
    # concept.
    explicit_access: Optional[str] = None

    # Best-effort names of query-string/body/form parameters the handler
    # reads (FastAPI: extra signature params; Spring: @RequestParam/
    # @RequestBody fields; Flask/Express/Django: request.args/request.json/
    # req.query/req.body accesses in the handler body). Path params are
    # tracked separately via `path` itself (core/paths.py extracts them) --
    # this exists so checks/idor.py can also catch an id-like value passed
    # via query string or JSON body, not just in the URL path.
    extra_param_names: list[str] = field(default_factory=list)

    # The actual code identifier bound to each path variable -- always a
    # valid identifier, unlike the URL segment name itself (`path`), which
    # can differ from it (e.g. Spring: a kebab-case URL segment like
    # `{order-id}` requires an explicit `@PathVariable("order-id") Long
    # orderId` binding, since Java identifiers can't contain hyphens). The
    # report's code-view highlighting needs this to find where the value is
    # actually used in the handler body -- the URL-side name never appears
    # there as a bare identifier, only inside the annotation's string
    # literal. Empty when an analyzer doesn't populate it or names never
    # diverge for that framework.
    path_variable_binding_names: list[str] = field(default_factory=list)

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

    # @RequestBody parameters, keyed by name, valued True if the parameter
    # itself carries @Valid/@Validated -- the separate trigger Spring needs
    # to cascade Bean Validation into the DTO's own field constraints
    # (unrelated to the class-level @Validated gate above, which only
    # governs @PathVariable/@RequestParam). Empty dict when the analyzer
    # doesn't populate it or the route has no @RequestBody param.
    request_body_validations: dict[str, bool] = field(default_factory=dict)

    # Simple type name for each @RequestBody parameter, keyed by name --
    # e.g. {"dto": "OrderItem"}. Used to cross-reference against classes
    # annotated @Entity elsewhere in the scan: binding a request body
    # directly to a persistence entity (instead of a dedicated DTO) means a
    # client can set any field the entity has, not just the ones the API
    # intends to accept (mass assignment / over-posting). Empty when the
    # analyzer doesn't populate it, the route has no @RequestBody param, or
    # the type couldn't be resolved to a simple name.
    request_body_param_types: dict[str, str] = field(default_factory=dict)

    # Whether any parameter's type is Spring Data's Pageable or Sort --
    # both let a client control which column an ORDER BY targets directly
    # via a query parameter. That's the client controlling query
    # *structure*, not just a value -- worth a nudge to verify sortable
    # fields are allowlisted before this reaches a query, the same
    # structure-vs-data distinction that makes bound query parameters safe
    # but doesn't extend to column/field names.
    accepts_pageable_or_sort: bool = False

    # Media type strings/constant-names on this route's produces/consumes
    # that look like XML (a literal like "application/xml", or a constant
    # name like Spring's own MediaType.APPLICATION_XML_VALUE) -- present so
    # a route that speaks XML can be flagged for an XXE (XML External
    # Entity) review, a distinct vulnerability class from anything else
    # tracked here. Empty when the analyzer doesn't populate it or no XML
    # type was declared. Best-effort: a codebase's own custom media-type
    # constants class won't be resolved by this (see checks/xml.py).
    xml_media_types: list[str] = field(default_factory=list)

    # Best-effort resolution of which rule in a global SecurityFilterChain's
    # authorizeHttpRequests()/authorizeRequests() matcher chain covers this
    # route's path -- e.g. "permitAll()" or "hasRole(ADMIN)" -- resolved by
    # walking the chain's ordered (pattern, rule) pairs the same way Spring
    # does (first matching pattern wins). None when no matcher rule was
    # found to cover this path (or the analyzer has no such concept), in
    # which case the route's auth coverage is still an open question.
    auth_matcher_verdict: Optional[str] = None


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
