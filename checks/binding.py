"""Request-binding shape heuristics: what a route's declared parameter
types themselves expose, independent of whether any value in them is
actually validated.
"""
from __future__ import annotations

from core.models import Finding, Route


def check_mass_assignment(routes: list[Route], entity_class_names: set[str]) -> list[Finding]:
    """Flag @RequestBody parameters whose type is itself a JPA @Entity
    rather than a dedicated DTO -- a client can then set any field the
    entity has, not just the ones the API intends to accept.
    """
    findings: list[Finding] = []
    for route in routes:
        exposed = sorted(
            name for name, type_name in route.request_body_param_types.items()
            if type_name in entity_class_names
        )
        if not exposed:
            continue

        findings.append(
            Finding(
                check_id="MASS-001",
                severity="medium",
                title=f"@RequestBody param(s) {', '.join(exposed)} bind directly to a JPA entity",
                description=(
                    "This parameter's type is annotated @Entity elsewhere in the "
                    "codebase -- binding a JSON request body directly to a persistence "
                    "entity (rather than a dedicated DTO) means a client can set any "
                    "field the entity has, not just the ones this API intends to "
                    "accept (mass assignment / over-posting). A field like an "
                    "ownership flag, a role, or an internal status that's never meant "
                    "to be client-writable is exposed the moment it exists on this "
                    "entity, with no code change needed to expose it. Prefer a "
                    "dedicated request DTO with only the fields this endpoint should "
                    "accept."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings


def check_unallowlisted_sort(routes: list[Route]) -> list[Finding]:
    """Flag routes accepting Spring Data's Pageable/Sort -- both let a
    client control an ORDER BY column via a query parameter directly.
    """
    findings: list[Finding] = []
    for route in routes:
        if not route.accepts_pageable_or_sort:
            continue

        findings.append(
            Finding(
                check_id="SORT-001",
                severity="info",
                title="Route accepts Pageable/Sort -- verify sortable fields are allowlisted",
                description=(
                    "Spring Data's Pageable/Sort binding lets a client control an ORDER "
                    "BY column directly via a query parameter (e.g. ?sort=fieldName). "
                    "If that reaches a query without restricting which fields are "
                    "actually sortable, the client is controlling query structure, not "
                    "just a value -- the same structure-vs-data distinction that makes "
                    "parameterized query values safe doesn't apply to column/field "
                    "names. Verify the repository method or query allowlists sortable "
                    "fields rather than passing Sort straight through unchecked."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
