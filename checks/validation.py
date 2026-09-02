"""Bean Validation (JSR 380) coverage heuristics.

Spring has two separate, easy-to-half-wire validation mechanisms, and both
fail the same way -- constraint annotations sitting in the source that are
never actually run at request time:

- @PathVariable/@RequestParam constraints (@NotBlank, @Digits, @Min, ...)
  only run when the containing controller is itself annotated @Validated,
  which wires in the AOP interceptor that runs the validator. Without it,
  the annotations are inert. See `check_validation_without_class_annotation`.
- @RequestBody DTO field constraints only run when the parameter itself is
  annotated @Valid (or @Validated) -- that's the separate trigger that
  cascades Bean Validation into the object's own fields. Without it, the
  DTO's constraints (declared elsewhere, on the DTO class) never run. See
  `check_request_body_without_valid`.

Both operate purely on fields the Spring analyzer populates on `Route`
(`param_validations`/`class_validated` and `request_body_validations`).
"""
from __future__ import annotations

from core.models import Finding, Route


def check_validation_without_class_annotation(routes: list[Route]) -> list[Finding]:
    findings: list[Finding] = []
    for route in routes:
        constrained = sorted(name for name, anns in route.param_validations.items() if anns)
        if not constrained or route.class_validated:
            continue

        findings.append(
            Finding(
                check_id="VALID-001",
                severity="medium",
                title=f"Constraint annotation(s) on {', '.join(constrained)} are not enforced -- controller isn't @Validated",
                description=(
                    "Spring only runs method-parameter constraint validation "
                    "(@PathVariable/@RequestParam annotations like @NotBlank, @Digits, "
                    "@Pattern, @Min/@Max) when the controller class itself carries "
                    "@Validated. Without it, these constraints are silently never "
                    "checked at runtime -- add @Validated at the class level, or treat "
                    "this input as unvalidated."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings


def check_request_body_without_valid(routes: list[Route]) -> list[Finding]:
    findings: list[Finding] = []
    for route in routes:
        unvalidated = sorted(name for name, has_valid in route.request_body_validations.items() if not has_valid)
        if not unvalidated:
            continue

        findings.append(
            Finding(
                check_id="VALID-002",
                severity="medium",
                title=f"@RequestBody param(s) {', '.join(unvalidated)} missing @Valid -- field constraints not enforced",
                description=(
                    "Spring only cascades Bean Validation into a @RequestBody object's "
                    "own field-level constraints (@NotBlank, @Size, @Email, ...) when "
                    "the parameter itself is annotated @Valid (or @Validated). Without "
                    "it, whatever constraints the DTO class declares are silently never "
                    "checked -- add @Valid to the parameter, or treat this body as "
                    "unvalidated."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
