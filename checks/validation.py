"""Bean Validation (JSR 380) coverage heuristics.

Spring only enforces @PathVariable/@RequestParam constraint annotations
(@NotBlank, @Digits, @Min, @Pattern, ...) when the containing controller is
itself annotated @Validated -- that annotation is what wires in the AOP
interceptor that actually runs the validator and turns a violation into a
400. Without it, those per-parameter constraint annotations are silently
inert: present in the source, never enforced at runtime. This module flags
that specific gap. It operates purely on `Route.param_validations` /
`Route.class_validated`, which today only the Spring analyzer populates.
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
