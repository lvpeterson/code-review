"""Bean Validation (JSR 380) coverage heuristics.

Spring has two separate, easy-to-half-wire validation mechanisms, and both
fail the same way -- constraint annotations sitting in the source that are
never actually run at request time:

- A constraint annotation declared directly on a parameter (@NotBlank on a
  @PathVariable, @Digits on a @RequestParam, or even @NotNull directly on a
  @RequestBody param like `@RequestBody @NotNull List<String> items`) only
  runs when the containing controller is itself annotated @Validated, which
  wires in the AOP interceptor (Bean Validation's ExecutableValidator) that
  actually runs it. Without it, the annotation is inert. See
  `check_validation_without_class_annotation`.
- A @RequestBody parameter's *own type* having field-level constraints
  (e.g. an OrderDto whose `email` field carries @Email) only gets validated
  when the parameter itself is annotated @Valid (or @Validated) -- that's
  the separate cascade trigger Bean Validation needs to descend into an
  object's fields, and it's independent of class-level @Validated: neither
  Spring's own @RequestBody deserialization path nor the AOP interceptor
  cascades into a referenced type's fields without it. See
  `check_request_body_without_valid`.

These are genuinely orthogonal: a @RequestBody parameter can have its own
direct constraint enforced (class-level @Validated, no @Valid needed) while
its type's internal field constraints remain completely unchecked (no
@Valid present) -- both facts can be true on the very same parameter.

Both checks operate purely on fields the Spring analyzer populates on
`Route` (`param_validations`/`class_validated` and
`request_body_validations`).
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
                    "Spring only runs method-parameter constraint validation -- a "
                    "constraint annotation (@NotBlank, @Digits, @Pattern, @Min/@Max, "
                    "...) declared directly on a @PathVariable, @RequestParam, or even "
                    "a @RequestBody parameter itself -- when the controller class "
                    "carries @Validated. Without it, these constraints are silently "
                    "never checked at runtime -- add @Validated at the class level, or "
                    "treat this input as unvalidated."
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
                title=f"@RequestBody param(s) {', '.join(unvalidated)} missing @Valid -- can't cascade into field constraints",
                description=(
                    "Bean Validation only cascades into a @RequestBody parameter's own "
                    "type -- checking whatever @NotBlank/@Size/@Email/etc constraints "
                    "that type's fields declare -- when the parameter itself is "
                    "annotated @Valid (or @Validated). This is unrelated to a "
                    "class-level @Validated on the controller: that only covers "
                    "constraint annotations sitting directly on a parameter (see "
                    "VALID-001), it never cascades into a parameter's own type "
                    "regardless. If this parameter's type declares field-level "
                    "constraints of its own, they are silently never checked without "
                    "@Valid here -- add it, or confirm the type has nothing to cascade "
                    "into."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
