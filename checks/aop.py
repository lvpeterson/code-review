"""AOP proxy self-invocation bypass.

Spring enforces method-level annotations like @PreAuthorize/@Secured/
@Transactional through a dynamic proxy wrapping the bean -- the annotation
is only evaluated when the call comes in *through that proxy*. Calling an
annotated method from another method in the *same class* (a bare
`method()` or `this.method()`) never goes through the proxy at all, since
`this` inside the bean refers to the raw, unproxied object. The annotation
is silently never evaluated for that call path -- no error, no log, it
just doesn't run. This is the same "annotation present, enforcement
mechanism never wired up" shape as AUTH-002 (@PreAuthorize without
@EnableMethodSecurity) and VALID-002 (@RequestBody without @Valid), just
triggered by a call site instead of missing app-wide config.
"""
from __future__ import annotations

from core.models import Finding


def self_invocation_bypass_finding(file: str, line: int, severity: str, method_name: str, annotations: list[str]) -> Finding:
    anns = ", ".join(f"@{a}" for a in annotations)
    return Finding(
        check_id="PROXY-001",
        severity=severity,
        title=f"{method_name}() called from within its own class -- {anns} won't run",
        description=(
            f"Spring enforces {anns} through an AOP proxy wrapping this bean -- calling "
            f"{method_name}() from another method in the SAME class (a bare or `this.`-"
            "qualified call) bypasses that proxy entirely, since the call never goes back "
            "out through the proxy object to reach the interceptor. The annotation is not "
            "evaluated at all for this call path, silently. Route the call through a "
            "self-injected proxy (inject the bean's own interface/self-reference and call "
            "through that) or move the annotated method to a separate bean if it needs to "
            "be called this way."
        ),
        file=file,
        line=line,
        route=None,
    )
