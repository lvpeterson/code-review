"""Unsafe deserialization heuristics.

Jackson's default typing, or an unrestricted @JsonTypeInfo(use =
Id.CLASS/MINIMAL_CLASS), lets a JSON payload's own embedded type metadata
pick which Java class gets instantiated during deserialization -- a
well-known RCE-class bug (Java deserialization gadget chains), distinct
from and more severe than anything the validation checks elsewhere in this
tool cover. These only flag the presence of the dangerous configuration;
they can't verify a gadget chain actually exists on the classpath, just
that the door is open if one does.
"""
from __future__ import annotations

from core.models import Finding


def default_typing_finding(file: str, line: int) -> Finding:
    return Finding(
        check_id="DESER-001",
        severity="high",
        title="Jackson default typing enabled",
        description=(
            "Found `.activateDefaultTyping(...)`/`.enableDefaultTyping(...)` on an "
            "ObjectMapper. This lets a JSON payload's own embedded type metadata decide "
            "which Java class gets instantiated during deserialization -- if any class "
            "reachable on the classpath can be chained into a gadget (a well-documented, "
            "actively-exploited category, most often via common logging/collections "
            "libraries), this is remote code execution, not just a data validation gap. "
            "Prefer explicit, allowlisted polymorphism (@JsonTypeInfo paired with a "
            "fixed @JsonSubTypes registry) instead."
        ),
        file=file,
        line=line,
        route=None,
    )


def json_type_info_finding(file: str, line: int, use_value: str) -> Finding:
    return Finding(
        check_id="DESER-001",
        severity="medium",
        title=f"@JsonTypeInfo uses unrestricted class-based typing ({use_value})",
        description=(
            f"`@JsonTypeInfo(use = JsonTypeInfo.Id.{use_value})` resolves the target "
            "class directly from a field in the incoming JSON, rather than through a "
            "fixed @JsonSubTypes allowlist. If this type is ever deserialized from "
            "untrusted input, an attacker can name any class on the classpath -- check "
            "whether this is paired with @JsonSubTypes restricting the actual allowed "
            "types, and whether this type ever reaches deserialization from a public "
            "endpoint."
        ),
        file=file,
        line=line,
        route=None,
    )
