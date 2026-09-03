"""Dangerous-sink heuristics for command injection, path traversal, and
SSRF -- three distinct injection classes, each flagging a specific,
well-known-dangerous Java API used with an argument that isn't a fixed
string literal (a rough "this might carry attacker input" proxy, not a
real taint trace -- a non-literal argument might still just be a
hardcoded constant, not attacker-controlled). None of these verify the
argument's value actually originates from request input; they flag the
sink so a human can trace it, same philosophy as every other heuristic in
this tool.
"""
from __future__ import annotations

from core.models import Finding


def command_injection_sink_finding(file: str, line: int) -> Finding:
    return Finding(
        check_id="CMD-001",
        severity="medium",
        title="Command execution API in use",
        description=(
            "Found Runtime.exec(...)/new ProcessBuilder(...). If any part of the "
            "command (or its arguments) is built from request input, this is command "
            "injection -- trace where the command string/argument list actually comes "
            "from. Presence-only: this doesn't verify user input reaches it, or that "
            "it's exploitable if it does."
        ),
        file=file,
        line=line,
        route=None,
    )


def path_traversal_sink_finding(file: str, line: int, api: str) -> Finding:
    return Finding(
        check_id="PATH-001",
        severity="low",
        title=f"File path constructed with a non-literal argument ({api})",
        description=(
            f"{api} was called with an argument that isn't a fixed string literal. If "
            "that value ever comes from request input without validating against `../` "
            "traversal or normalizing/allowlisting the resulting path, this can read or "
            "write files outside the intended directory. A non-literal argument might "
            "just be a hardcoded constant, not attacker-controlled -- trace it before "
            "treating this as a real gap."
        ),
        file=file,
        line=line,
        route=None,
    )


def ssrf_sink_finding(file: str, line: int, api: str) -> Finding:
    return Finding(
        check_id="SSRF-001",
        severity="low",
        title=f"Outbound HTTP call with a non-literal URL ({api})",
        description=(
            f"{api} was called with a non-literal URL argument. If that URL (or its "
            "host/path) comes from request input, an attacker can direct this server to "
            "make requests to internal-only services, cloud metadata endpoints, or "
            "arbitrary external hosts (SSRF). Only RestTemplate's own methods and raw "
            "URL/URI construction are detected here -- WebClient's fluent `.uri(...)` "
            "isn't, since that method name is too generic to detect without a lot of "
            "false positives."
        ),
        file=file,
        line=line,
        route=None,
    )
