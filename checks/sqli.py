"""SQL injection via string concatenation.

Everything covered elsewhere in this tool about parameterized queries
(`:name` bind parameters going to the database as data, never as SQL
syntax) has an unspoken assumption: that the query text itself is a fixed
string. This check flags the moment that assumption breaks -- a query
string built by concatenating a value directly into it with `+`, passed to
one of JPA/JDBC's query-execution APIs. Deliberately narrower than the
other dangerous-sink checks (CMD-001/PATH-001/SSRF-001), which flag *any*
non-literal argument: a plain variable holding a fixed, already-
parameterized query string (`String sql = "... WHERE x = :val"`) is
exactly the safe pattern and must not be flagged, so only a direct `+`
concatenation at the call site counts. That also means concatenation done
in an earlier statement, then passed in as a variable, isn't caught here --
this tool doesn't trace data flow across statements.
"""
from __future__ import annotations

from core.models import Finding

# The natural way to dismiss this is "I traced every route and none of them
# reach this" -- true as far as it goes, but a route-only trace misses two
# real paths in: a non-route entry point (a @Scheduled job, a
# @KafkaListener/@RabbitListener/@JmsListener, a WebSocket @MessageMapping)
# that never appears in any route trace at all, and indirect reachability
# through persisted data (a route writes a value that this code reads back
# out later, with no direct call chain for a route trace to follow). Neither
# is something this tool can verify -- both need a human to actually check.
_TRACE_REMINDER = (
    " When tracing this by hand, a route-only trace can under-clear it: also check "
    "whether it's reachable from a non-route entry point (a @Scheduled job, a message "
    "listener, a WebSocket handler) or indirectly, via data a route wrote earlier "
    "(a DB field, a cache) that this code reads back out."
)


def sql_concatenation_finding(file: str, line: int, api: str) -> Finding:
    return Finding(
        check_id="SQLI-001",
        severity="high",
        title=f"SQL/JPQL built via string concatenation ({api})",
        description=(
            f"{api} was called with a query string built using `+` concatenation, not "
            "a fixed template with bind parameters. If any concatenated part comes from "
            "request input, this is SQL injection -- the value becomes indistinguishable "
            "from query syntax, the same failure mode a `:namedParam` bind parameter "
            "exists specifically to prevent. Replace the concatenation with a named/"
            "positional bind parameter and pass the value separately. Note: this only "
            "catches concatenation happening directly in the call's argument -- "
            "concatenation done in an earlier statement and passed in via a variable "
            "isn't traced." + _TRACE_REMINDER
        ),
        file=file,
        line=line,
        route=None,
    )
