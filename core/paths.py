"""Route-path parameter extraction, shared by the IDOR heuristic
(checks/idor.py) and the HTML report's parameter highlighting -- both need
"what are ALL the parameter names in this route's path", just for different
purposes (one filters them down to id-like ones, the other doesn't).
"""
from __future__ import annotations

import re

# Path parameter syntax across the frameworks we support:
#   Flask/Django   <int:user_id>  or  <user_id>   (converter prefix optional)
#   FastAPI/Spring {item_id}
#   Express        :orderId
# Kept as separate alternatives (not one loose `[:{<]...[}>]?` pattern) so a
# Flask converter prefix like `<uuid:record_uuid>` doesn't get double-counted
# as two separate params ("uuid" and "record_uuid").
_PARAM_NAME_PATTERN = re.compile(
    r"<(?:[a-zA-Z_][a-zA-Z0-9_]*:)?([a-zA-Z_][a-zA-Z0-9_]*)>"
    r"|\{([a-zA-Z_][a-zA-Z0-9_]*)\}"
    r"|:([a-zA-Z_][a-zA-Z0-9_]*)"
)


def extract_path_param_names(path: str) -> list[str]:
    """Every parameter name in a route path, in the order they appear.
    Doesn't dedupe -- a path repeating the same name twice (rare, but
    possible in a nested resource path) yields it twice.
    """
    names = []
    for m in _PARAM_NAME_PATTERN.finditer(path):
        names.append(m.group(1) or m.group(2) or m.group(3))
    return names


def join_path_segments(*segments: str) -> str:
    """Join route-path segments (a mount prefix chain + the route's own
    sub-path) into one normalized path, regardless of which segments do or
    don't have leading/trailing slashes.
    """
    parts = [s.strip("/") for s in segments if s and s.strip("/")]
    return "/" + "/".join(parts) if parts else "/"


def resolve_mount_prefix(base_name: str, mounts: dict[str, tuple[str, str]]) -> str:
    """Walk a chain of `child -> (parent, prefix)` mount records (built by
    each analyzer from its own framework's "include this router/blueprint
    under this prefix" call) starting at `base_name`, and return the full
    accumulated prefix -- root-most segment first.

    Shared because FastAPI (`include_router`), Express
    (`app.use(path, router)`), and Flask (`register_blueprint`/`Blueprint`)
    all have the same shape of problem even though the call that produces
    the mount looks different in each.
    """
    prefix_parts = []
    current = base_name
    seen = set()
    while current in mounts and current not in seen:
        seen.add(current)
        parent, prefix = mounts[current]
        prefix_parts.append(prefix)
        current = parent
    return join_path_segments(*reversed(prefix_parts))
