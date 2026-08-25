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
