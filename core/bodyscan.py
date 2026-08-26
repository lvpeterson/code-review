"""Best-effort request-field-usage scan over a handler's raw source text --
catches an id-like value read from a query string or request body/form,
which `core/paths.py:extract_path_param_names()` can't see since those
never appear in the route path itself.

Regex over raw text, not AST -- deliberately shallow (same spirit as the
rest of checks/idor.py): this is a presence signal for a human to look at,
not a claim about what the code actually does with the value afterward.
"""
from __future__ import annotations

import re

# Flask:   request.args.get('x') / request.args['x'] / request.form.get('x')
#          / request.form['x'] / request.json.get('x') / request.json['x']
# Django:  request.GET.get('x') / request.GET['x'] / request.POST.get('x')
#          / request.POST['x'] / request.data.get('x')  (DRF)
# Express: req.query.x / req.query['x'] / req.body.x / req.body['x']
# Next.js: (App Router) request.nextUrl.searchParams.get('x') / a locally
#          destructured searchParams.get('x'); Pages Router handlers use the
#          same req.query/req.body shape as Express, already covered above.
# Go:      net/http `r.URL.Query().Get("x")`; gin `c.Query("x")` (query
#          string), `c.PostForm("x")` (form body).
_ACCESSOR_PATTERN = re.compile(
    r"request\.(?:args|form|json|GET|POST|data)\.get\(\s*['\"](\w+)['\"]"
    r"|request\.(?:args|form|json|GET|POST|data)\[['\"](\w+)['\"]\]"
    r"|req\.(?:query|body)\.(\w+)"
    r"|req\.(?:query|body)\[['\"](\w+)['\"]\]"
    r"|searchParams\.get\(\s*['\"](\w+)['\"]"
    r"|\.URL\.Query\(\)\.Get\(\s*['\"](\w+)['\"]"
    r"|\.(?:Query|PostForm)\(\s*['\"](\w+)['\"]"
)


def extract_request_field_names(body_text: str) -> list[str]:
    """Every field name read off a request/req object in this text."""
    names = []
    for m in _ACCESSOR_PATTERN.finditer(body_text):
        name = next((g for g in m.groups() if g), None)
        if name:
            names.append(name)
    return names
