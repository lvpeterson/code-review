# Python: flask, fastapi, django

Route extraction uses the stdlib `ast` module (no dependency). Shared
decorator/call-parsing helpers live in `_ast_utils.py`.

## Detection

`detector.py` checks `requirements.txt`/`pyproject.toml`/`setup.py`/`Pipfile`
text (or falls back to per-file source scan) for `"django"`/`"fastapi"`/
`"flask"` substrings, or a `manage.py` file for Django specifically. More
than one can be detected in the same repo (a Flask app growing FastAPI
services alongside it mid-migration is a real pattern this is built to
handle, not an edge case).

**Flask/FastAPI decorator collision**: Flask 2.x's shortcut decorators
(`@app.get(...)`, `@app.post(...)`) are syntactically identical to
FastAPI's. `_app_index.py` builds a project-wide index of which framework
each variable name (`app`, a `Blueprint`, an `APIRouter`, ...) was actually
constructed as, and each analyzer vetoes a match only when it can prove the
object belongs to the *other* framework. An unresolved name (most commonly:
`app` built in one module, imported into the blueprint/router modules that
decorate routes on it) is claimed by **both** analyzers rather than
neither -- under-reporting is worse than an occasional duplicate for a
triage tool, so expect ambiguous cases to sometimes show up in both
sections.

**`unittest.mock.patch` collision**: `@patch(...)`/`@mock.patch(...)`
(constant in test files) parses to a decorator literally named `patch`,
identical to `@app.patch(...)`. `mock_import_names()` tracks what a file
imports from `unittest.mock` so both Flask and FastAPI exclude it before
ever treating it as a route.

## Flask

- **Routes**: `@app.route(path, methods=[...])` (default `["GET"]`) and the
  2.x shortcuts `@app.get`/`@app.post`/`@app.put`/`@app.patch`/`@app.delete`
  (fixed method, ignores any `methods=`). Blueprint routes work the same way.
- **Blueprint prefix**: `Blueprint(..., url_prefix=...)` and/or
  `app.register_blueprint(bp, url_prefix=...)` -- the `register_blueprint`
  kwarg wins if both are present, matching real Flask precedence.
- **Auth**: `auth_decorators` = every *other* stacked decorator's name (not
  pre-filtered against known indicators at capture time). `KNOWN_AUTH_INDICATORS
  = {login_required, jwt_required, auth_required, permission_required, roles_required}`.
- **Global auth**: a `@before_request`-decorated function is treated as
  global auth if its body text contains `abort(401`/`abort(403`/
  `current_user.is_authenticated`/`g.user`/`unauthorized`/`Unauthorized`, or
  any known indicator -- a presence-only text scan, not real analysis.
- **CONFIG-001 (debug mode)**: `<x>.run(debug=True)` or `<x>.debug = True`,
  matched on the trailing attribute name so any object works.
- **extra_param_names**: `request.args/form/json.get(...)` via the shared
  `core/bodyscan.py` regex scan.

## FastAPI

- **Routes**: `@<obj>.get/post/put/patch/delete/options/head(path)`.
- **Router mounts**: `parent.include_router(child, prefix=...)`, resolved
  through the full chain (a router mounted into a router mounted into the
  app) via the shared `core/paths.py:resolve_mount_prefix()`.
- **Auth**: FastAPI's idiom is `Depends(x)` as a parameter default, not a
  stacked decorator -- `auth_decorators` is built from every `Depends(...)`
  default's callable name. `KNOWN_AUTH_INDICATORS = {get_current_user,
  require_auth, verify_token, oauth2_scheme, get_current_active_user}`.
- **Global auth**: `dependencies=[Depends(x), ...]` on the `FastAPI(...)`/
  `APIRouter(...)` constructor -- structural, not text-sniffed.
- **extra_param_names**: every function parameter that isn't a path param
  and doesn't have a `Depends(...)` default -- precise, since FastAPI binds
  query/body params directly as typed parameters.
- **No CONFIG checks implemented** (no debug-mode or CORS-wildcard check for
  FastAPI specifically).

## Django

- **Two-pass resolution**: pass 1 walks every `urls.py`'s `path`/`re_path`/
  `url` calls; pass 2 resolves each view reference to its real definition in
  whatever file actually declares it (function, class-based view, or
  `Class.as_view()`) -- mirrors Express's cross-file handler index, but for
  routing-file-to-view-file specifically. `source_file`/`source_start_line`/
  `source_end_line` point at the *view's* file, not `urls.py`.
- **Auth**: decorator names, class base-class names (e.g.
  `LoginRequiredMixin`), and a class-level `permission_classes = [...]`
  assignment (adds the literal token `"permission_classes"`) all merge into
  `auth_decorators`. `KNOWN_AUTH_INDICATORS = {login_required,
  permission_required, staff_member_required, LoginRequiredMixin,
  IsAuthenticated, permission_classes}`.
- **Global auth**: `REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]` in any
  `settings.py`, if not `AllowAny`.
- **CONFIG-001 (debug mode)**: `DEBUG = True` in a file named `settings.py`.
- **extra_param_names**: `request.GET/POST/data.get(...)` via `core/bodyscan.py`.
- **Known gap**: `methods` is **hardcoded to `["GET", "POST"]"` for every
  route** -- not derived from the actual view logic, so AUTH-001's
  sensitive-method severity scoring is only ever approximate here, never
  refined per-view.

## What still needs a human

- **No ownership-check tracing anywhere** (true for every language here) --
  IDOR-001 only flags an id-like param exists, never whether the handler/
  view actually checks the caller owns the referenced object.
- **Global-auth findings are presence-only** -- confirm the mechanism
  actually covers the *specific* route you're looking at; none of these
  three do real path-matching simulation the way Spring's matcher-chain
  resolution does (see `languages/java/README.md`).
- **Flask/FastAPI**: no CSRF check, no SQL-injection check, no command/path/
  SSRF injection checks -- none of the dangerous-sink checks built for
  Spring this session exist yet for Python. If a Flask/FastAPI/Django app
  uses raw SQL (`cursor.execute(f"... {var}")`, string-built ORM `.raw()`/
  `.extra()` calls), that's entirely unchecked -- trace it by hand.
- **Django-specific**: no CSRF check (`@csrf_protect`/`csrf_exempt`
  presence), no check for `.raw()`/`.extra()` unsanitized SQL, `methods`
  being hardcoded means don't fully trust AUTH-001 severity here -- verify
  the view's actual HTTP-method handling yourself.
- **`auth_decorators` isn't filtered to known indicators at capture time**
  for Flask/FastAPI (Django and Spring do filter) -- the HTML report's
  per-route auth line can show an unrelated decorator (a caching one, say)
  on an actually-unprotected route. Harmless to AUTH-001 itself (it only
  reacts to *absence* of a known indicator), just a cosmetic thing to be
  aware of when reading the report.
- **No framework-version detection** (CONFIG-003 equivalent) for any of the
  three -- an outdated Flask/FastAPI/Django pinned in `requirements.txt` is
  not flagged; check manually.
