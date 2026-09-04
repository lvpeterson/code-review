# Ruby: rails, sinatra

Route extraction uses `tree-sitter-ruby`. `_ts_utils.py` is the same
node-text/walk-helper pattern duplicated per language (not shared).

## Detection

`detector.py`: `Gemfile` text containing `"rails"`, or a `config/routes.rb`
file's mere existence → rails. `Gemfile` text containing `"sinatra"` →
sinatra. Both can be detected in the same repo. Unlike Python/JS, there's
**no per-file source-scan fallback** here -- detection is purely
Gemfile/routes.rb presence based.

## Rails -- explicitly a "v1" scope, read this carefully

The module docstring says it directly: **routes are not resolved to their
controller#action source.** Every other analyzer in this tool that can
(Django, Express, gin, net/http) resolves a route registration to the
actual function/method that handles it, wherever it's defined. Rails
doesn't yet -- every route reports only its `routes.rb` registration line,
never `app/controllers/orders_controller.rb`'s `show` method itself. This
has a real, cascading consequence: **because the controller body is never
looked at, Rails routes currently get no per-route auth detection and no
query/body param extraction at all** -- only the global `before_action`
check (below) and path-param IDOR-001 apply. A route protected by a
per-action `before_action :require_admin, only: [:destroy]` filter, or one
with an obvious IDOR via a body/query param, is invisible to this tool
today.

- **Routing DSL**, walked inside `Rails.application.routes.draw do ... end`:
  - `get`/`post`/`put`/`patch`/`delete path, to: 'controller#action'` --
    named routes; falls back to the bare method name as the handler if no
    `to:` is given.
  - `resources :name` expands to the 7 canonical RESTful routes
    (index/new/create/show/edit/update/destroy) with `<resource>#<action>`
    handler names. Note: only emits `PATCH :id → update`, not the `PUT`
    alias Rails itself also generates for the same route.
  - `namespace`/`scope` blocks recurse arbitrarily deep, accumulating a
    path-prefix stack (`namespace :api do resources :orders end` → `/api/orders`).
- **Auth**: `KNOWN_AUTH_INDICATORS = {authenticate_user!, authenticate!,
  require_login, login_required}`.
- **Global auth**: a `before_action` call in
  `app/controllers/application_controller.rb` whose argument text contains
  a known indicator -- models the fact that every controller inherits from
  `ApplicationController` by default, so a `before_action` there cascades
  app-wide (a `skip_before_action` override elsewhere is **not** checked
  for, so this can over-claim coverage on routes that opted out).
- **No CONFIG checks** -- no debug-mode equivalent (`config.consider_all_requests_local`) implemented.

## Sinatra -- the thinnest analyzer in this tool

- **Routes**: `get`/`post`/`put`/`patch`/`delete path do ... end` -- the
  block *is* the handler (no separate function to resolve, so
  `source_file`/`source_start_line`/`source_end_line` are set directly from
  the block's own range). `handler_name` is synthesized as `"get
  '/users/:id'"` since Sinatra routes have no real function name.
- **Auth**: a plain substring match (not even requiring a trailing `(`) of
  each `KNOWN_AUTH_INDICATORS = {authenticate!, require_login, authorize!,
  protected!}` string against the block's text.
- **No global-auth detection at all** -- Sinatra has no
  `ApplicationController`-style base-class inheritance model, so there's no
  equivalent mechanism to check for.
- **No `extra_param_names`** -- `core/bodyscan.py` isn't used, so only
  path-param IDOR-001 ever fires, never the query/body variant.
- **No CONFIG checks.**
- No TODOs in source -- this is presented as essentially complete for its
  intentionally minimal scope, not a stub awaiting more work.

## What still needs a human

- **Rails is the biggest gap in this whole tool for any language**: because
  controller bodies are never resolved, assume **every Rails route needs a
  full manual check** for per-action auth (`before_action` filters scoped
  to specific actions, `skip_before_action` overrides) and for IDOR via
  query/body params (`params[:user_id]` used directly) -- this tool can't
  see either right now. Path-param IDOR-001 and the global
  `ApplicationController` auth note are the only signal you get.
- **Sinatra**: no global-auth check means if auth is enforced via Rack
  middleware (`use Rack::Auth::Basic` or a custom middleware class) rather
  than in-block calls, **every route will be flagged** with no caveat
  attached -- verify the middleware stack (`config.ru`) by hand before
  trusting AUTH-001 findings at face value.
- **Ownership-check tracing** -- IDOR-001 (where it fires at all) only
  flags the id-like param exists, never whether an ownership check happens.
- **No SQL/command/path/SSRF injection checks** for either -- trace
  string-interpolated `ActiveRecord::Base.connection.execute("... #{x}")`,
  `.where("... #{x}")`, `` `...` ``/`system(...)`, `File.open(userPath)`,
  `Net::HTTP.get(userUrl)` patterns by hand.
- **No CSRF check** for either, despite Rails having `protect_from_forgery`
  as a real, checkable mechanism -- not built yet.
- **No framework-version detection** -- an outdated `rails`/`sinatra` gem
  pinned in the `Gemfile` isn't flagged.
