# JavaScript/TypeScript: express, nextjs, hono

Route extraction uses `tree-sitter` with the `tree-sitter-javascript`/
`tree-sitter-typescript` grammars (prebuilt wheels -- no Node.js or compiler
needed to run this).

## Detection

`detector.py` reads `package.json`'s merged `dependencies`+`devDependencies`
for an `"express"` or `"next"` key, or a `next.config.{js,mjs,ts}` file
presence for Next.js. Hono is detected via either `"hono"` or
`"@hono/node-server"` in the same merged deps -- either alone is enough,
since Hono's own routing/middleware API (what this tool actually analyzes)
is identical regardless of which runtime adapter serves it (`@hono/
node-server`, Cloudflare Workers, Deno, Bun). Falls back to a
`require('express')`/`import ... from 'express'` (or the equivalent for
`'hono'`) source scan if no manifest signal is found (no equivalent
fallback for Next.js). TODO in source: NestJS/Koa/Hapi/Fastify aren't
detected at all yet.

## Express

- **Routes**: `<obj>.<verb>(path, ...)` where `obj` is literally named `app`
  or `router` (`_ROUTER_OBJECT_NAMES` -- **doesn't trace** `const foo =
  express.Router()` to catch arbitrary variable names) and `verb` is
  `get`/`post`/`put`/`patch`/`delete`/`all` (`all` maps to all five HTTP
  methods).
- **Router mounts**: `parent.use('/prefix', ...middleware, routerIdentifier)`,
  resolved across files via the shared `core/paths.py:resolve_mount_prefix()`.
- **Handler resolution**: a project-wide index maps named function
  declarations, `const foo = () => {}`/`function(){}`, and
  `exports.foo`/`obj.foo = function(){}` assignments to their real file/
  line, so a route registered with a named handler (`router.get('/x',
  controller.getOrders)`) resolves to wherever that function actually lives.
  Inline handlers (`router.get('/x', (req, res) => {...})`) are labeled
  `<inline handler>` and scanned directly.
- **`supertest` false-positive guard**: `supertest.agent(app)` renamed to a
  local `app`/`router` variable in a test file parses identically to real
  route registration. Skipped only when *that same file* locally declares
  the name as provably not an `express()`/`.Router()` call **and** the file
  imports `supertest` -- deliberately per-file, not project-wide, since the
  same name can be a real Express object in one file and something else
  entirely in another.
- **Auth**: `auth_decorators` = every middleware arg before the final
  handler arg (not pre-filtered against known indicators at capture time).
  `KNOWN_AUTH_INDICATORS = {requireAuth, isAuthenticated, authenticate,
  authMiddleware, verifyToken, ensureLoggedIn}`.
- **Global auth**: `<obj>.use(<identifier>)` where the identifier is in
  `KNOWN_AUTH_INDICATORS` specifically (not any `.use()` call -- avoids
  false-triggering on `cors()`/`helmet()`/`bodyParser()`/`morgan()`
  registrations, which are also `.use()` calls).
- **CONFIG-002 (CORS wildcard)**: a bare `cors()` call with zero args, or a
  call whose text contains `origin:` plus `'*'`/`"*"`/`origin: true`.
- **extra_param_names**: `req.query/body.x` via `core/bodyscan.py`.
- **No CONFIG-001 (debug mode) check** for Express.

## Hono

Same tree-sitter approach as Express, adapted for the API differences that
actually matter here -- everything not called out below (route-path
param syntax, `core/paths.py`/`core/bodyscan.py` reuse) works identically
to Express.

- **Routes**: `<obj>.<verb>(path, ...)` -- same `get`/`post`/`put`/
  `patch`/`delete`/`all` set as Express. `obj` is resolved per-file: any
  variable initialized via `new Hono()` (or `new <ns>.Hono()`) counts,
  falling back to the literal name `app` if a file declares none (covers
  the common case of a route file that imports an already-constructed
  `app` from elsewhere rather than declaring its own).
- **Router mounts**: `parent.route('/prefix', subAppIdentifier)` -- Hono's
  dedicated mount method, distinct from `.use()` (middleware-only in
  Hono, never a router mount, unlike Express which conflates both into
  `.use()`). Resolved via the same shared
  `core/paths.py:resolve_mount_prefix()` Express uses.
- **Handler resolution**: not built -- unlike Express, there's no
  project-wide named-handler index. Only inline handlers
  (`app.get('/x', (c) => {...})`) get their body scanned for
  `extra_param_names`; a route registered with a handler passed by
  reference (`app.get('/x', ordersController.get)`) resolves to
  `<handler name>` with no source range and no param scan.
- **Auth**: `auth_decorators` = every middleware arg before the final
  handler arg, same as Express, but each arg is described differently
  when it's a **call expression** (`jwt({ secret })`) rather than a bare
  identifier -- only the callee name (`jwt`) is captured, not the whole
  call text, since Hono's own official middleware (`hono/jwt`, `hono/
  basic-auth`, `hono/bearer-auth`) is always invoked with options, never
  passed bare. `KNOWN_AUTH_INDICATORS = {jwt, bearerAuth, basicAuth,
  requireAuth, isAuthenticated, authenticate, authMiddleware,
  verifyToken, ensureLoggedIn}`.
- **Global auth**: `<obj>.use([path,] <identifier-or-call>)` where the
  identifier/callee name is in `KNOWN_AUTH_INDICATORS` -- the same
  call-expression-aware matching as per-route auth, so `app.use('/api/*',
  jwt({ secret }))` is recognized as covering every route under `/api/*`
  (without this, every route behind global JWT middleware would show a
  false-positive AUTH-001).
- **CONFIG-002 (CORS wildcard)**: identical detection to Express -- `hono/
  cors`'s `cors()` has the same call shape as the npm `cors` package, so
  the same bare-call/`origin: '*'` check applies unchanged.
- **extra_param_names**: `c.req.query('x')`/`c.req.queries('x')` via
  `core/bodyscan.py`. `c.req.json()`/`c.req.parseBody()` take no field-name
  argument (the body is destructured afterward), so an id-like field read
  off a parsed body isn't caught -- same class of gap as Express missing
  `const body = req.body; body.x`.
- **No CONFIG-001 (debug mode) check**, no framework-version detection --
  same gaps as Express. Dangerous-sink checks (CMD-001/PATH-001/SSRF-001/
  REDIRECT-001) *are* covered, via the shared module below.

## Dangerous sinks (CMD-001/PATH-001/SSRF-001/REDIRECT-001)

One shared module, `languages/javascript/dangerous_sinks.py`, called from
all three frameworks' `run_baseline_checks` -- these scans look at raw
Node/browser-fetch APIs that show up identically no matter which framework
registered the route that (maybe) calls them, so duplicating the scan
per-analyzer (like the small CORS check does) wasn't worth it here; this is
substantial enough to share. Same philosophy as every other dangerous-sink
check in this tool (`checks/injection.py`): presence-only, flags a call
with a non-literal argument, never a real taint trace.

- **CMD-001**: `exec()`/`execSync()` (shell-interpreted, so a non-literal
  command argument is the whole risk) are flagged directly. `spawn()`/
  `execFile()` are safe by default (array args, no shell) and only flagged
  when their options object sets `shell: true`.
- **PATH-001**: `fs.readFile/readFileSync/writeFile/writeFileSync/unlink/
  unlinkSync/createReadStream/createWriteStream` called with a non-literal
  first argument -- the string-to-path construction moment, same idea as
  Java's `new File(...)`. A `path.join(base, userInput)` argument is
  itself a non-literal `call_expression`, so it's caught with no extra
  tracing across statements needed.
- **SSRF-001**: bare `fetch(url)`, plus `<obj>.get/post/put/patch/delete/
  request(url)` restricted to `<obj>` being literally named `axios`/
  `http`/`https` -- deliberately narrow, since `get`/`post`/etc are far too
  generic a method name to flag on any object (Express's/Hono's own
  `app.get(path, handler)` route registrations would otherwise match; a
  regression test for exactly this exists).
- **REDIRECT-001**: any `<obj>.redirect(nonLiteralArg)` call, matched by
  method name alone regardless of the object -- catches Express's
  `res.redirect()`, Hono's `c.redirect()`, and Next's
  `NextResponse.redirect()` in one check with no framework branching.
- **Not covered**: `axios(url)`/`axios({ url })` (only `axios.<method>()`
  is checked), WebSocket-based outbound connections, and (as always) SQL
  injection -- no template-literal-built-query check exists for JS at all.

## Next.js

File-based routing -- a route's URL comes from the file's own path in the
tree, not anything textually inside it. Two conventions supported
independently:

- **App Router** (`app/**/route.{js,ts}`): named exports `GET`/`POST`/
  `PUT`/`PATCH`/`DELETE`/`HEAD`/`OPTIONS`, each becomes its own separate
  `Route` (two exports in one file → two routes). Dynamic segments: `[id]`
  → `:id`, `[...slug]`/`[[...slug]]` (catch-all/optional catch-all) →
  `:slug`, `(group)` route groups are stripped entirely (they don't appear
  in the URL).
- **Pages Router** (`pages/api/**/*.{js,ts}`, `.jsx`/`.tsx` not matched):
  one default-export handler; methods are sniffed from `req.method ===
  'GET'`-style comparisons in the body, same technique as Go's net/http
  analyzer. If no explicit branching is found, defaults to all five common
  methods (`GET/POST/PUT/PATCH/DELETE`) rather than under-reporting. An
  `index.js`/`.ts` file's `"index"` stem is dropped from the path.
- **Auth**: no decorators exist in JS, so `auth_decorators` comes from a
  plain substring check (`"name("` in the handler body) against
  `KNOWN_AUTH_INDICATORS = {getServerSession, getToken, auth, currentUser,
  requireAuth, verifySession}`.
- **Global auth**: an exported `middleware` function in
  `middleware.ts`/`.js` (or under `src/`), body-text-checked against
  `redirect`/`Unauthorized`/`401`/known indicators -- Next.js's equivalent
  of Flask's `before_request`/Express's `app.use()`.
- **extra_param_names**: `core/bodyscan.py`, including App Router's
  `searchParams.get(...)`.
- **No CONFIG checks implemented at all** for Next.js (despite the
  in-source TODO naming a CORS-via-`next.config.js`-`headers()` check as a
  candidate -- not built yet).

## What still needs a human

- **Ownership-check tracing** -- IDOR-001 flags the id-like param exists,
  never whether the handler actually checks ownership.
- **Global-auth findings are presence-only** -- neither Express's/Hono's
  `.use()` scan nor Next.js's `middleware.ts` scan verifies the mechanism
  actually covers the specific route's path (Hono's does at least respect
  a path-prefix argument textually, e.g. `/api/*`, but doesn't simulate
  Hono's real pattern-matching against it); Spring is the only framework
  in this tool with real per-route matcher resolution.
- **No SQL injection check** for any JS framework -- unlike Spring's
  SQLI-001, raw SQL built via template-literal interpolation
  (`db.query(\`... WHERE id = ${x}\`)`) isn't detected; trace it by hand.
  CMD-001/PATH-001/SSRF-001/REDIRECT-001 *are* covered now -- see below.
- **Express**: `auth_decorators` isn't filtered to known indicators at
  capture time -- the report's per-route auth line can show an unrelated
  middleware name on an actually-unprotected route (cosmetic; AUTH-001
  itself only reacts to *absence*). `_ROUTER_OBJECT_NAMES` only recognizes
  literal `app`/`router` -- extend it if a codebase uses different naming.
- **Hono**: same auth_decorators-not-filtered cosmetic gap as Express. No
  named-handler resolution at all (see above) -- a route registered by
  reference gets no code view, no param scan, and no IDOR/body-param
  findings, silently, not flagged as a gap. `.on(method, path, handler)`
  (Hono's generic multi-method registration) isn't recognized as a route
  at all, only the six per-verb methods are.
- **Next.js**: no CORS check despite the framework having a real
  `next.config.js` `headers()` mechanism for it -- check by hand. No
  `export const runtime` segment-config review either.
- **No framework-version detection** for any JS framework -- an outdated
  `express`/`next`/`hono` pinned in `package.json` isn't flagged.
