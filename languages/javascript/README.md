# JavaScript/TypeScript: express, nextjs

Route extraction uses `tree-sitter` with the `tree-sitter-javascript`/
`tree-sitter-typescript` grammars (prebuilt wheels -- no Node.js or compiler
needed to run this).

## Detection

`detector.py` reads `package.json`'s merged `dependencies`+`devDependencies`
for an `"express"` or `"next"` key, or a `next.config.{js,mjs,ts}` file
presence for Next.js. Falls back to a `require('express')`/`import ...
from 'express'` source scan if no manifest signal is found (no equivalent
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
- **Global-auth findings are presence-only** -- neither Express's
  `app.use()` scan nor Next.js's `middleware.ts` scan verifies the
  mechanism actually covers the specific route's path; Spring is the only
  framework in this tool with real per-route matcher resolution.
- **No SQL/command/path/SSRF injection checks** for either framework --
  none of the dangerous-sink checks built for Spring exist here yet. Trace
  raw SQL (template-literal-built queries, `db.query(\`... ${x}\`)`) and
  `child_process.exec`/`fs.readFile(userPath)`/`fetch(userUrl)` patterns by
  hand.
- **Express**: `auth_decorators` isn't filtered to known indicators at
  capture time -- the report's per-route auth line can show an unrelated
  middleware name on an actually-unprotected route (cosmetic; AUTH-001
  itself only reacts to *absence*). `_ROUTER_OBJECT_NAMES` only recognizes
  literal `app`/`router` -- extend it if a codebase uses different naming.
- **Next.js**: no CORS check despite the framework having a real
  `next.config.js` `headers()` mechanism for it -- check by hand. No
  `export const runtime` segment-config review either.
- **No framework-version detection** for either -- an outdated `express`/
  `next` pinned in `package.json` isn't flagged.
