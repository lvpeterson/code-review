# Java: spring

By far the deepest analyzer in this tool -- everything below was built
specifically for Spring (Boot/MVC), and most of it doesn't exist yet for
the other five languages (check each one's own README for what they
actually have). Route extraction uses `javalang`, a pure-Python Java
parser -- no JDK required to run this.

## Detection

`languages/java/detector.py`: any `pom.xml`/`build.gradle`/`build.gradle.kts`
containing `"spring-boot"`/`"springframework"`, or any `.java` file
containing `"org.springframework"`/`"@SpringBootApplication"`.

## Route extraction

- **Mapping annotations**: `@GetMapping`/`@PostMapping`/`@PutMapping`/
  `@PatchMapping`/`@DeleteMapping`, and `@RequestMapping` (which needs its
  own `method` attribute resolved separately -- see below).
- **Path**: `value`/`path` attributes are treated as aliases (Spring's own
  `path=` alias is commonly used instead of the positional `value` as soon
  as another named attribute like `produces` is also set -- missing this
  used to silently truncate the whole sub-path down to the class-level
  base path). Array-valued mappings (`@GetMapping({"/a", "/b"})`) use the
  first entry as representative rather than dropping the route entirely.
  Path segments support the regex-constrained syntax (`{orderId:[0-9]+}`)
  and hyphenated names (`{order-id}`, requiring an explicit
  `@PathVariable("order-id") Long orderId` binding since Java identifiers
  can't contain hyphens) -- both are handled by the shared
  `core/paths.py:extract_path_param_names()` regex, not Spring-specific
  code.
- **Method(s)**: a bare `@RequestMapping` with no `method=` matches **every**
  HTTP verb in real Spring (GET/POST/PUT/DELETE/PATCH -- not just GET,
  which this tool used to silently assume). `method = {RequestMethod.GET,
  RequestMethod.POST}` (an array) keeps every listed entry, not just the
  first. This matters beyond labeling: AUTH-001's severity is scored off
  which methods a route accepts, so under-reporting methods under-scored
  routes that are actually reachable via a sensitive verb.
- **`Route.path_variable_binding_names`**: the actual Java identifier for
  every `@PathVariable`, tracked separately from the URL-side placeholder
  name specifically so the HTML report's code-view highlighting can find
  where the value is *used* in the handler body -- the URL-side name (e.g.
  `order-id`) never appears there as a bare identifier, only inside the
  annotation's own string literal.

## Auth

`KNOWN_AUTH_INDICATORS = {PreAuthorize, Secured, RolesAllowed,
PostAuthorize}`. A class-level annotation applies to every method in the
controller (merged into each route's `auth_decorators`, same mechanism as
class-level `@Validated` below). `KNOWN_EXPLICIT_ACCESS_INDICATORS =
{PermitAll, DenyAll}` -- an explicit, deliberate access declaration is
tracked *separately* from `auth_decorators` and suppresses AUTH-001
entirely (a developer documenting "yes, intentionally public" shouldn't get
flagged for exactly that documentation).

- **AUTH-001** -- no recognized auth control on a route. Severity `medium`
  for POST/PUT/PATCH/DELETE, `low` for GET-only. Gets rewritten by the
  matcher-chain resolution below when a `SecurityFilterChain` verdict is
  available.
- **AUTH-002** -- `@PreAuthorize`/etc. is used somewhere in the codebase,
  but `@EnableMethodSecurity` (or the legacy `@EnableGlobalMethodSecurity`)
  was found nowhere. Without one of these, every method-security annotation
  in the app is pure decoration -- Spring never evaluates it. Project-wide,
  severity `high`.
- **AUTH-003** -- `.csrf(...).disable()`/`.csrf().disable()` found.
  Downgraded from `medium` to `info` when the *same enclosing method* also
  configures `.oauth2ResourceServer(...)` + `SessionCreationPolicy.STATELESS`
  with no `.oauth2Login(...)`/`.formLogin(...)` -- the standard, correct
  combination for a pure bearer-token API where CSRF genuinely doesn't
  apply. Still flagged (never silently dropped) even then, since this is a
  same-method-only check: a session established by a *different*
  `SecurityFilterChain`, or a token that ends up riding in on a cookie
  instead of a header, are both invisible to it.
- **AUTH-004/005** -- Actuator hygiene. AUTH-004 fires when
  `management.endpoints.web.exposure.include` names a sensitive endpoint
  (`env`, `heapdump`, `beans`, `configprops`, `shutdown`, `mappings`,
  `threaddump`, `httptrace`, `loggers`, or `*`). AUTH-005 fires when the
  parsed `SecurityFilterChain` matcher rules resolve the Actuator's *actual*
  base path (read from `management.endpoints.web.base-path`, defaulting to
  `/actuator` -- a relocated base path is a real, common hardening move, and
  the check uses the real one, not always the default) to `permitAll()`.
- **AUTH-006** -- `Cookie`/`ResponseCookie` creation whose enclosing method
  body doesn't also set `Secure`/`HttpOnly`. Method-body-scoped text check,
  not real per-variable data-flow tracing -- a flag set via a shared helper
  method elsewhere would be missed.

### The matcher-chain engine

The single most load-bearing (and most heavily hedged) piece of Spring
support here: a regex-based, best-effort parse of a `SecurityFilterChain`
bean's `.requestMatchers(...)`/`.antMatchers(...)`/`.anyRequest()` chain
into an ordered list of `(pattern, rule)` pairs, walked the same way Spring
itself does (first matching pattern wins), using a hand-rolled Ant-style
path matcher (`**`, `*`, `{name}` all supported). This is what lets
AUTH-001 go from "no annotation found, go check the config yourself" to an
actual resolved verdict per route:

- Resolves to `permitAll()` → downgraded to `info`, worded as "explicitly
  public per SecurityFilterChain."
- Resolves to `hasRole(...)`/`authenticated()`/etc. → downgraded to `low`,
  worded as "covered by SecurityFilterChain."
- No rule matches → stays as the original, unresolved AUTH-001.

**Known limitation, stated plainly**: this is regex over raw source text,
not a real parse of the fluent builder chain -- it works for the common,
readable formatting real Spring Security config is almost always written
in, but won't resolve a matcher pattern built from a variable or a loop
rather than a literal string, and doesn't distinguish two independent
`authorizeHttpRequests` blocks in the same file. Verify a resolved verdict
against the actual chain before fully trusting it, same as every other
heuristic in this tool -- this one just gets you much closer than "go read
the file yourself."

## Validation -- two genuinely separate mechanisms

This tripped up manual review during development, so it's worth being
explicit: Spring has **two independent** validation-wiring gates, and
neither substitutes for the other.

- **VALID-001** -- a constraint annotation (`@NotBlank`, `@Digits`,
  `@Pattern`, `@Min`/`@Max`, ...) sitting *directly on* a `@PathVariable`,
  `@RequestParam`, **or a `@RequestBody` parameter itself** (e.g.
  `@RequestBody @NotNull List<String> items` -- checking the list reference
  isn't null, not anything about the DTO's own fields) is only evaluated
  when the class carries `@Validated`. Without it, the constraint is pure
  decoration.
- **VALID-002** -- a `@RequestBody` parameter's own *type* having
  field-level constraints (an `OrderDto` whose `email` field carries
  `@Email`) is only cascaded into when the parameter itself is annotated
  `@Valid` (or `@Validated`) -- completely independent of class-level
  `@Validated`, which never reaches into a parameter's own type regardless.
  Always fires when `@Valid` is absent, since this tool can't resolve
  whether the referenced type actually has field constraints to cascade
  into (no cross-file type resolution) -- deliberately errs toward noise
  over silently dropping a real gap.

A single parameter can have one of these enforced and the other not, at the
same time -- the report's `validation:` note line shows both facts side by
side for exactly this reason.

## Other checks

- **XML-001** -- `produces`/`consumes` declares an XML media type (a
  literal string containing "xml", or a Spring `MediaType.*_XML_VALUE`-style
  constant -- these conveniently all embed "XML" in the constant name
  itself, so no hardcoded constant list is needed). Flags the route for an
  XXE review; can't verify whether the actual XML parser has external
  entity resolution disabled. Won't catch a codebase's own custom
  media-type constants class (needs real type resolution).
- **DESER-001** -- Jackson `.activateDefaultTyping(...)`/
  `.enableDefaultTyping(...)`, or `@JsonTypeInfo(use =
  Id.CLASS/MINIMAL_CLASS)` -- the actual RCE-class Java deserialization
  gadget-chain risk, distinct from and more severe than the validation gaps
  above.
- **CMD-001/PATH-001/SSRF-001/REDIRECT-001** (`checks/injection.py`) --
  `Runtime.exec`/`new ProcessBuilder`; `new File(...)`/`Paths.get(...)`
  called with a non-literal argument (scoped to the actual string→path
  construction moment, not `Files.*` methods that take an already-built
  `Path`); RestTemplate's request methods/`new URL`/`URI.create` with a
  non-literal URL; `sendRedirect(...)`/a `Location` header built from a
  non-literal value. All presence-only: flags that a dangerous API was
  called with something that isn't a fixed literal, never that request
  input actually reaches it.
- **MASS-001** (`checks/binding.py`) -- a `@RequestBody` parameter whose
  type is itself annotated `@Entity` elsewhere in the scan, rather than a
  dedicated DTO (mass assignment / over-posting: a client can set any field
  the entity has).
- **SORT-001** -- a route accepts `Pageable`/`Sort`, both of which let a
  client control an `ORDER BY` column directly via a query parameter --
  the client controlling query *structure*, not just a value. Always
  `info`, a nudge to verify sortable fields are allowlisted.
- **SQLI-001** (`checks/sqli.py`) -- SQL/JPQL built via `+` string
  concatenation passed directly into `EntityManager.createQuery`/
  `createNativeQuery`, `JdbcTemplate`'s query methods, or
  `Connection.prepareStatement`. Deliberately narrower than the other
  sink checks: a plain variable holding a fixed `:namedParam` template
  (the safe pattern) is not flagged -- only concatenation happening
  directly in the call's own argument is caught; concatenation done in an
  earlier statement and passed in via a variable isn't traced.
- **PROXY-001** (`checks/aop.py`) -- a same-class call (bare `method()` or
  `this.method()`) to a `@PreAuthorize`/`@Secured`/`@Transactional`-etc.
  method, which bypasses Spring's AOP proxy entirely and silently never
  evaluates the annotation. The same "annotation present, enforcement
  mechanism never triggered" shape as AUTH-002, just at the call-site level.
  Severity `high` if an auth annotation is involved, `medium` for
  `@Transactional`-only.
- **CONFIG-002 (CORS)** -- a bare `@CrossOrigin` or explicit `origins="*"`.
- **CONFIG-003 (framework version)** -- Spring Boot/Framework version read
  from `pom.xml`/`build.gradle(.kts)` (parent POM, an explicit
  `spring-boot.version`/`spring.version` property, the Gradle plugin
  version, or a Gradle version-catalog entry), root-first in a multi-module
  Maven repo. **Not a CVE feed** -- a coarse, major-version-bucketed
  staleness check against Spring's own published support timeline (1.x
  Boot / ≤4.x Framework = end of life, `high`; 2.x Boot / 5.x Framework =
  tail of support, `medium`; current-looking = `info` nudge to verify the
  exact minor/patch line and check for known CVEs yourself).

## What's not covered at all

Real gaps, not built this session, worth knowing about explicitly rather
than assuming silence means "clean":

- **Interface-based controllers** -- `@GetMapping` declared on an interface
  (common with OpenAPI-generated contracts), implemented by a class that
  just carries `@RestController` with no repeated mapping annotations on
  its own methods. This tool finds **zero routes** for a controller built
  this way.
- **WebFlux functional routing** (`RouterFunctions.route(GET("/x"),
  handler)`) -- a completely different, code-based routing paradigm with no
  annotations at all. Untouched entirely.
- **Custom composed/meta-annotations** -- a codebase's own
  `@MyRestController` that itself carries `@RestController` (a real Spring
  feature) isn't recognized; javalang doesn't resolve annotation
  composition.
- **Twin routes on the same path differentiated by `produces`/`consumes`**
  -- e.g. one method serving JSON with `@PreAuthorize`, another serving XML
  on the identical path with a different (or missing) auth annotation.
  Each route is evaluated independently with no cross-referencing, so a
  weaker twin with *zero* annotations is still caught by AUTH-001 on its
  own merits, but two twins that both have *some* annotation with different
  actual role requirements won't be flagged as inconsistent.
- **SpEL/LDAP/XPath injection** -- same shape of problem as SQL injection
  (structure vs. data) but none of these have a dedicated check.
- **Custom/hand-rolled JWT validation** (`Jwts.parser()`, a bespoke
  `JwtDecoder`) -- algorithm-confusion and signature-bypass bugs live here;
  verifying correctness needs real semantic understanding, not a pattern
  scan.
- **Hardcoded secrets / weak crypto** (`MD5`, `DES`, ECB mode, a literal
  API key) -- a different, well-trodden category most dedicated secrets
  scanners already cover; not duplicated here.
- **ReDoS** -- determining whether a regex is catastrophically backtracking
  needs real complexity analysis, not pattern matching.
- **XSS in server-rendered views** (Thymeleaf's `th:utext` vs `th:text`,
  JSP) -- only relevant if the codebase uses `@Controller` + templates
  rather than `@RestController` + JSON; would need template-engine-specific
  parsing, a different domain from everything else here.

## Manual work, by check family

| Check(s) | Automated | Still manual |
|---|---|---|
| `AUTH-001` | Annotation presence + matcher-chain resolution | Whether a resolved matcher verdict *really* covers the exact path (best-effort regex, not a real parse); anything enforced outside this repo (gateway, BFF) |
| `AUTH-002` | `@EnableMethodSecurity` presence, codebase-wide | Confirm it's a true negative, not a scan-scope gap (wrong module scanned, an unusual location) |
| `AUTH-003` | Same-method CSRF+resource-server signal correlation | Whether a session exists via a *different* config bean, or the token rides in on a cookie instead of a header |
| `AUTH-004/005` | Exposure config + matcher-chain resolution | Whether the exposed endpoints are actually needed by monitoring |
| `AUTH-006` | Method-body-scoped Secure/HttpOnly text check | A flag set via a shared cookie-builder helper elsewhere in the codebase |
| `VALID-001/002` | `@Validated`/`@Valid` wiring | Whether the referenced DTO type actually has field constraints to cascade into; whether validation happens some other way |
| `IDOR-001` | Id-like param detection | The actual ownership check -- always in the service layer, which this tool never opens |
| `XML-001` | XML media-type presence | The actual parser config -- is external entity resolution disabled |
| `DESER-001` | Dangerous Jackson config presence | Whether a gadget chain actually exists on the classpath |
| `CMD-001`/`PATH-001`/`SSRF-001`/`REDIRECT-001`/`SQLI-001` | Sink presence + literal-vs-dynamic (or concatenation) argument check | **Full taint trace** from the sink back to request input -- the largest remaining manual burden across this whole tool |
| `MASS-001` | Entity-bound `@RequestBody` detection | Whether the exposed fields are actually sensitive, or already guarded (`@JsonIgnore`, a serializer view) |
| `PROXY-001` | Same-class call-site detection | None really -- this one's close to a hard fact once found, just confirm the call site |
| `CONFIG-002` (CORS) | Wildcard presence | Whether it's actually intended |
| `CONFIG-003` (version) | Version detection + coarse EOL bucketing | Cross-checking against real CVE databases -- explicitly not what this does |
