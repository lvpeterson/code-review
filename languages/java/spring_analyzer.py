"""Deep-dive analyzer for Spring (Boot/MVC) targets.

Uses javalang to parse a real Java AST instead of regex/line-window
scanning -- annotations are resolved as actual class/method attributes, so
class-level vs method-level @RequestMapping can't be confused, and an auth
annotation is found regardless of whether it's written above or below the
mapping annotation it's paired with.
"""
from __future__ import annotations

import re

import javalang

from checks import auth as auth_checks
from checks import config as config_checks
from checks import idor as idor_checks
from checks import validation as validation_checks
from checks import xml as xml_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, iter_named_files, read_text_safe
from core.models import Finding, Route, ScanResult
from core.registry import register

_MAPPING_ANNOTATIONS = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "DeleteMapping": "DELETE",
    "PatchMapping": "PATCH",
    "RequestMapping": "GET",  # overridden below if a method=... value is present
}

_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}

KNOWN_AUTH_INDICATORS = {
    "PreAuthorize",
    "Secured",
    "RolesAllowed",
    "PostAuthorize",
}

# Bean Validation (JSR 380) constraint annotations -- javax.validation.constraints
# and jakarta.validation.constraints alike, since javalang only exposes the bare
# annotation name, not its resolved package.
KNOWN_VALIDATION_CONSTRAINTS = {
    "NotNull", "NotBlank", "NotEmpty", "Min", "Max", "DecimalMin", "DecimalMax",
    "Digits", "Size", "Pattern", "Email", "Positive", "PositiveOrZero",
    "Negative", "NegativeOrZero", "Future", "FutureOrPresent", "Past",
    "PastOrPresent", "AssertTrue", "AssertFalse",
}


def _clean_literal(value: str) -> str:
    return value.strip('"')


def _method_end_line(text: str, start_line: int) -> int:
    """Scan forward from `start_line` (1-indexed, the method declaration's
    own line) to find the line with the matching closing brace of its body.
    javalang doesn't expose an end position, so this does simple brace
    counting -- tracking string/char literals and comments so braces inside
    them (e.g. a `"{"` in a log message) don't throw the count off.
    """
    lines = text.split("\n")
    offset = sum(len(line) + 1 for line in lines[: start_line - 1])

    depth = 0
    started = False
    in_string = in_char = in_line_comment = in_block_comment = False
    i, n = offset, len(text)
    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 1
        elif in_string:
            if ch == "\\":
                i += 1
            elif ch == '"':
                in_string = False
        elif in_char:
            if ch == "\\":
                i += 1
            elif ch == "'":
                in_char = False
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            i += 1
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            i += 1
        elif ch == '"':
            in_string = True
        elif ch == "'":
            in_char = True
        elif ch == "{":
            depth += 1
            started = True
        elif ch == "}":
            depth -= 1
            if started and depth == 0:
                return text.count("\n", 0, i) + 1
        i += 1

    return start_line


def _first_literal_value(element) -> str | None:
    """Best-effort single string out of an annotation element -- a bare
    literal, an enum constant reference (`RequestMethod.POST`), or an array
    of either (`@GetMapping({"/a", "/b"})` -- Spring registers every entry
    as an equivalent route, but this tool models one route per handler, so
    the first is used as representative; better than dropping the whole
    mapping, which silently truncated the route down to just the class-level
    base path).
    """
    if isinstance(element, javalang.tree.Literal):
        return _clean_literal(element.value)
    if isinstance(element, javalang.tree.MemberReference):
        return element.member
    if isinstance(element, javalang.tree.ElementArrayValue) and element.values:
        return _first_literal_value(element.values[0])
    return None


def _all_literal_values(element) -> list[str]:
    """Every string out of an annotation element, keeping every entry of an
    array rather than just the first (unlike `_first_literal_value`).
    produces/consumes are array-typed attributes where a route legitimately
    declares multiple formats (`produces = {"application/json",
    "application/xml"}`) -- taking only the first entry would silently drop
    an XML format listed after a JSON one.
    """
    if isinstance(element, javalang.tree.Literal):
        return [_clean_literal(element.value)]
    if isinstance(element, javalang.tree.MemberReference):
        return [element.member]
    if isinstance(element, javalang.tree.ElementArrayValue):
        values: list[str] = []
        for v in element.values:
            values.extend(_all_literal_values(v))
        return values
    return []


_XML_MEDIA_TYPE_RE = re.compile(r"xml", re.IGNORECASE)


def _xml_media_types(mapping_annotation) -> list[str]:
    """produces/consumes values on `mapping_annotation` that look like XML
    -- a literal media-type string containing "xml" (application/xml,
    text/xml, application/soap+xml, ...) or a constant/enum-member name
    containing "xml". Spring's own MediaType.APPLICATION_XML_VALUE,
    MediaType.TEXT_XML_VALUE, MediaType.APPLICATION_SOAP_XML_VALUE, etc all
    happen to embed "XML" in the constant name itself, which is what makes
    this catch them without needing a hardcoded list of Spring's exact
    constant names. Won't catch a value built via a method call
    (`SomeEnum.XML.getValue()`) or a codebase's own custom media-type
    constants class defined elsewhere -- those need real cross-file type
    resolution, which this AST-only tool doesn't do.
    """
    element = mapping_annotation.element
    if not isinstance(element, list):
        return []
    found: list[str] = []
    for pair in element:
        if isinstance(pair, javalang.tree.ElementValuePair) and pair.name in ("produces", "consumes"):
            found += [v for v in _all_literal_values(pair.value) if _XML_MEDIA_TYPE_RE.search(v)]
    return found


def _annotation_values(annotation) -> dict[str, str]:
    """Normalize `@X("path")`, `@X(value="path", method=RequestMethod.POST)`,
    and `@X({"path1", "path2"})` into a {"value": "path", "method": "POST"}
    dict.
    """
    element = annotation.element
    if element is None:
        return {}
    if isinstance(element, (javalang.tree.Literal, javalang.tree.ElementArrayValue)):
        value = _first_literal_value(element)
        return {"value": value} if value is not None else {}

    result: dict[str, str] = {}
    if isinstance(element, list):
        for pair in element:
            if not isinstance(pair, javalang.tree.ElementValuePair):
                continue
            value = _first_literal_value(pair.value)
            if value is not None:
                result[pair.name] = value
    return result


def _detect_global_security_filter_chain(target_path) -> tuple[str, int, str] | None:
    """Most real Spring Security setups enforce auth through a
    SecurityFilterChain bean (or the older WebSecurityConfigurerAdapter
    `configure(HttpSecurity)` override) rather than -- or in addition to --
    per-method @PreAuthorize. Without this, an app that does auth entirely
    through the filter chain would get every single route flagged.
    """
    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        try:
            tree = javalang.parse.parse(text)
        except Exception:
            continue

        for _, member in tree.filter(javalang.tree.MethodDeclaration):
            return_type_name = getattr(member.return_type, "name", None) if member.return_type else None
            is_filter_chain_bean = return_type_name == "SecurityFilterChain"
            is_legacy_configure = member.name == "configure" and any(
                getattr(p.type, "name", None) == "HttpSecurity" for p in member.parameters
            )
            if not (is_filter_chain_bean or is_legacy_configure) or not member.position:
                continue

            end_line = _method_end_line(text, member.position.line)
            body_text = "\n".join(text.split("\n")[member.position.line - 1:end_line])
            if ".authenticated()" in body_text or ".anyRequest()" in body_text:
                relative_file = str(java_file.relative_to(target_path))
                return relative_file, member.position.line, f"{member.name}(...) configures a security filter chain with broad .authenticated() coverage"

    return None


_METHOD_SECURITY_ENABLING_ANNOTATIONS = {"EnableMethodSecurity", "EnableGlobalMethodSecurity"}


def _detect_method_security_enabled(target_path) -> bool:
    """Whether @EnableMethodSecurity (Spring Security 5.6+) or the legacy
    @EnableGlobalMethodSecurity exists anywhere in the target -- one of
    these is required for @PreAuthorize/@PostAuthorize/@Secured/
    @RolesAllowed to be evaluated at all; without it they're pure
    decoration. Presence-only, codebase-wide (not tied to any one route).
    """
    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        try:
            tree = javalang.parse.parse(text)
        except Exception:
            continue
        for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
            if {a.name for a in class_node.annotations} & _METHOD_SECURITY_ENABLING_ANNOTATIONS:
                return True
    return False


_CSRF_DISABLED_RE = re.compile(
    r"\.csrf\s*\([^)]*\.disable\(\)"   # .csrf(csrf -> csrf.disable())  (Spring Security 6+ lambda DSL)
    r"|\.csrf\(\)\s*\.\s*disable\(\)"  # .csrf().disable()              (older fluent builder style)
)
_OAUTH2_RESOURCE_SERVER_RE = re.compile(r"\.oauth2ResourceServer\s*\(")
_SESSION_STATELESS_RE = re.compile(r"SessionCreationPolicy\.STATELESS")
_SESSION_BASED_AUTH_RE = re.compile(r"\.oauth2Login\s*\(|\.formLogin\s*\(")


def _enclosing_method_body(tree, text: str, line: int) -> str | None:
    """The full body text of whichever method declaration contains `line`,
    or None if none does. Used to give a CSRF-disable match the actual
    surrounding security-config context to check for corroborating
    resource-server signals -- rather than scanning the whole file blindly,
    which could pick up an unrelated `.oauth2Login(...)` sitting in a
    completely different bean/method than the one that disabled CSRF.
    Picks the innermost enclosing method if there's nesting (the one whose
    start line is latest while still containing `line`).
    """
    best: tuple[int, int] | None = None
    for _, member in tree.filter(javalang.tree.MethodDeclaration):
        if not member.position:
            continue
        start = member.position.line
        if start > line:
            continue
        end = _method_end_line(text, start)
        if start <= line <= end and (best is None or start > best[0]):
            best = (start, end)
    if best is None:
        return None
    start, end = best
    return "\n".join(text.split("\n")[start - 1:end])


def _detect_csrf_disabled(target_path) -> list[Finding]:
    findings: list[Finding] = []
    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        relative_file = str(java_file.relative_to(target_path))
        try:
            tree = javalang.parse.parse(text)
        except Exception:
            tree = None

        for match in _CSRF_DISABLED_RE.finditer(text):
            line = _line_of(text, match.start())
            context = (_enclosing_method_body(tree, text, line) if tree else None) or text
            resource_server_only = bool(
                _OAUTH2_RESOURCE_SERVER_RE.search(context)
                and _SESSION_STATELESS_RE.search(context)
                and not _SESSION_BASED_AUTH_RE.search(context)
            )
            findings.append(auth_checks.csrf_disabled_finding(relative_file, line, resource_server_only))
    return findings


_SENSITIVE_ACTUATOR_ENDPOINTS = {
    "env", "heapdump", "beans", "configprops", "shutdown", "mappings",
    "threaddump", "httptrace", "loggers", "*",
}
_ACTUATOR_EXPOSURE_RE = re.compile(
    r"management\.endpoints\.web\.exposure\.include\s*[:=]\s*[\"']?([^\r\n\"']+)"
    r"|exposure:\s*\n\s*include:\s*[\"']?([^\r\n\"']+)"
)


def _detect_actuator_exposure(target_path) -> list[Finding]:
    """Regex scan of application.properties/.yml/.yaml for a
    management.endpoints.web.exposure.include naming a sensitive endpoint
    (or "*"). Handles the flattened dotted-key form (valid in both
    properties files and YAML) and the simple two-line nested YAML form
    (`exposure:` immediately followed by `include:`) -- not a real YAML
    parser, so an unusually-formatted nested block could be missed.
    """
    findings: list[Finding] = []
    for config_file in iter_named_files(
        target_path, ("application.properties", "application.yml", "application.yaml")
    ):
        text = read_text_safe(config_file)
        relative_file = str(config_file.relative_to(target_path))
        for match in _ACTUATOR_EXPOSURE_RE.finditer(text):
            raw = (match.group(1) or match.group(2) or "").strip()
            hit = {n.strip() for n in raw.split(",") if n.strip()} & _SENSITIVE_ACTUATOR_ENDPOINTS
            if hit:
                findings.append(
                    auth_checks.actuator_exposure_finding(
                        relative_file, _line_of(text, match.start()), ", ".join(sorted(hit))
                    )
                )
    return findings


_SECURITY_RULE_RE = re.compile(
    r"\.(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*(?P<patterns>(?:\"[^\"]*\"\s*,?\s*)+)\)"
    r"\s*\.\s*(?P<rule1>permitAll|authenticated|denyAll|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\((?P<args1>[^)]*)\)"
    r"|\.anyRequest\(\)\s*\.\s*(?P<rule2>permitAll|authenticated|denyAll|hasRole|hasAnyRole|hasAuthority|hasAnyAuthority)\s*\((?P<args2>[^)]*)\)"
)
_QUOTED_STRING_RE = re.compile(r'"([^"]*)"')


def _describe_rule(rule: str, args: str) -> str:
    values = _QUOTED_STRING_RE.findall(args)
    return f"{rule}({', '.join(values)})" if values else f"{rule}()"


def _extract_security_matchers(target_path) -> list[tuple[list[str], str]]:
    """Best-effort, regex-based extraction of a SecurityFilterChain's
    ordered (pattern(s), rule) pairs -- e.g. [(["/api/public/**"],
    "permitAll()"), (["/api/admin/**"], "hasRole(ADMIN)"), (["**"],
    "authenticated()")] for a chain ending `.anyRequest().authenticated()`.

    Regex over raw source text, not a real parse of the fluent builder
    chain -- javalang doesn't model method-chain order in a shape that's
    easy to walk reliably. Works for the common, readable formatting real
    Spring Security config is almost always written in, but won't resolve
    a matcher pattern built from a variable/loop rather than a literal
    string, and doesn't distinguish two independent authorizeHttpRequests
    blocks in the same file (rare). `**` here is this function's own
    sentinel for anyRequest()'s catch-all, not literal source text.
    """
    rules: list[tuple[list[str], str]] = []
    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        for match in _SECURITY_RULE_RE.finditer(text):
            if match.group("patterns") is not None:
                patterns = _QUOTED_STRING_RE.findall(match.group("patterns"))
                rules.append((patterns, _describe_rule(match.group("rule1"), match.group("args1"))))
            else:
                rules.append((["**"], _describe_rule(match.group("rule2"), match.group("args2"))))
    return rules


def _ant_pattern_to_regex(pattern: str):
    """Ant-style path pattern (Spring's own matcher syntax) -> compiled
    regex. `**` matches any number of segments, `*` matches within one
    segment, `{name}`/`{name:constraint}` matches one segment (the
    constraint itself is ignored -- treated the same as a bare `*`).
    """
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*\*", ".*")
    escaped = escaped.replace(r"\*", "[^/]*")
    escaped = re.sub(r"\\\{[^}]*\\\}", "[^/]+", escaped)
    return re.compile("^" + escaped + "$")


def _resolve_matcher_coverage(route_path: str, rules: list[tuple[list[str], str]]) -> str | None:
    """Walk the ordered matcher rules the same way Spring does -- first
    matching pattern wins -- and return the rule text covering this
    route's path, or None if nothing matched (no verdict, still open).
    """
    for patterns, rule in rules:
        for pattern in patterns:
            if pattern == "**" or _ant_pattern_to_regex(pattern).match(route_path):
                return rule
    return None


def _extra_param_names(member) -> list[str]:
    """Method parameters annotated @RequestParam/@RequestBody -- Spring
    binds these from the query string / JSON body respectively, so an
    id-like one here is just as much an IDOR candidate as one in the path.
    """
    names = []
    for param in member.parameters:
        ann_names = {a.name for a in param.annotations}
        if "RequestParam" in ann_names or "RequestBody" in ann_names:
            names.append(param.name)
    return names


def _path_variable_binding_names(member) -> list[str]:
    """The Java identifier for every @PathVariable-annotated parameter,
    regardless of whether its explicit binding name (`@PathVariable("order-
    id")`) matches the URL segment name or not. See `Route.
    path_variable_binding_names` for why the report needs this separately
    from the URL-side name.
    """
    return [param.name for param in member.parameters if "PathVariable" in {a.name for a in param.annotations}]


def _request_body_param_validations(member) -> dict[str, bool]:
    """@RequestBody params, keyed by name, valued True if the parameter
    itself carries @Valid or @Validated -- the trigger Bean Validation needs
    to cascade into the *referenced type's own fields* (e.g. an OrderDto's
    @NotBlank `name` field). This is unrelated to whether the parameter has
    a *direct* constraint annotation on itself (that's `_param_validations`
    below, gated by class-level @Validated instead) -- a @RequestBody param
    can have one of these enforced and not the other at the same time.

    Every @RequestBody param without @Valid is recorded, regardless of
    whether its type looks like it could plausibly have fields to cascade
    into (a `List<String>` included) -- this is a heuristic triage tool, not
    a verdict, and a human is going to trace the actual usage regardless.
    Silently dropping a param because its type *looks* scalar risks a
    reviewer never even glancing at a route that turns out to matter (e.g.
    a type alias, a generic bound, or downstream logic this tool can't see);
    an occasional "yeah that one's fine" costs a lot less.
    """
    result: dict[str, bool] = {}
    for param in member.parameters:
        ann_names = {a.name for a in param.annotations}
        if "RequestBody" not in ann_names:
            continue
        result[param.name] = bool({"Valid", "Validated"} & ann_names)
    return result


def _param_validations(member) -> dict[str, list[str]]:
    """Bean Validation constraint annotations found directly on a parameter
    (not on the fields of a type it references), keyed by param name.
    Covers @PathVariable/@RequestParam always (empty list included, so the
    report can say "no constraint" at a glance), and @RequestBody only when
    it actually carries one -- e.g. `@RequestBody @NotNull List<String>
    items`. That @NotNull is a *direct* constraint on the parameter itself
    (checking the list reference isn't null), which class-level @Validated
    enforces via the same AOP path as @PathVariable/@RequestParam -- @Valid
    is irrelevant to it. @Valid only matters for a separate concern: whether
    Bean Validation cascades into the *fields of the referenced type itself*
    (see `_request_body_param_validations`). An unconstrained @RequestBody
    param is deliberately left out here (rather than recorded as an empty
    list like path/query params get) since that case is already fully
    covered by the "(body): NOT @Valid" line from `_request_body_param_validations`
    and would otherwise show up twice.
    """
    result: dict[str, list[str]] = {}
    for param in member.parameters:
        ann_names = {a.name for a in param.annotations}
        constraints = sorted(ann_names & KNOWN_VALIDATION_CONSTRAINTS)
        if "PathVariable" in ann_names or "RequestParam" in ann_names:
            result[param.name] = constraints
        elif "RequestBody" in ann_names and constraints:
            result[param.name] = constraints
    return result


_POM_PARENT_RE = re.compile(r"<parent>(?P<block>.*?)</parent>", re.DOTALL)
_POM_VERSION_TAG_RE = re.compile(r"<version>\s*([^<\s]+)\s*</version>")
_POM_PROPERTY_VERSION_RE = re.compile(
    r"<(spring-boot\.version|spring\.version)>\s*([^<\s]+)\s*</\1>"
)
_GRADLE_BOOT_PLUGIN_RE = re.compile(
    r"org\.springframework\.boot[\"']\s*\)?\s*version\s*[\"']([^\"']+)[\"']"
)
# A Gradle version-catalog alias (`alias(libs.plugins.spring.boot)`) has no
# literal version in build.gradle at all -- the version lives in
# gradle/libs.versions.toml instead, keyed under [versions] or [plugins].
_GRADLE_BOOT_PLUGIN_REFERENCED_RE = re.compile(r"springframework\.boot|spring[.\-]boot", re.IGNORECASE)
_VERSION_CATALOG_SPRING_BOOT_RE = re.compile(
    r"(?im)^\s*([\w.-]*spring[\w.-]*boot[\w.-]*)\s*=\s*[\"']([^\"']+)[\"']"
)


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _by_depth(target_path, paths) -> list:
    """Root-first ordering for build files -- in a multi-module Maven repo
    the root pom.xml is what actually declares the Spring Boot parent/
    version almost always; child module poms just inherit it. `rglob`
    doesn't guarantee traversal order, so without this a child pom could
    get checked (and, if it happens to have its own unrelated <version> tag
    inside its own <parent> block, wrongly matched) before the root one.
    """
    return sorted(paths, key=lambda p: (len(p.relative_to(target_path).parts), str(p)))


def _detect_spring_version(target_path) -> tuple[str, str, str, int, str] | None:
    """Best-effort Spring Boot/Framework version detection from the
    project's build file, so the report can flag an obviously outdated
    runtime. Checked in order of how authoritative the signal is: an
    explicit version property overrides whatever the parent POM/Gradle
    plugin declares by default, since a project can (and often does) pin a
    different version than its parent.

    Returns (label, version, file, line, description) or None if nothing
    was found. `label` distinguishes "Spring Boot" from bare
    "Spring Framework", since they have separate support timelines.
    """
    for pom in _by_depth(target_path, iter_named_files(target_path, ("pom.xml",))):
        text = read_text_safe(pom)
        relative_file = str(pom.relative_to(target_path))

        prop_match = _POM_PROPERTY_VERSION_RE.search(text)
        if prop_match:
            prop_name, version = prop_match.group(1), prop_match.group(2)
            label = "Spring Boot" if "boot" in prop_name else "Spring Framework"
            return label, version, relative_file, _line_of(text, prop_match.start()), f"<{prop_name}> property"

        parent_match = _POM_PARENT_RE.search(text)
        if parent_match and "spring-boot-starter-parent" in parent_match.group("block"):
            version_match = _POM_VERSION_TAG_RE.search(parent_match.group("block"))
            if version_match:
                offset = parent_match.start() + version_match.start()
                return "Spring Boot", version_match.group(1), relative_file, _line_of(text, offset), "spring-boot-starter-parent parent POM"

    gradle_files = _by_depth(target_path, iter_named_files(target_path, ("build.gradle", "build.gradle.kts")))
    references_boot_plugin = False
    for build_file in gradle_files:
        text = read_text_safe(build_file)
        relative_file = str(build_file.relative_to(target_path))
        match = _GRADLE_BOOT_PLUGIN_RE.search(text)
        if match:
            return "Spring Boot", match.group(1), relative_file, _line_of(text, match.start()), "org.springframework.boot Gradle plugin"
        references_boot_plugin = references_boot_plugin or bool(_GRADLE_BOOT_PLUGIN_REFERENCED_RE.search(text))

    if references_boot_plugin:
        for catalog in _by_depth(target_path, iter_named_files(target_path, ("libs.versions.toml",))):
            text = read_text_safe(catalog)
            match = _VERSION_CATALOG_SPRING_BOOT_RE.search(text)
            if match:
                relative_file = str(catalog.relative_to(target_path))
                return "Spring Boot", match.group(2), relative_file, _line_of(text, match.start()), f"[{match.group(1)}] in Gradle version catalog"

    return None


def _classify_spring_version(label: str, version: str) -> tuple[str, str]:
    """Not a CVE feed -- just a coarse, major-version-bucketed staleness
    check against Spring's own published support timeline, so a clearly
    ancient runtime gets flagged loudly and a current-looking one still
    gets a nudge to verify the exact minor/patch line's status.
    """
    leading = version.split(".", 1)[0]
    major = int(leading) if leading.isdigit() else None
    support_url = (
        "https://spring.io/projects/spring-boot#support"
        if label == "Spring Boot"
        else "https://spring.io/projects/spring-framework#support"
    )

    if major is None:
        return "info", f"Could not parse a major version from '{version}' -- verify manually at {support_url}."

    eol_major = 1 if label == "Spring Boot" else 4
    tail_major = 2 if label == "Spring Boot" else 5

    if major <= eol_major:
        return "high", f"{label} {major}.x is end of life and receives no security patches -- upgrading is strongly recommended."
    if major == tail_major:
        return "medium", f"{label} {major}.x is on or past the tail of its OSS support window -- confirm this minor/patch line still receives security patches at {support_url}, and cross-check for known CVEs (NVD, Spring Security Advisories)."
    return "info", f"{label} {version} detected -- confirm this specific minor/patch line is still within Spring's active support window ({support_url}) and check for known CVEs."


def _detect_cors_wildcards(target_path) -> list[Finding]:
    """@CrossOrigin with no explicit origins (Spring's own default in that
    case is to allow all) or an explicit "*" -- both mean any site can make
    a cross-origin request against this controller/method.
    """
    findings: list[Finding] = []
    for java_file in iter_files(target_path, (".java",)):
        text = read_text_safe(java_file)
        try:
            tree = javalang.parse.parse(text)
        except Exception:
            continue
        relative_file = str(java_file.relative_to(target_path))

        for _, node in tree.filter(javalang.tree.Annotation):
            if node.name != "CrossOrigin" or not node.position:
                continue
            values = _annotation_values(node)
            origins = values.get("value") or values.get("origins")
            if origins is None or "*" in origins:
                description = f"@CrossOrigin{'(origins=' + origins + ')' if origins else ''}".strip()
                findings.append(config_checks.cors_wildcard_finding(relative_file, node.position.line, description))
    return findings


@register("java", "spring")
class SpringAnalyzer(BaseFrameworkAnalyzer):
    def find_routes(self) -> list[Route]:
        routes: list[Route] = []

        for java_file in iter_files(self.target_path, (".java",)):
            text = read_text_safe(java_file)
            try:
                tree = javalang.parse.parse(text)
            except Exception:
                # javalang chokes on some valid-but-uncommon syntax (newer
                # language features, malformed snippets, etc) -- skip rather
                # than aborting the whole scan over one file.
                continue

            for _, class_node in tree.filter(javalang.tree.ClassDeclaration):
                class_annotation_names = {a.name for a in class_node.annotations}
                if not ({"RestController", "Controller"} & class_annotation_names):
                    continue

                class_validated = "Validated" in class_annotation_names
                # A class-level @PreAuthorize/@Secured/etc applies to every
                # method in the controller -- missing this used to make
                # every route in such a class a false-positive AUTH-001,
                # the same shape of bug as the class-level @Validated gap.
                class_auth_decorators = sorted(class_annotation_names & KNOWN_AUTH_INDICATORS)
                base_path = ""
                for annotation in class_node.annotations:
                    if annotation.name == "RequestMapping":
                        base_values = _annotation_values(annotation)
                        base_path = base_values.get("value") or base_values.get("path") or ""

                for member in class_node.body:
                    if not isinstance(member, javalang.tree.MethodDeclaration):
                        continue

                    mapping_annotation = next(
                        (a for a in member.annotations if a.name in _MAPPING_ANNOTATIONS), None
                    )
                    if mapping_annotation is None:
                        continue

                    values = _annotation_values(mapping_annotation)
                    # `path` is Spring's own alias for `value` -- functionally
                    # identical, but required (or just commonly used) instead
                    # of the bare/positional `value` as soon as another named
                    # attribute like `produces`/`method` is also set, e.g.
                    # `@GetMapping(path = "/{id}", produces = "...")`. Missing
                    # this silently truncated the whole sub-path -- not just
                    # one param -- down to the class-level base path.
                    sub_path = values.get("value") or values.get("path") or ""
                    full_path = (base_path.rstrip("/") + "/" + sub_path.lstrip("/")).rstrip("/") or "/"

                    method = values.get("method", "").upper()
                    if method not in _HTTP_METHODS:
                        method = _MAPPING_ANNOTATIONS[mapping_annotation.name]

                    auth_decorators = list(dict.fromkeys(
                        class_auth_decorators
                        + [a.name for a in member.annotations if a.name in KNOWN_AUTH_INDICATORS]
                    ))

                    method_line = member.position.line if member.position else 0
                    annotation_lines = [a.position.line for a in member.annotations if a.position]
                    start_line = min([method_line, *annotation_lines]) if method_line else 0
                    end_line = _method_end_line(text, method_line) if method_line else 0

                    routes.append(
                        Route(
                            path=full_path,
                            methods=[method],
                            handler_name=member.name,
                            file=str(java_file.relative_to(self.target_path)),
                            line=method_line,
                            auth_decorators=auth_decorators,
                            raw_snippet=f"@{mapping_annotation.name}(...) {member.name}(...)",
                            source_start_line=start_line or None,
                            source_end_line=end_line or None,
                            extra_param_names=_extra_param_names(member),
                            path_variable_binding_names=_path_variable_binding_names(member),
                            param_validations=_param_validations(member),
                            class_validated=class_validated,
                            request_body_validations=_request_body_param_validations(member),
                            xml_media_types=_xml_media_types(mapping_annotation),
                        )
                    )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        findings += validation_checks.check_validation_without_class_annotation(routes)
        findings += validation_checks.check_request_body_without_valid(routes)
        findings += xml_checks.check_xml_media_type_routes(routes)
        findings += _detect_cors_wildcards(self.target_path)
        findings += _detect_csrf_disabled(self.target_path)
        findings += _detect_actuator_exposure(self.target_path)
        # TODO: Spring-specific checks -- e.g. JPA repository methods
        # exposed directly (Spring Data REST) without ownership filtering.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_security_filter_chain(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)

        routes_with_auth_annotations = [r for r in result.routes if r.auth_decorators]
        if routes_with_auth_annotations and not _detect_method_security_enabled(self.target_path):
            first = routes_with_auth_annotations[0]
            indicator_names = sorted({d for r in routes_with_auth_annotations for d in r.auth_decorators})
            result.findings.append(
                auth_checks.method_security_not_enabled_finding(first.file, first.line, indicator_names)
            )

        matcher_rules = _extract_security_matchers(self.target_path)
        if matcher_rules:
            for route in result.routes:
                if route.auth_decorators:
                    continue
                verdict = _resolve_matcher_coverage(route.path, matcher_rules)
                if verdict is None:
                    continue
                route.auth_matcher_verdict = verdict
                for finding in result.findings:
                    if finding.check_id == "AUTH-001" and finding.route is route:
                        auth_checks.apply_matcher_verdict(finding, verdict)
                        break

            actuator_finding = next((f for f in result.findings if f.check_id == "AUTH-004"), None)
            if actuator_finding is not None:
                actuator_verdict = _resolve_matcher_coverage("/actuator/env", matcher_rules)
                if actuator_verdict and actuator_verdict.lower().startswith("permitall"):
                    result.findings.append(
                        auth_checks.actuator_not_covered_finding(
                            actuator_finding.file, actuator_finding.line, actuator_verdict
                        )
                    )

        version_info = _detect_spring_version(self.target_path)
        if version_info:
            label, version, file, line, description = version_info
            result.framework_version = version
            result.framework_version_label = label
            result.framework_version_source = (file, line, description)
            severity, note = _classify_spring_version(label, version)
            result.findings.append(
                config_checks.outdated_framework_finding(file, line, severity, label, version, note)
            )
        return result
