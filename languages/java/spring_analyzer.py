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


def _annotation_values(annotation) -> dict[str, str]:
    """Normalize `@X("path")` and `@X(value="path", method=RequestMethod.POST)`
    into a {"value": "path", "method": "POST"} dict.
    """
    element = annotation.element
    if element is None:
        return {}
    if isinstance(element, javalang.tree.Literal):
        return {"value": _clean_literal(element.value)}

    result: dict[str, str] = {}
    if isinstance(element, list):
        for pair in element:
            if not isinstance(pair, javalang.tree.ElementValuePair):
                continue
            value = pair.value
            if isinstance(value, javalang.tree.Literal):
                result[pair.name] = _clean_literal(value.value)
            elif isinstance(value, javalang.tree.MemberReference):
                result[pair.name] = value.member
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


def _request_body_param_validations(member) -> dict[str, bool]:
    """@RequestBody params, keyed by name, valued True if the parameter
    itself carries @Valid or @Validated -- the trigger Spring needs to
    cascade Bean Validation into the DTO's own field constraints. Without
    it, whatever @NotBlank/@Size/etc constraints live on the DTO class are
    silently never checked -- same failure mode as the class-level
    @Validated gate below, but for request bodies instead of path/query
    params.
    """
    result: dict[str, bool] = {}
    for param in member.parameters:
        ann_names = {a.name for a in param.annotations}
        if "RequestBody" not in ann_names:
            continue
        result[param.name] = bool({"Valid", "Validated"} & ann_names)
    return result


def _param_validations(member) -> dict[str, list[str]]:
    """Bean Validation constraint annotations on each @PathVariable/
    @RequestParam of `member`, keyed by param name -- an empty list means
    the param was seen but carries no recognized constraint annotation.
    Deliberately scoped to these two (rather than every parameter): they're
    the ones Spring only validates via the class-level @Validated AOP path,
    unlike a @Valid @RequestBody DTO, which validates independently of it.
    """
    result: dict[str, list[str]] = {}
    for param in member.parameters:
        ann_names = {a.name for a in param.annotations}
        if "PathVariable" not in ann_names and "RequestParam" not in ann_names:
            continue
        result[param.name] = sorted(ann_names & KNOWN_VALIDATION_CONSTRAINTS)
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
                base_path = ""
                for annotation in class_node.annotations:
                    if annotation.name == "RequestMapping":
                        base_path = _annotation_values(annotation).get("value", "")

                for member in class_node.body:
                    if not isinstance(member, javalang.tree.MethodDeclaration):
                        continue

                    mapping_annotation = next(
                        (a for a in member.annotations if a.name in _MAPPING_ANNOTATIONS), None
                    )
                    if mapping_annotation is None:
                        continue

                    values = _annotation_values(mapping_annotation)
                    sub_path = values.get("value", "")
                    full_path = (base_path.rstrip("/") + "/" + sub_path.lstrip("/")).rstrip("/") or "/"

                    method = values.get("method", "").upper()
                    if method not in _HTTP_METHODS:
                        method = _MAPPING_ANNOTATIONS[mapping_annotation.name]

                    auth_decorators = [a.name for a in member.annotations if a.name in KNOWN_AUTH_INDICATORS]

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
                            param_validations=_param_validations(member),
                            class_validated=class_validated,
                            request_body_validations=_request_body_param_validations(member),
                        )
                    )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        findings += validation_checks.check_validation_without_class_annotation(routes)
        findings += validation_checks.check_request_body_without_valid(routes)
        findings += _detect_cors_wildcards(self.target_path)
        # TODO: Spring-specific checks -- e.g. missing CSRF config, JPA
        # repository methods exposed directly (Spring Data REST) without
        # ownership filtering.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_security_filter_chain(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)

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
