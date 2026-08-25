"""Deep-dive analyzer for Spring (Boot/MVC) targets.

Uses javalang to parse a real Java AST instead of regex/line-window
scanning -- annotations are resolved as actual class/method attributes, so
class-level vs method-level @RequestMapping can't be confused, and an auth
annotation is found regardless of whether it's written above or below the
mapping annotation it's paired with.
"""
from __future__ import annotations

import javalang

from checks import auth as auth_checks
from checks import idor as idor_checks
from core.base import BaseFrameworkAnalyzer
from core.fsutil import iter_files, read_text_safe
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
                        )
                    )

        return routes

    def run_baseline_checks(self, routes: list[Route]) -> list[Finding]:
        findings: list[Finding] = []
        findings += idor_checks.check_id_param_routes(routes)
        findings += auth_checks.check_missing_auth_indicator(routes, KNOWN_AUTH_INDICATORS)
        # TODO: Spring-specific checks -- e.g. @CrossOrigin("*"), missing
        # CSRF config, JPA repository methods exposed directly (Spring Data
        # REST) without ownership filtering.
        return findings

    def analyze(self) -> ScanResult:
        result = super().analyze()
        detected = _detect_global_security_filter_chain(self.target_path)
        if detected:
            auth_checks.apply_global_auth_note(result, *detected)
        return result
