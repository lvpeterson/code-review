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
from core.models import Finding, Route
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

                    routes.append(
                        Route(
                            path=full_path,
                            methods=[method],
                            handler_name=member.name,
                            file=str(java_file.relative_to(self.target_path)),
                            line=member.position.line if member.position else 0,
                            auth_decorators=auth_decorators,
                            raw_snippet=f"@{mapping_annotation.name}(...) {member.name}(...)",
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
