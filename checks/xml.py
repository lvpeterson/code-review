"""XML-format route heuristics.

A route that produces/consumes XML means some XML parser handles this
request somewhere -- and an XML parser that hasn't explicitly disabled
external entity resolution is vulnerable to XXE (XML External Entity
injection): a malicious payload that gets the parser to read local files or
make outbound requests. This is a distinct vulnerability class from
everything else this tool checks (unparameterized SQL, IDOR, missing auth/
validation), and this check can only flag that XML is in play -- it can't
verify whether whatever parser handles it (JAXB, a custom
HttpMessageConverter, a raw DocumentBuilderFactory/SAXParserFactory/
XMLInputFactory) is actually hardened. That's a manual follow-up.
"""
from __future__ import annotations

from core.models import Finding, Route


def check_xml_media_type_routes(routes: list[Route]) -> list[Finding]:
    findings: list[Finding] = []
    for route in routes:
        if not route.xml_media_types:
            continue

        media_types = sorted(set(route.xml_media_types))
        findings.append(
            Finding(
                check_id="XML-001",
                severity="medium",
                title=f"Route produces/consumes XML ({', '.join(media_types)})",
                description=(
                    "This route's produces/consumes declares an XML media type. XML "
                    "parsers that haven't explicitly disabled external entity resolution "
                    "are vulnerable to XXE -- check whatever parser actually handles this "
                    "route (JAXB, a custom HttpMessageConverter, a raw "
                    "DocumentBuilderFactory/SAXParserFactory/XMLInputFactory) for external "
                    "entity processing being disabled. Detected via literal media-type "
                    "strings and Spring's own MediaType.*_XML_VALUE-style constants -- a "
                    "custom enum/constants class a codebase defines itself to hold "
                    "media-type strings won't be resolved by this heuristic, so the "
                    "absence of this finding elsewhere doesn't confirm there's no XML "
                    "route; check for one if this codebase has such a class."
                ),
                file=route.file,
                line=route.line,
                route=route,
            )
        )
    return findings
