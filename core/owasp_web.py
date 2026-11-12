"""Maps check IDs to OWASP Web Top 10 2025, Web Top 10 2021 and API Top 10 2023.
https://owasp.org/Top10/ and https://owasp.org/API-Security/

Used by the dotnet_legacy checks (via checks.dnl.findings.dnl_finding) to
fill Finding.owasp. This is separate from core/owasp_isr.py, which tags the
infrastructure ISR category and stays in Finding.category.

Lookup order: exact check id, then longest matching prefix. The API 2023 tag
is only emitted when the rule's api_mode is "always", or it is
"api_surface" and the caller says the finding sits on an API surface.
"""
from __future__ import annotations

from typing import Optional

TITLES: dict[str, dict[str, str]] = {
    "2025": {
        "A01": "Broken Access Control",
        "A02": "Security Misconfiguration",
        "A03": "Software Supply Chain Failures",
        "A04": "Cryptographic Failures",
        "A05": "Injection",
        "A06": "Insecure Design",
        "A07": "Authentication Failures",
        "A08": "Software or Data Integrity Failures",
        "A09": "Security Logging and Alerting Failures",
        "A10": "Mishandling of Exceptional Conditions",
    },
    "2021": {
        "A01": "Broken Access Control",
        "A02": "Cryptographic Failures",
        "A03": "Injection",
        "A04": "Insecure Design",
        "A05": "Security Misconfiguration",
        "A06": "Vulnerable and Outdated Components",
        "A07": "Identification and Authentication Failures",
        "A08": "Software and Data Integrity Failures",
        "A09": "Security Logging and Monitoring Failures",
        "A10": "Server-Side Request Forgery",
    },
    "api2023": {
        "API1": "Broken Object Level Authorization",
        "API2": "Broken Authentication",
        "API3": "Broken Object Property Level Authorization",
        "API4": "Unrestricted Resource Consumption",
        "API5": "Broken Function Level Authorization",
        "API6": "Unrestricted Access to Sensitive Business Flows",
        "API7": "Server Side Request Forgery",
        "API8": "Security Misconfiguration",
        "API9": "Improper Inventory Management",
        "API10": "Unsafe Consumption of APIs",
    },
}

_YEARS = {"2025": "2025", "2021": "2021", "api2023": "2023"}

# id -> (code2025, code2021, api code or None, api_mode)
RULES: dict[str, tuple[str, str, Optional[str], str]] = {}


def _add(ids, c25, c21, api, mode="api_surface"):
    for i in ids:
        RULES[i] = (c25, c21, api, mode)


_add([f"DNL-CFG-00{n}" for n in range(1, 8)], "A02", "A05", "API8")
_add(["DNL-XSS-002"], "A05", "A03", None)
_add([f"DNL-SESS-00{n}" for n in range(1, 5)], "A07", "A07", "API2")
_add(["DNL-SESS-005"], "A04", "A02", "API2")
_add(["DNL-INT-001", "DNL-INT-002"], "A08", "A08", None)
_add(["DNL-SEC-001", "DNL-SEC-002"], "A07", "A07", "API2")
_add(["DNL-INV-001"], "A02", "A05", "API9", "always")
_add(["DNL-RES-001"], "A06", "A04", "API4")
_add([f"DNL-AUTHZ-00{n}" for n in range(1, 5)], "A01", "A01", "API5")
_add(["DNL-CSRF-001"], "A01", "A01", None)
# Taint-analysis rules (Plan 2).
_add([f"DNL-INJ-00{n}" for n in range(1, 7)], "A05", "A03", "API8")
_add(["DNL-XSS-001", "DNL-XSS-003", "DNL-XSS-004"], "A05", "A03", None)
_add(["DNL-PATH-001", "DNL-REDIR-001"], "A01", "A01", None)
_add(["DNL-SSRF-001"], "A01", "A10", "API7")
_add(["DNL-LOG-001"], "A09", "A09", None)
_add(["DNL-AUTHZ-005"], "A01", "A01", "API1")
_add(["DNL-AUTHZ-006", "DNL-AUTHZ-007"], "A06", "A04", "API3")

_PREFIX: list[tuple[str, tuple[str, str, Optional[str], str]]] = []


def _label(key: str, code: str) -> str:
    return f"{code}:{_YEARS[key]} {TITLES[key][code]}"


def owasp_for(check_id: str, api_surface: bool = False) -> dict[str, str]:
    """{"2025": "A05:2025 Injection", "2021": ..., "api2023": ...} or {}."""
    rule = RULES.get(check_id)
    if rule is None:
        for prefix, r in sorted(_PREFIX, key=lambda p: -len(p[0])):
            if check_id.startswith(prefix):
                rule = r
                break
    if rule is None:
        return {}
    c25, c21, api, mode = rule
    out = {"2025": _label("2025", c25), "2021": _label("2021", c21)}
    if api and (mode == "always" or api_surface):
        out["api2023"] = _label("api2023", api)
    return out
