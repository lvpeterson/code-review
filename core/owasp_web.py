"""Maps check IDs to OWASP Web Top 10 2025, Web Top 10 2021 and API Top 10 2023.
https://owasp.org/Top10/ and https://owasp.org/API-Security/

Every language is tagged: dotnet_legacy fills Finding.owasp when a finding
is created (checks.dnl.findings.dnl_finding); every other finding is filled
by tag_results() after the analyzers run. This is separate from
core/owasp_isr.py, which tags the infrastructure ISR category and stays in
Finding.category.

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
_add(["DNL-CFG-008", "DNL-CFG-009"], "A02", "A05", "API8")
_add(["DNL-XSS-002"], "A05", "A03", None)
_add([f"DNL-SESS-00{n}" for n in range(1, 5)], "A07", "A07", "API2")
_add(["DNL-SESS-005"], "A04", "A02", "API2")
_add(["DNL-INT-001", "DNL-INT-002"], "A08", "A08", None)
_add(["DNL-SEC-001", "DNL-SEC-002"], "A07", "A07", "API2")
_add(["DNL-INV-001"], "A02", "A05", "API9", "always")
_add(["DNL-RES-001"], "A06", "A04", "API4")
_add([f"DNL-AUTHZ-00{n}" for n in range(1, 5)], "A01", "A01", "API5")
_add(["DNL-AUTHZ-008"], "A01", "A01", "API5")
_add(["DNL-CSRF-001"], "A01", "A01", None)
# Taint-analysis rules (Plan 2).
_add([f"DNL-INJ-00{n}" for n in range(1, 7)], "A05", "A03", "API8")
_add(["DNL-XSS-001", "DNL-XSS-003", "DNL-XSS-004"], "A05", "A03", None)
_add(["DNL-PATH-001", "DNL-REDIR-001"], "A01", "A01", None)
_add(["DNL-SSRF-001"], "A01", "A10", "API7")
_add(["DNL-LOG-001"], "A09", "A09", None)
_add(["DNL-AUTHZ-005"], "A01", "A01", "API1")
_add(["DNL-AUTHZ-006", "DNL-AUTHZ-007"], "A06", "A04", "API3")
# WCF configuration rules (Plan 3).
_add(["DNL-WCF-001", "DNL-WCF-002"], "A02", "A05", "API8")
_add(["DNL-WCF-003"], "A02", "A05", "API9", "always")
_add(["DNL-WCF-004"], "A06", "A04", "API4")
# Crypto and hardcoded secrets in code (Plan 3).
_add(["DNL-CRY-001", "DNL-CRY-002", "DNL-CRY-003", "DNL-CRY-004", "DNL-CRY-005", "DNL-CRY-007", "DNL-CRY-008"],
     "A04", "A02", None)
_add(["DNL-CRY-006"], "A08", "A08", "API10", "always")
_add(["DNL-SEC-003"], "A07", "A07", "API2")
# Insecure deserialization and XXE (Plan 3).
_add(["DNL-DESER-001", "DNL-DESER-002", "DNL-DESER-003"], "A08", "A08", None)
_add(["DNL-XXE-001", "DNL-XXE-002"], "A02", "A05", "API8")
# Integrity markup and session/auth code rules (Plan 3).
_add(["DNL-INT-003", "DNL-INT-004"], "A08", "A08", None)
_add(["DNL-SESS-006", "DNL-SESS-007", "DNL-SESS-008"], "A07", "A07", "API2")
# Exception handling.
_add(["DNL-ERR-001", "DNL-ERR-003"], "A10", "A04", None)
_add(["DNL-ERR-002"], "A10", "A05", "API8")
# Logging, business-flow, resource, inventory and API-consumption rules.
_add(["DNL-LOG-002", "DNL-LOG-003", "DNL-LOG-004"], "A09", "A09", None)
_add(["DNL-DES-001"], "A06", "A04", "API6", "always")
_add(["DNL-RES-002", "DNL-RES-003"], "A06", "A04", "API4")
_add(["DNL-INV-002"], "A02", "A05", "API9", "always")
_add(["DNL-CONSUME-001", "DNL-CONSUME-002"], "A08", "A08", "API10", "always")
# Offline SCA rules (Plan 4).
_add(["DNL-SCA-001", "DNL-SCA-002", "DNL-SCA-004"], "A03", "A06", None)
_add(["DNL-SCA-003"], "A03", "A06", "API9", "always")
_add(["DNL-SCA-005"], "A03", "A08", None)

# ---------------------------------------------------------------------------
# Application rules (checks/auth.py, idor.py, injection.py, ... and the
# Lambda / PL/SQL scanners). Where a DNL rule covers the same risk the
# category pair mirrors it, so one risk reads the same in every language.
# ---------------------------------------------------------------------------
# Access control. AUTH-001 / AUTH-002 / AUTH-005 / PROXY-001 are
# function-level (API5); IDOR is object-level (API1).
_add(["AUTH-001", "AUTH-002", "AUTH-005", "PROXY-001"], "A01", "A01", "API5")
_add(["AUTH-003"], "A01", "A01", None)                      # CSRF, as DNL-CSRF-001
_add(["AUTH-004"], "A02", "A05", "API8")                    # exposed actuator endpoints = misconfig
_add(["AUTH-006"], "A07", "A07", "API2")                    # cookie flags, as DNL-SESS-001/002
_add(["IDOR-001"], "A01", "A01", "API1")
# Mass assignment: API3 (object property level). The web categories follow
# DNL-AUTHZ-006/007 (over-posting) -> Insecure Design; CWE-915 is also
# listed under A08, but the DNL precedent is kept so one risk reads the same.
_add(["MASS-001"], "A06", "A04", "API3")
# Injection family. API8 mirrors DNL-INJ-*; it only appears on an API surface.
_add(["SQLI-001", "CMD-001", "SORT-001"], "A05", "A03", "API8")
_add(["VALID-001", "VALID-002"], "A05", "A03", None)         # CWE-20 sits under Injection in both lists
_add(["PATH-001", "REDIRECT-001"], "A01", "A01", None)       # as DNL-PATH-001 / DNL-REDIR-001
# SSRF: merged into A01 in 2025, A10 in 2021. API7 is tagged unconditionally.
_add(["SSRF-001"], "A01", "A10", "API7", "always")
_add(["XML-001"], "A02", "A05", "API8")                      # XXE review, as DNL-XXE-001
_add(["DESER-001"], "A08", "A08", None)
_add(["CONFIG-001", "CONFIG-002"], "A02", "A05", "API8")     # debug mode / CORS, as DNL-CFG-*
_add(["CONFIG-003"], "A03", "A06", "API9", "always")         # EOL framework, as DNL-SCA-003
_add(["SCA-001"], "A03", "A06", None)                        # as DNL-SCA-001
# Hardcoded credentials follow DNL-SEC-*; key material is cryptographic.
_add(["SECRET-001", "SECRET-003", "SECRET-004", "SECRET-005", "SECRET-006"], "A07", "A07", "API2")
_add(["SECRET-002"], "A04", "A02", None)
# AWS Lambda handler code (checks/aws_lambda.py).
_add(["LMB-001", "LMB-002", "LMB-004"], "A05", "A03", "API8")
_add(["LMB-003"], "A08", "A08", None)
_add(["LMB-005"], "A01", "A10", "API7", "always")
_add(["LMB-006", "LMB-013", "LMB-016", "LMB-017", "LMB-018", "LMB-019"], "A01", "A01", None)
_add(["LMB-007"], "A09", "A09", None)
_add(["LMB-008"], "A08", "A08", "API10", "always")           # TLS check off, as DNL-CRY-006
_add(["LMB-009"], "A06", "A04", "API4")                      # no timeout, as DNL-RES-*
_add(["LMB-010"], "A04", "A02", None)
_add(["LMB-011"], "A07", "A07", None)                        # secret in config, as TF-VAR-002
_add(["LMB-012"], "A10", "A05", "API8")                      # as DNL-ERR-002
_add(["LMB-014"], "A07", "A07", "API2")
_add(["LMB-015"], "A02", "A05", "API8")                      # as DNL-CFG-007
# Oracle PL/SQL (checks/plsql.py). Stored code has no HTTP surface, so no
# API tag is mapped.
_add([f"INJ-{n}" for n in range(1, 7)], "A05", "A03", None)
_add(["EXC-1", "EXC-2", "EXC-3"], "A10", "A04", None)        # as DNL-ERR-003
_add([f"AUTHZ-{n}" for n in range(1, 6)], "A01", "A01", None)
_add(["CRED-1", "CRED-2", "CRED-3"], "A07", "A07", None)
_add(["NET-1"], "A01", "A10", None)                          # outbound UTL_HTTP: SSRF-shaped
_add(["NET-2", "PRIV-3", "SYN-1"], "A01", "A01", None)
_add(["NET-3", "PRIV-1", "PRIV-2", "XSS-1", "XSS-2"], "A05", "A03", None)
_add(["NET-4", "DATA-2"], "A04", "A02", None)
_add([f"CRYPTO-{n}" for n in range(1, 5)], "A04", "A02", None)
_add(["PRAGMA-1", "DATA-1"], "A06", "A04", None)

# ---------------------------------------------------------------------------
# Infrastructure rules (Terraform, IAM policy JSON, GitLab CI, shell, repo
# files). Misconfiguration is A02:2025 / A05:2021. API Gateway and Lambda
# function URLs are API-serving resources, so they carry an API tag
# unconditionally ("always": no route says so for IaC); everything else has
# no API 2023 equivalent. Pinning and pipeline-integrity rules use A03:2025
# supply chain with A08:2021 (A06:2021 is about known-vulnerable versions).
# ---------------------------------------------------------------------------
_MISCONF = ("A02", "A05")
_CRYPTO = ("A04", "A02")
_AC = ("A01", "A01")
_LOGGING = ("A09", "A09")
_SECRETS = ("A07", "A07")
_PINNING = ("A03", "A08")
_OUTDATED = ("A03", "A06")
_INTEGRITY = ("A08", "A08")
_INJECTION = ("A05", "A03")


def _grp(ids, pair, api=None, mode="api_surface"):
    _add(ids, pair[0], pair[1], api, mode)


# Terraform
_grp(["TF-S3-001", "TF-S3-002", "TF-S3-007", "TF-IAM-001", "TF-IAM-002", "TF-LMB-006", "TF-LMB-007",
      "TF-LMB-008", "TF-OIDC-001"], _AC)
_grp(["TF-API-001", "TF-LMB-004"], _AC, "API5", "always")    # unauthenticated API entry point
_grp(["TF-S3-003", "TF-S3-006", "TF-DB-002", "TF-DB-005", "TF-DB-006", "TF-LMB-003", "TF-EKS-002",
      "TF-ENC-001", "TF-ENC-002", "TF-ENC-003", "TF-ENC-004", "TF-KMS-001", "TF-TLS-001", "TF-TLS-002",
      "TF-SEC-002", "TF-SEC-003", "TF-STATE-001", "TF-STATE-004", "TF-LOG-003", "TF-LOG-004"], _CRYPTO)
_grp(["TF-S3-004", "TF-S3-008", "TF-S3-009", "TF-EC2-001", "TF-EC2-002", "TF-NET-001", "TF-NET-002",
      "TF-NET-004", "TF-NET-005", "TF-NET-007", "TF-NET-008", "TF-DB-001", "TF-DB-003", "TF-DB-010",
      "TF-EKS-001", "TF-STATE-002", "TF-STATE-003", "TF-VAR-001", "TF-VAR-003", "TF-ASSET-001",
      "TF-ECS-001", "TF-ECS-003", "TF-CB-001"], _MISCONF)
_grp(["TF-LMB-005"], _MISCONF, "API8", "always")
_grp(["TF-S3-005", "TF-LOG-001", "TF-LOG-002", "TF-LOG-005", "TF-LOG-006", "TF-LOG-007", "TF-LOG-008",
      "TF-LOG-009", "TF-NET-006"], _LOGGING)
_grp(["TF-API-002"], _LOGGING, "API8", "always")             # request/response bodies end up in logs
_grp(["TF-DB-004", "TF-DB-008", "TF-DB-009", "TF-LMB-002", "TF-SEC-001", "TF-VAR-002", "TF-PROV-001",
      "TF-IAM-003", "TF-IAM-004", "TF-IAM-005", "TF-IAM-006", "TF-OIDC-002", "TF-ECS-002", "TF-CB-002"],
     _SECRETS)
_grp(["TF-DB-007", "TF-LMB-001", "TF-ECR-002"], _OUTDATED)
_grp(["TF-SUP-001", "TF-SUP-002", "TF-SUP-003", "TF-SUP-004"], _PINNING)
_grp(["TF-ECR-001", "TF-PROV-002", "TF-TLS-003", "TF-EXEC-002"], _INTEGRITY)
_grp(["TF-EXEC-001"], _INJECTION)                            # variables interpolated into a shell command
# IAM policy documents
_grp(["POL-001", "POL-002", "POL-003", "POL-004", "POL-005", "POL-006", "POL-007", "POL-010"], _AC)
_grp(["POL-008"], _CRYPTO)
_grp(["POL-009"], _SECRETS)
_grp(["POL-011"], _MISCONF)
# GitLab CI
_grp(["GL-001", "GL-011"], _MISCONF)
_grp(["GL-002", "GL-003"], _INJECTION)
_grp(["GL-004", "GL-007", "GL-008", "GL-013"], _SECRETS)
_grp(["GL-005", "GL-TF-003"], _CRYPTO)
_grp(["GL-006", "GL-012"], ("A06", "A04"))                   # security gate missing / non-blocking
_grp(["GL-IMG-001", "GL-INC-001", "GL-INC-002", "GL-INC-003"], _PINNING)
_grp(["GL-TF-001", "GL-TF-002", "GL-TF-004"], _INTEGRITY)
# Shell
_grp(["SH-001", "SH-002", "SH-007"], _INTEGRITY)
_grp(["SH-003"], _INJECTION)
_grp(["SH-004", "SH-023", "SH-025"], _AC)
_grp(["SH-005", "SH-008"], _MISCONF)
_grp(["SH-006", "SH-020", "SH-021", "SH-022"], ("A10", "A04"))  # failure ignored or unchecked
_grp(["SH-009", "SH-011", "SH-012", "SH-013", "SH-014", "SH-024"], _CRYPTO)
_grp(["SH-010", "SH-015", "SH-016", "SH-017"], _LOGGING)
# Repo hygiene
_grp(["REPO-001", "REPO-002", "REPO-004"], _CRYPTO)
_grp(["REPO-003"], _SECRETS)
_grp(["REPO-005"], _MISCONF)

# ---------------------------------------------------------------------------
# Crypto rules (Java / PHP crypto scanners, Bouncy Castle FIPS checks).
# Weak or misused cryptography is A04:2025 / A02:2021. TLS validation off
# follows DNL-CRY-006 (A08, API10 always).
# ---------------------------------------------------------------------------
_grp([f"JC-{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 14, 15, 17)], _CRYPTO)
_grp(["JC-011"], _INTEGRITY, "API10", "always")
_grp(["JC-013"], _SECRETS, "API2")                           # hardcoded keystore password
_grp(["JC-016", "PHP-009"], _LOGGING)
_grp(["JC-FIPS-001", "JC-FIPS-002", "JC-FIPS-003", "JC-FIPS-004", "JC-FIPS-007"], _CRYPTO)
_grp(["JC-FIPS-005", "JC-FIPS-006", "JC-FIPS-008", "JC-INV-001", "PHP-010"], _OUTDATED)
_grp([f"PHP-{n:03d}" for n in (1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15)], _CRYPTO)
_grp(["PHP-011"], _AC)
_grp(["PHP-012"], _INTEGRITY, "API10", "always")

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


# Frameworks whose whole purpose is serving an API, so every finding in the
# scan is on an API surface even when it has no route (project-wide config).
# Frameworks that serve both pages and JSON (Flask, Express, Rails, Spring
# MVC, ASP.NET MVC, net/http) are too vague to guess from the name; those
# analyzers either stamp Route.meta["api_surface"] (Spring: @RestController,
# ASP.NET Core: [ApiController] or a minimal-API route) or stay False.
API_FRAMEWORKS = frozenset({"fastapi", "gin", "hono"})


def api_surface_for(result, finding) -> bool:
    """Whether `finding` sits on an API surface.

    1. The finding's route says so explicitly: Route.meta["api_surface"].
    2. Otherwise the scan's framework is API-only (API_FRAMEWORKS).
    3. Otherwise False -- infra, crypto and PL/SQL findings never count.
    """
    route = finding.route
    if route is not None and "api_surface" in route.meta:
        return bool(route.meta["api_surface"])
    return result.framework in API_FRAMEWORKS


def tag_results(results) -> None:
    """Fill Finding.owasp on every finding that has none yet.

    Runs after the analyzers (and again after --sca results are appended),
    before any report is written. Findings
    that already carry tags (dotnet_legacy fills its own) are left alone, so
    calling this twice is harmless.
    """
    for result in results:
        for finding in result.findings:
            if not finding.owasp:
                finding.owasp = owasp_for(finding.check_id, api_surface_for(result, finding))
