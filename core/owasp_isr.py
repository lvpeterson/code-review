"""Maps check IDs to the OWASP Top 10 Infrastructure Security Risks (2024).
https://owasp.org/www-project-top-10-infrastructure-security-risks/

Every finding produced through core.rulescan.make_finding() gets a
`category` from here, which the HTML report (Infrastructure tab coverage
table + per-finding badge), JSON and SARIF (as a rule tag) carry through.

Lookup order: exact check id, then longest matching prefix. Add new rules
here when you add them -- tests/test_owasp_isr.py fails if an infra/crypto/
lambda rule id has no mapping.
"""
from __future__ import annotations

from typing import Optional

ISR_TITLES = {
    "ISR01": "Outdated Software",
    "ISR02": "Insufficient Threat Detection",
    "ISR03": "Insecure Configurations",
    "ISR04": "Insecure Resource and User Management",
    "ISR05": "Insecure Use of Cryptography",
    "ISR06": "Insecure Network Access Management",
    "ISR07": "Insecure Authentication Methods and Default Credentials",
    "ISR08": "Information Leakage",
    "ISR09": "Insecure Access to Resources and Management Components",
    "ISR10": "Insufficient Asset Management and Documentation",
}

_EXACT = {
    # Terraform
    "TF-S3-001": "ISR09", "TF-S3-002": "ISR09", "TF-S3-003": "ISR05", "TF-S3-004": "ISR03",
    "TF-S3-005": "ISR02", "TF-S3-006": "ISR05", "TF-S3-007": "ISR09", "TF-S3-008": "ISR09",
    "TF-S3-009": "ISR09",
    "TF-EC2-001": "ISR09", "TF-EC2-002": "ISR06",
    "TF-DB-001": "ISR06", "TF-DB-002": "ISR05", "TF-DB-003": "ISR03", "TF-DB-004": "ISR08",
    "TF-DB-005": "ISR05", "TF-DB-006": "ISR05", "TF-DB-007": "ISR01", "TF-DB-008": "ISR07",
    "TF-DB-009": "ISR07",
    "TF-LMB-001": "ISR01", "TF-LMB-002": "ISR08", "TF-LMB-003": "ISR05", "TF-LMB-004": "ISR07",
    "TF-LMB-005": "ISR09", "TF-LMB-006": "ISR09", "TF-LMB-007": "ISR09", "TF-LMB-008": "ISR09",
    "TF-API-001": "ISR07", "TF-API-002": "ISR08",
    "TF-EKS-001": "ISR09", "TF-EKS-002": "ISR05",
    "TF-SEC-001": "ISR07", "TF-SEC-002": "ISR05", "TF-SEC-003": "ISR08",
    "TF-ECR-001": "ISR03", "TF-ECR-002": "ISR01",
    "TF-STATE-001": "ISR05", "TF-STATE-002": "ISR03", "TF-STATE-003": "ISR08", "TF-STATE-004": "ISR05",
    "TF-VAR-001": "ISR08", "TF-VAR-002": "ISR07", "TF-VAR-003": "ISR08",
    "TF-PROV-001": "ISR07", "TF-PROV-002": "ISR05",
    "TF-EXEC-001": "ISR03", "TF-EXEC-002": "ISR03",
    "TF-IAM-001": "ISR04", "TF-IAM-002": "ISR04", "TF-IAM-003": "ISR07", "TF-IAM-004": "ISR08",
    "TF-IAM-005": "ISR07",
    "TF-SUP-004": "ISR10",
    "TF-NET-005": "ISR03",
    "TF-ECS-002": "ISR08", "TF-CB-002": "ISR08", "TF-DB-010": "ISR03", "TF-IAM-006": "ISR07",
    "GL-TF-004": "ISR07", "LMB-019": "ISR04",
    # IAM policy documents
    "POL-005": "ISR09", "POL-008": "ISR05", "POL-009": "ISR07", "POL-010": "ISR07", "POL-011": "ISR03",
    # GitLab CI
    "GL-001": "ISR08", "GL-002": "ISR03", "GL-003": "ISR03", "GL-004": "ISR08", "GL-005": "ISR06",
    "GL-006": "ISR10", "GL-007": "ISR07", "GL-008": "ISR07", "GL-011": "ISR03", "GL-012": "ISR10",
    "GL-013": "ISR07", "GL-TF-003": "ISR08",
    # Shell
    "SH-001": "ISR03", "SH-002": "ISR05", "SH-003": "ISR03", "SH-004": "ISR04", "SH-005": "ISR08",
    "SH-006": "ISR03", "SH-007": "ISR03", "SH-008": "ISR03", "SH-009": "ISR08", "SH-010": "ISR08",
    "SH-011": "ISR08", "SH-012": "ISR05", "SH-013": "ISR05", "SH-014": "ISR05", "SH-015": "ISR08",
    "SH-016": "ISR08", "SH-017": "ISR08", "SH-020": "ISR03", "SH-021": "ISR03", "SH-022": "ISR03",
    "SH-023": "ISR08", "SH-024": "ISR08", "SH-025": "ISR04",
    # Repo hygiene
    "REPO-001": "ISR08", "REPO-002": "ISR07", "REPO-003": "ISR08", "REPO-004": "ISR08", "REPO-005": "ISR08",
    # Java / PHP crypto: mostly ISR05, exceptions here
    "JC-013": "ISR07", "JC-FIPS-005": "ISR01", "JC-FIPS-006": "ISR01", "JC-FIPS-008": "ISR01",
    "JC-INV-001": "ISR10", "JC-016": "ISR08",
    "PHP-010": "ISR01", "PHP-009": "ISR08",
    # Lambda
    "LMB-007": "ISR08", "LMB-008": "ISR05", "LMB-011": "ISR08", "LMB-012": "ISR08",
    "LMB-013": "ISR09", "LMB-014": "ISR07", "LMB-009": "ISR03", "LMB-010": "ISR05",
    "LMB-015": "ISR09", "LMB-016": "ISR09", "LMB-018": "ISR08",
}

_PREFIX = [
    ("TF-NET-", "ISR06"), ("TF-ENC-", "ISR05"), ("TF-KMS-", "ISR05"), ("TF-TLS-", "ISR05"),
    ("TF-LOG-", "ISR02"), ("TF-SUP-", "ISR01"), ("TF-ASSET-", "ISR10"),
    ("TF-ECS-", "ISR03"), ("TF-CB-", "ISR03"), ("TF-OIDC-", "ISR07"), ("SCA-", "ISR01"),
    ("POL-", "ISR04"), ("SECRET-", "ISR07"), ("GL-IMG-", "ISR01"), ("GL-INC-", "ISR01"),
    ("GL-TF-", "ISR03"), ("JC-", "ISR05"), ("PHP-", "ISR05"), ("LMB-", "ISR03"),
]


def isr_for(check_id: str) -> Optional[str]:
    """'ISR05:2024 Insecure Use of Cryptography' style label, or None."""
    code = _EXACT.get(check_id)
    if code is None:
        for prefix, c in sorted(_PREFIX, key=lambda p: -len(p[0])):
            if check_id.startswith(prefix):
                code = c
                break
    if code is None:
        return None
    return f"{code}:2024 {ISR_TITLES[code]}"


def isr_code(category: Optional[str]) -> Optional[str]:
    return category.split(":", 1)[0] if category else None
