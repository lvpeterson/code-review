"""Hardcoded-credential rules shared by every file-oriented analyzer
(Terraform, GitLab CI, shell, Lambda, Java/PHP crypto).

SECRET-001..004 match well-known token formats (high confidence);
SECRET-005 is the generic "secret-sounding name = literal value" heuristic,
filtered to skip obvious references/placeholders (${var}, $ENV, <changeme>,
var.x, os.environ[...], empty strings).
"""
from __future__ import annotations

import re

from core.rulescan import LineRule

# Name fragments that make an assignment "secret-sounding".
_SECRET_NAME = (
    r"(?:password|passwd|passphrase|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"secret[_-]?key|private[_-]?key|client[_-]?secret|auth[_-]?key|credentials?|key[_-]?pass)"
)

# A value that is clearly not a literal secret.
_PLACEHOLDER = re.compile(
    r"""(?ix)^(?:
        \$\{?.*            # ${VAR} / $VAR / ${var.x}
      | \{\{.*             # {{ template }}
      | <[^>]*>            # <your-password-here>
      | %\(?\w+.*          # %(name)s / %VAR%
      | (?:var|local|data|module|each|aws_\w+)\..*    # Terraform reference
      | (?:os\.environ|os\.getenv|getenv|process\.env|System\.getenv|env\(|ENV\[).*
      | (?:true|false|null|none|nil|undefined|yes|no)
      | x{3,}|\*{3,}|\.{3,}
      | (?:example|sample|dummy|placeholder|redacted|your[_-].*|test)
    )$"""
)

_GENERIC_SECRET = re.compile(
    r"""(?ix)
    (?P<name>[\w.-]*""" + _SECRET_NAME + r"""[\w.-]*)["']?   # the key / variable name
    \s*(?::=|=>|=|:)\s*                                       # assignment in most syntaxes
    (?P<q>["'])(?P<value>[^"'\n]{4,})(?P=q)                   # a quoted literal
    """
)

# Unquoted form, for YAML (`DB_PASSWORD: hunter22`) and shell
# (`export DB_PASSWORD=hunter22`).
_GENERIC_SECRET_BARE = re.compile(
    r"""(?ix)
    ^\s*(?:export\s+|-\s+)?(?P<name>[\w.-]*""" + _SECRET_NAME + r"""[\w.-]*)
    \s*(?:=|:\s)\s*(?P<value>[^\s"'#|&;$(){}\[\]]{4,})\s*$
    """
)


def _value_is_literal(value: str) -> bool:
    value = value.strip()
    if not value or _PLACEHOLDER.match(value):
        return False
    # "${...}" anywhere inside -> interpolated, not literal.
    if "${" in value or "{{" in value:
        return False
    # A bare number / boolean-ish value for "token_ttl = 3600"-style config.
    if re.fullmatch(r"[\d.]+[smhd]?", value):
        return False
    return True


_DEFAULT_CREDS = {
    "admin", "administrator", "password", "password1", "password123", "passw0rd", "p@ssw0rd", "changeme",
    "change_me", "changeit", "secret", "root", "toor", "default", "letmein", "welcome", "welcome1", "12345678",
    "123456", "qwerty", "postgres", "mysql", "oracle", "guest", "test123", "admin123", "pass", "master",
}


def _is_default_cred(m: re.Match) -> bool:
    return m.group("value").strip().lower() in _DEFAULT_CREDS


def _keep_default(m: re.Match) -> bool:
    return _keep_name(m) and _is_default_cred(m)


def _keep_name(m: re.Match) -> bool:
    name = m.group("name").lower()
    return not re.search(r"(?:_|-|\b)(?:ttl|length|len|min|max|policy|name|id|arn|path|file|type|prefix|"
                         r"version|header|param|field|rotation|expir\w*|count|enabled|required|regex)$", name)


_KNOWN_TOKEN = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}|glpat-|gh[pousr]_|xox[baprs]-")


def _keep_generic(m: re.Match) -> bool:
    if _is_default_cred(m):
        return False  # reported as SECRET-006 instead
    if _KNOWN_TOKEN.search(m.group("value")):
        return False  # reported as SECRET-001/003/004 with higher confidence
    # "token_ttl", "password_length", "secret_name" etc. describe a secret,
    # they don't hold one.
    return _keep_name(m) and _value_is_literal(m.group("value"))


def secret_rules(bare_assignments: bool = False) -> list[LineRule]:
    rules = [
        LineRule(
            "SECRET-001", "high", "Hardcoded AWS access key ID",
            r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b",
            "A long-lived AWS access key ID is committed to source. Treat the key pair as "
            "compromised: deactivate/rotate it in IAM, check CloudTrail for its use, and move "
            "to role-based credentials (instance profile, Lambda execution role, GitLab OIDC).",
            exclude=r"EXAMPLE",
        ),
        LineRule(
            "SECRET-002", "high", "Private key material committed to source",
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            "A PEM private key is embedded in the file. Rotate the key and load it at runtime "
            "from a secrets manager / KMS instead. If it is ENCRYPTED, confirm the passphrase "
            "is not committed alongside it.",
        ),
        LineRule(
            "SECRET-003", "high", "Hardcoded platform token (GitLab/GitHub/Slack)",
            r"\b(?:glpat-[0-9A-Za-z_-]{20,}|glrt-[0-9A-Za-z_-]{20,}|gldt-[0-9A-Za-z_-]{20,}|"
            r"gh[pousr]_[A-Za-z0-9]{36,}|xox[baprs]-[0-9A-Za-z-]{10,})",
            "A personal/deploy/runner token is committed. Revoke it and inject it as a masked, "
            "protected CI/CD variable (or use CI_JOB_TOKEN / OIDC where possible).",
        ),
        LineRule(
            "SECRET-004", "high", "Hardcoded AWS secret access key",
            r"(?i)aws_?secret_?access_?key\w*[\"']?\s*(?::=|=|:)\s*[\"']?[A-Za-z0-9/+]{40}\b",
            "An AWS secret access key is committed. Rotate it immediately and switch to "
            "role-based / short-lived credentials.",
        ),
        LineRule(
            "SECRET-005", "medium", "Hardcoded credential-looking value",
            _GENERIC_SECRET.pattern,
            "A secret-sounding name is assigned a literal value. Confirm whether it is a live "
            "credential; if so rotate it and load it from Secrets Manager / SSM / a masked CI "
            "variable at runtime.",
            confidence="REVIEW",
            keep=_keep_generic,
        ),
        LineRule(
            "SECRET-006", "high", "Default / well-known credential",
            _GENERIC_SECRET.pattern,
            "A credential is set to a vendor default or a top-of-wordlist password (admin, changeit, "
            "changeme, password...). These are the first values any attacker tries. Generate a "
            "random secret and store it in a secrets manager.",
            keep=_keep_default,
        ),
    ]
    if bare_assignments:
        rules.append(
            LineRule(
                "SECRET-006", "high", "Default / well-known credential",
                _GENERIC_SECRET_BARE.pattern,
                "A credential is set to a vendor default or a top-of-wordlist password. Generate a "
                "random secret and store it in a secrets manager.",
                keep=_keep_default,
            )
        )
        rules.append(
            LineRule(
                "SECRET-005", "medium", "Hardcoded credential-looking value",
                _GENERIC_SECRET_BARE.pattern,
                "A secret-sounding name is assigned a literal value. Confirm whether it is a "
                "live credential; if so rotate it and inject it at runtime instead.",
                confidence="REVIEW",
                keep=_keep_generic,
            )
        )
    return rules
