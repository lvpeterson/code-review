"""Shell script checks (SH-xxx), aimed at the usual IaC wrapper scripts
(terraform plan/validate/apply wrappers, key-generation helpers, bootstrap
scripts).

SCRIPT_RULES are line rules that make sense anywhere shell runs, so they're
also applied to GitLab CI `script:` lines by checks/gitlab_ci.py. The
file-level checks (missing `set -e`, pipes without pipefail) only make sense
for a standalone script and live in scan_script().
"""
from __future__ import annotations

import re
from pathlib import Path

from checks import secrets
from core.fsutil import _SKIP_DIRS, read_text_safe
from core.models import Finding
from core.rulescan import LineRule, make_finding, mask_comments, rel, scan_text

SHELL_EXTENSIONS = (".sh", ".bash", ".ksh", ".zsh")
_SHEBANG = re.compile(r"^#!\s*(?:/usr)?/bin/(?:env\s+)?(?:ba|k|z|da)?sh\b")
_TF = r"(?:terraform|tofu|terragrunt|gitlab-terraform)"

SCRIPT_RULES: list[LineRule] = [
    LineRule("SH-001", "medium", "Remote script piped straight into a shell",
             r"\b(?:curl|wget)\b[^|#\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b|"
             r"\b(?:ba)?sh\s+(?:-c\s+)?[\"']?\$\((?:curl|wget)\b|\bsource\s+<\((?:curl|wget)",
             "Whatever the remote server (or anyone who can MITM/compromise it) returns runs with "
             "this job's credentials. Download to a file, verify a pinned checksum/signature, then run it."),
    LineRule("SH-002", "medium", "TLS certificate verification disabled",
             r"\bcurl\b[^\n]*\s(?:-k|--insecure)\b|\bwget\b[^\n]*--no-check-certificate|"
             r"\bGIT_SSL_NO_VERIFY\s*[=:]\s*[\"']?(?:1|true)|\bhttp\.sslVerify\s*(?:=\s*)?false|"
             r"PYTHONHTTPSVERIFY\s*=\s*[\"']?0|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0|"
             r"--insecure-skip-tls-verify|--tls-verify=false|\bsslverify\s*=\s*(?:0|false)",
             "A man-in-the-middle can read credentials sent over this connection and tamper with "
             "anything downloaded. Fix the trust store (e.g. add the internal CA) instead."),
    LineRule("SH-003", "high", "eval of a variable",
             r"\beval\s+[\"']?[^\n]*\$",
             "eval re-parses its argument as shell code -- any variable content containing ;, $(), "
             "or backticks runs as a command. Use arrays (\"${args[@]}\") instead of eval.",
             confidence="REVIEW"),
    LineRule("SH-004", "medium", "World-writable permissions",
             r"\bchmod\s+(?:-R\s+)?(?:0?[0-7]?7[0-7]?7|a\+w|o\+w|ugo\+w)\b",
             "Any local user/process can modify these files (and, for scripts or binaries, run code "
             "as whoever executes them next)."),
    LineRule("SH-005", "medium", "Terraform debug logging enabled",
             r"\bTF_LOG\s*[=:]\s*[\"']?(?:TRACE|DEBUG|JSON)\b",
             "TF_LOG=TRACE/DEBUG writes provider requests -- including credentials, tokens and "
             "secret values -- to the job log. Remove it, or route it to TF_LOG_PATH outside artifacts."),
    LineRule("SH-006", "medium", "Terraform exit status swallowed by `|| true`",
             _TF + r"\s+(?:validate|plan|fmt|apply|init)\b[^\n]*\|\|\s*(?:true|:|exit\s+0)\b",
             "A failed validate/plan is reported as success, so the gate this wrapper exists to "
             "enforce silently passes. Let the non-zero exit status propagate (or handle "
             "-detailed-exitcode 2 explicitly)."),
    LineRule("SH-007", "low", "Terraform apply with -auto-approve",
             _TF + r"\s+(?:apply|destroy)\b[^\n]*-auto-approve",
             "Changes are applied without a human looking at the plan. Apply a reviewed saved plan "
             "file (terraform apply plan.tfplan) from a manual/protected job instead.",
             confidence="REVIEW"),
    LineRule("SH-008", "low", "Terraform state locking disabled",
             _TF + r"\s+\w+[^\n]*-lock=false",
             "Concurrent runs can corrupt state."),
    LineRule("SH-009", "medium", "Secret passed on the terraform command line",
             _TF + r"\s+\w+[^\n]*-var[= ]\s*[\"']?[\w-]*(?:password|secret|token|key)[\w-]*=",
             "Command-line arguments are visible to every process on the host (ps, /proc) and are "
             "often echoed in CI logs. Pass secrets as TF_VAR_* environment variables from a masked "
             "CI variable instead."),
    LineRule("SH-010", "low", "State or plan contents printed / exported",
             _TF + r"\s+(?:state\s+pull|show(?:\s+-json)?|output\s+-(?:json|raw))\b",
             "State/plan JSON contains every sensitive value in plaintext (sensitive = true only "
             "hides it from the human-readable plan). Make sure this output isn't logged or saved "
             "as an artifact.", confidence="REVIEW"),
    LineRule("SH-011", "medium", "Secret passed on a command line",
             r"(?:--password[= ]|\s-p[\"']?\$|-passout\s+pass:|-passin\s+pass:|-pass\s+pass:|"
             r"-storepass\s+|-keypass\s+|--token[= ]|--secret[= ])",
             "Arguments are readable by any local user via ps/proc and frequently end up in shell "
             "history or CI logs. Use env:/file: forms (openssl -passout env:VAR / file:path, "
             "keytool -storepass:env) or stdin.", confidence="REVIEW"),
    LineRule("SH-012", "high", "Weak openssl key / cipher parameters",
             r"\bopenssl\s+(?:genrsa|genpkey|req)\b[^\n]*(?:\b(?:512|768|1024)\b|rsa_keygen_bits:(?:512|768|1024))|"
             r"\bopenssl\s+\w+[^\n]*\s-(?:des|des3|rc4|rc2|bf|md5|idea)\b|\bopenssl\s+enc\b[^\n]*-(?:aes-\d+-ecb|nosalt)\b",
             "RSA < 2048 bits, DES/3DES/RC4/MD5 and ECB/no-salt encryption are broken or not "
             "FIPS-approved. Use RSA >= 3072 / EC P-256+, AES-256-GCM, and -pbkdf2 -iter for enc."),
    LineRule("SH-013", "medium", "openssl enc without PBKDF2",
             r"\bopenssl\s+enc\b(?![^\n]*-pbkdf2)(?![^\n]*\s-d\b)[^\n]*-(?:pass|k)\b",
             "Without -pbkdf2 openssl derives the key with a single MD5/SHA-256 round (EVP_BytesToKey), "
             "making the passphrase cheap to brute-force. Add -pbkdf2 -iter 600000 (or use age/gpg/KMS)."),
    LineRule("SH-014", "low", "Private key generated without a passphrase",
             r"\bopenssl\s+req\b[^\n]*-(?:nodes|noenc)\b|\bssh-keygen\b[^\n]*-N\s*[\"']{2}",
             "The private key is written unencrypted. Make sure it is created with restrictive "
             "permissions (umask 077) and never lands in an artifact or the repo.", confidence="REVIEW"),
    LineRule("SH-015", "medium", "Secret echoed to output",
             r"\b(?:echo|printf|cat\s+<<)[^\n|>]*\$\{?[A-Za-z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|ACCESS_KEY)",
             "The value is written to stdout (and therefore the CI job log). Masked CI variables are "
             "only masked when printed verbatim -- base64/JSON/partial forms leak.",
             exclude=r">\s*[\"']?[/$\w.~-]+\s*$|\|\s*(?:docker|helm|kubectl|aws|gcloud|vault|gh|glab)\b[^\n]*(?:login|--password-stdin|-)"),
    LineRule("SH-016", "medium", "Environment dumped to output",
             r"(?:^|[;&|]\s*|\s)(?:printenv|env|export\s+-p|set)\s*(?:[;&|]|$)",
             "Prints every environment variable -- in CI that includes every non-masked secret and "
             "file-type variable paths.", exclude=r"\benv\s+\w+=|\bset\s+-"),
    LineRule("SH-017", "medium", "xtrace (set -x) enabled",
             r"\bset\s+-[a-wyz]*x|\bbash\s+-x\b|\bset\s+-o\s+xtrace",
             "set -x prints every command after expansion -- secrets in variables appear in the log "
             "in clear text (masking does not apply to all expanded forms).",
             file_require=r"(?i)(?:password|secret|token|key|terraform|aws|vault)"),
]

_SECRET_RULES = secrets.secret_rules(bare_assignments=True)


def iter_shell_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
            continue
        if path.suffix in SHELL_EXTENSIONS:
            yield path
        elif path.suffix == "" and path.stat().st_size < 512_000:
            try:
                with path.open("rb") as fh:
                    head = fh.read(64).decode("utf-8", "ignore")
            except OSError:
                continue
            if _SHEBANG.match(head):
                yield path


def scan_script(path: Path, root: Path) -> list[Finding]:
    text = read_text_safe(path)
    relative = rel(path, root)
    findings = scan_text(text, SCRIPT_RULES + _SECRET_RULES + _SCRIPT_ONLY_RULES, relative, "hash")
    masked = mask_comments(text, "hash")
    first = text.split("\n", 1)[0]
    has_errexit = re.search(r"\bset\s+-[a-z]*e|\bset\s+-o\s+errexit|\bset\s+-euo\b", masked) or re.search(r"\s-[a-z]*e\b", first)
    runs_tf = re.search(_TF + r"\s+(?:validate|plan|apply|init|fmt)\b", masked)
    if not has_errexit:
        findings.append(make_finding(
            "SH-020", "medium" if runs_tf else "low", "Script does not exit on error (no set -e)",
            "Without set -euo pipefail a failing command (including terraform validate/plan, or a "
            "failed `cd`) doesn't stop the script, and its exit status is that of the *last* command "
            "-- a wrapper can report success after the step it wraps failed."
            if runs_tf else
            "Without set -euo pipefail a failing command (or a failed `cd` before an `rm`) doesn't "
            "stop the script.",
            relative, 1,
        ))
    if not re.search(r"pipefail", masked):
        for m in re.finditer(_TF + r"\s+(?:validate|plan|apply|fmt)\b[^\n|]*\|(?!\|)", masked):
            findings.append(make_finding(
                "SH-021", "medium", "Terraform output piped without pipefail",
                "In `terraform plan | tee plan.log` the pipeline's exit status is tee's (0), so a "
                "failed plan/validate looks successful. Add `set -o pipefail`.",
                relative, masked.count("\n", 0, m.start()) + 1,
            ))
    return findings


_SCRIPT_ONLY_RULES: list[LineRule] = [
    LineRule("SH-022", "medium", "rm -rf on an unguarded variable",
             r"\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+(?:-[a-zA-Z]+\s+)*[\"']?\$\{?(?![^}\s\"']*:\?)[A-Za-z_]\w*\}?[\"']?/",
             "If the variable is empty or unset this expands to `rm -rf /...`. Use \"${VAR:?}\" "
             "(aborts when unset) and set -u."),
    LineRule("SH-023", "low", "Predictable temp file path",
             r"(?:>|\btee\s+|\bcp\s+\S+\s+|\bmv\s+\S+\s+)[\"']?/tmp/[\w.-]+",
             "A fixed /tmp path can be pre-created or symlinked by another local user (symlink "
             "attack / data leak). Use mktemp / mktemp -d with a trap to clean up.",
             exclude=r"mktemp"),
    LineRule("SH-024", "low", "Password read without -s",
             r"\bread\s+(?!-[a-zA-Z]*s)(?:-[a-zA-Z]+\s+)*(?:-p\s+[\"'][^\"']*(?:pass|secret|token)[^\"']*[\"']\s+)?\w*(?:pass|secret|token)\w*\b",
             "The typed secret is echoed to the terminal (and screen recordings/scrollback). Use read -rs."),
    LineRule("SH-025", "medium", "Private key / secret written without restricting permissions",
             r"(?:>\s*[\"']?[^\s\"']*\.(?:pem|key|p12|pfx|jks|bcfks)\b|\bopenssl\s+(?:genrsa|genpkey|req)\b[^\n]*-(?:out|keyout)\s)",
             "The key file is created with the default umask (often world-readable 0644). Set "
             "`umask 077` before creating it or chmod 600 immediately after.",
             file_suppress=r"\bumask\s+0?077\b|\bchmod\s+(?:0?[46]00|go-rwx|u=rw,go=)\b",
             confidence="REVIEW"),
]


def scan_project(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_shell_files(root):
        findings.extend(scan_script(path, root))
    return findings
