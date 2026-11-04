"""Sensitive files sitting in the scanned tree -- REPO-xxx.

Presence-based: a file on disk isn't necessarily committed. When the target
is a git checkout, `git ls-files` is used to say which ones are tracked
(those are the ones in every clone and in history); untracked ones are still
reported at lower severity since they tend to leak via CI artifacts/images.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from core.fsutil import _SKIP_DIRS, read_text_safe
from core.models import Finding
from core.rulescan import make_finding, rel

_KEY_EXTS = {".key", ".p12", ".pfx", ".jks", ".jceks", ".bcfks", ".keystore", ".p8", ".ppk"}
_KEY_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
_PLAN = re.compile(r"(?i)(?:\.tfplan|^tfplan(?:\.\w+)?|^plan\.(?:out|cache|bin))$")


def _tracked(root: Path) -> set[str] | None:
    if not (root / ".git").exists():
        return None
    try:
        out = subprocess.run(["git", "-C", str(root), "ls-files", "-z"], capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return {p for p in out.stdout.decode("utf-8", "ignore").split("\0") if p}


def scan_project(root: Path) -> list[Finding]:
    tracked = _tracked(root)
    findings: list[Finding] = []
    has_tf = False

    def sev(path: Path, high: str, low: str) -> tuple[str, str]:
        r = rel(path, root)
        if tracked is None:
            return high, "present in the scanned tree (not a git checkout -- confirm whether it's committed)"
        if r.replace("\\", "/") in tracked:
            return high, "tracked in git -- it's in every clone and stays in history after deletion"
        return low, "present on disk but not tracked by git -- check it doesn't ship in artifacts or images"

    for path in root.rglob("*"):
        parts = path.parts
        if any(p in _SKIP_DIRS for p in parts):
            continue
        if path.is_dir():
            continue
        if ".terraform" in parts:
            continue
        name = path.name
        if path.suffix == ".tf":
            has_tf = True
        if name.endswith((".tfstate", ".tfstate.backup")):
            s, where = sev(path, "high", "medium")
            findings.append(make_finding(
                "REPO-001", s, f"Terraform state file: {name}",
                f"State holds every resource attribute in plaintext, including passwords, keys and "
                f"tokens marked sensitive. File is {where}. Move state to an encrypted remote backend, "
                "rotate anything it contains, and purge it from history.", rel(path, root), 1))
        elif path.suffix.lower() in _KEY_EXTS or name in _KEY_NAMES or (
                path.suffix.lower() in (".pem", ".crt", ".cer") and "PRIVATE KEY" in read_text_safe(path)[:20000]):
            s, where = sev(path, "high", "medium")
            findings.append(make_finding(
                "REPO-002", s, f"Private key / keystore file: {name}",
                f"Key material is {where}. Rotate the key/certificate and load it at runtime from a "
                "secrets manager, KMS or HSM.", rel(path, root), 1, "REVIEW" if path.suffix.lower() in (".jks", ".p12", ".pfx", ".bcfks", ".keystore") else None))
        elif name == ".env" or (name.startswith(".env.") and not name.endswith((".example", ".sample", ".template", ".dist"))):
            s, where = sev(path, "medium", "low")
            findings.append(make_finding(
                "REPO-003", s, f"Environment file: {name}",
                f"dotenv files usually hold credentials; this one is {where}.", rel(path, root), 1, "REVIEW"))
        elif _PLAN.search(name) or name == "crash.log":
            s, where = sev(path, "high", "medium")
            findings.append(make_finding(
                "REPO-004", s, f"Terraform plan / crash file: {name}",
                f"Saved plans and crash logs contain variable and resource values in plaintext. File is {where}.",
                rel(path, root), 1))

    if has_tf:
        gi = root / ".gitignore"
        text = read_text_safe(gi) if gi.exists() else ""
        missing = [p for p, rx in (("*.tfstate", r"tfstate"), (".terraform/", r"\.terraform\b"), ("*.tfplan", r"tfplan|plan"))
                   if not re.search(rx, text)]
        if missing:
            findings.append(make_finding(
                "REPO-005", "low", f".gitignore doesn't exclude {', '.join(missing)}",
                "One `git add .` away from committing state/plans/provider caches. Add them to .gitignore "
                "(nested .gitignore files aren't checked -- verify by hand if the repo uses them).",
                ".gitignore" if gi.exists() else ".", 1, "REVIEW"))
    return findings
