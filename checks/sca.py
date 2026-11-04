"""Optional dependency vulnerability scan (SCA-001) via osv-scanner.

Opt-in with `main.py <target> --sca`. Runs the external `osv-scanner`
binary (https://google.github.io/osv-scanner/) over every lockfile /
manifest it recognises (requirements.txt, poetry.lock, pom.xml,
build.gradle lockfiles, package-lock.json, go.sum, composer.lock...) and
turns each vulnerable package into one finding in the Infrastructure tab
(ISR01 Outdated Software).

Confidentiality: by default osv-scanner sends package names + versions to
api.osv.dev. Use `--sca-offline` to download the OSV databases once and
match locally instead (osv-scanner v2 flags --offline-vulnerabilities
--download-offline-databases).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from core.models import Finding, ScanResult
from core.rulescan import make_finding, rel


def _severity(group_max: Optional[str], db_sev: list[str]) -> str:
    try:
        score = float(group_max) if group_max else None
    except ValueError:
        score = None
    if score is not None:
        return "high" if score >= 7 else "medium" if score >= 4 else "low"
    s = {x.upper() for x in db_sev}
    if s & {"CRITICAL", "HIGH"}:
        return "high"
    if "MODERATE" in s or "MEDIUM" in s:
        return "medium"
    return "low"


def _run(binary: str, root: Path, offline: bool) -> Optional[dict]:
    attempts = [[binary, "scan", "source", "-r", "--format", "json"], [binary, "--format", "json", "-r"]]
    if offline:
        attempts[0] += ["--offline-vulnerabilities", "--download-offline-databases"]
        attempts[1] += ["--experimental-offline", "--experimental-download-offline-databases"]
    for cmd in attempts:
        try:
            proc = subprocess.run(cmd + [str(root)], capture_output=True, text=True, timeout=900)
        except (OSError, subprocess.TimeoutExpired):
            continue
        out = proc.stdout.strip()
        if out.startswith("{"):
            try:
                return json.loads(out)
            except ValueError:
                continue
    return None


def _line_of(path: Path, name: str) -> int:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    m = re.search(re.escape(name), text, re.I)
    return text.count("\n", 0, m.start()) + 1 if m else 1


def parse(data: dict, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for res in data.get("results", []) or []:
        src = Path((res.get("source") or {}).get("path", ""))
        for pkg in res.get("packages", []) or []:
            p = pkg.get("package", {}) or {}
            vulns = pkg.get("vulnerabilities", []) or []
            if not vulns:
                continue
            groups = pkg.get("groups", []) or []
            max_sev = max((g.get("max_severity") or "" for g in groups), default="", key=lambda x: float(x) if x else -1)
            sev = _severity(max_sev, [str((v.get("database_specific") or {}).get("severity", "")) for v in vulns])
            ids = []
            for v in vulns:
                cve = next((a for a in v.get("aliases", []) or [] if a.startswith("CVE-")), None)
                ids.append(cve or v.get("id", "?"))
            ids = list(dict.fromkeys(ids))
            summaries = "; ".join(f"{v.get('id')}: {v.get('summary', '')}".strip() for v in vulns[:3])
            name, version = p.get("name", "?"), p.get("version", "?")
            findings.append(make_finding(
                "SCA-001", sev, f"{name} {version} ({p.get('ecosystem', '')}) has {len(ids)} known "
                f"vulnerabilit{'y' if len(ids) == 1 else 'ies'}: {', '.join(ids[:4])}",
                f"{summaries}. Upgrade to a fixed version (see https://osv.dev/list?q={name}), or confirm the "
                "vulnerable code path isn't reachable and record the exception.",
                rel(src, root) if src.is_absolute() else str(src), _line_of(src, name) if src.is_file() else 1))
    return findings


def run(root: Path, offline: bool = False) -> ScanResult:
    result = ScanResult(language="infra", framework="dependencies")
    binary = shutil.which("osv-scanner")
    if not binary:
        result.notes.append("--sca requested but osv-scanner isn't on PATH. Install it "
                            "(https://google.github.io/osv-scanner/installation/) and re-run; no dependency "
                            "vulnerabilities were checked.")
        return result
    data = _run(binary, root, offline)
    if data is None:
        result.notes.append("osv-scanner ran but produced no JSON output (no supported lockfiles found, or the "
                            "scan failed). Run it by hand to see why.")
        return result
    result.findings = parse(data, root)
    result.notes.append(f"osv-scanner{' (offline databases)' if offline else ' (queries api.osv.dev)'}: "
                        f"{len(result.findings)} vulnerable package(s).")
    return result
