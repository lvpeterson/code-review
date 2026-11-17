"""Offline software-composition rules for SDK-style (ASP.NET Core) projects.

Reuses the helpers of `rules_sca` (version compare, advisory match, JS banner scan)
and adds what SDK projects have and `packages.config` projects do not:
  - `PackageReference` versions as resolved by `project.py` (inline `Version`,
    central `Directory.Packages.props`, `VersionOverride`) matched against the
    offline advisories (DNL-SCA-001),
  - `packages.lock.json`: its `resolved` version beats the project file, and
    transitive-only entries are reported against the lock file (DNL-SCA-001),
  - target frameworks past Microsoft's end-of-support date, from the dated table in
    the advisory data file (DNL-SCA-003),
  - packages whose version cannot be resolved (floating, `$(Prop)`, missing central
    entry, unparsable range) are DNL-SCA-006 REVIEW, never reported as clean.
`wwwroot/lib` JS, packages.config, HintPath and nuget.config checks are the shared
`rules_sca` ones. The online, authoritative path stays `--sca` (osv-scanner).
"""
from __future__ import annotations

import datetime
import json
import re
from pathlib import Path

from checks.dnl import rules_sca as sca
from checks.dnl.findings import dnl_finding
from checks.dnl.project import Project, ProjectModel, _props_chain
from core.models import Finding

_LOCK_NAME = "packages.lock.json"
# `packages.lock.json` format versions this reader understands (2 adds CentralTransitive).
_LOCK_VERSIONS = (1, 2)
_LOCK_KINDS = {"direct", "transitive", "centraltransitive"}

_BRACKET = re.compile(r"^([\[(])\s*([^,\])]*?)\s*(?:(,)\s*([^\])]*?)\s*)?([\])])$")
_REFERENCE = re.compile(r"<PackageReference\b(?P<body>[^>]*?)(?:/>|>(?P<inner>.*?)</PackageReference\s*>)", re.S | re.I)
_INCLUDE = re.compile(r"\bInclude\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.I)
_HAS_VERSION = re.compile(r"\bVersion(?:Override)?\s*=|<Version(?:Override)?\b", re.I)
_TFM_LINE = re.compile(r"<TargetFrameworks?\b", re.I)


def resolved_version(spec: str) -> tuple[str | None, str]:
    """(version, how) for a `PackageReference` version spec. how is "exact" (`1.2.3`,
    `[1.2.3]`), "range-lower" (`[a,b)`, `[a,]`, `(a,b)`: NuGet restores the lowest
    applicable version, so the lower bound is what runs) or "unresolved" (floating `*`,
    `$(Prop)`, empty, no lower bound, unparsable): the caller reports those, it never skips them."""
    s = (spec or "").strip()
    if not s or "*" in s or "$(" in s:
        return None, "unresolved"
    if sca._parse_version(s) is not None:
        return s, "exact"
    m = _BRACKET.match(s)
    if not m:
        return None, "unresolved"
    lower, comma = m.group(2), m.group(3)
    if lower and sca._parse_version(lower) is not None and (comma or (m.group(1) == "[" and m.group(5) == "]")):
        return lower, "range-lower" if comma else "exact"
    return None, "unresolved"


# -- end of support ---------------------------------------------------------

def _norm_tfm(tfm: str) -> str:
    """`net6.0-windows` -> `net6.0` (platform suffixes do not change the support date)."""
    return tfm.strip().lower().split("-")[0]


def eol_tfms(today: datetime.date | None = None) -> set[str]:
    """Lower-cased target frameworks whose end-of-support date is on or before today."""
    today = today or datetime.date.today()
    return {r["tfm"] for r in sca.eol_table()[1] if datetime.date.fromisoformat(r["eol"]) <= today}


# -- packages.lock.json -----------------------------------------------------

def _read_locks(model: ProjectModel, projects: list[Project], notes: list[str]) -> dict[Path, dict]:
    """{project dir -> lock facts} for each packages.lock.json that sits in an SDK project's own
    directory (next to the csproj, where NuGet writes it). A lock file anywhere else (a sample or
    vendored tree below the project) is ignored, so it can never replace the real one; one that
    is malformed or of an unknown format version adds a note and is ignored."""
    dirs = {p.dir.resolve() for p in projects}
    out: dict[Path, dict] = {}
    for path in model.iter_files((".json",)):
        if path.name.lower() != _LOCK_NAME:
            continue
        here = path.parent.resolve()
        if here not in dirs:
            # A lock file below a project (a sample or vendored tree) is not NuGet's own: say so.
            if any(here.is_relative_to(d) for d in dirs):
                notes.append(f"{model.rel(path)}: packages.lock.json is not next to a project file; ignored")
            continue
        owner = here
        rel = model.rel(path)
        text = sca._safe_read(path, notes)
        try:
            data = json.loads(text)
            version = data.get("version")
            deps = data.get("dependencies")
            if version not in _LOCK_VERSIONS:
                notes.append(f"{rel}: unsupported packages.lock.json version {version!r}; lock file ignored")
                continue
            if not isinstance(deps, dict):
                raise ValueError("no dependencies object")
        except (ValueError, AttributeError) as ex:
            notes.append(f"{rel}: packages.lock.json is not readable ({ex.__class__.__name__}); lock file ignored")
            continue
        entries: dict[str, dict] = {}
        for section in deps.values():
            if not isinstance(section, dict):
                continue
            for pid, e in section.items():
                if not isinstance(e, dict) or not isinstance(e.get("resolved"), str):
                    continue
                kind = str(e.get("type", "")).lower()
                if kind not in _LOCK_KINDS:
                    continue            # `Project` entries are solution projects, not packages
                ent = entries.setdefault(pid.lower(), {"id": pid, "kind": kind, "versions": []})
                if e["resolved"] not in ent["versions"]:
                    ent["versions"].append(e["resolved"])
        out[owner] = {"path": path, "rel": rel, "text": text, "entries": entries}
    return out


# -- PackageReference / central versions ------------------------------------

def _references(text: str) -> dict[str, tuple[str, int, bool]]:
    """{lower id -> (id as written, line, version declared in the project file)} for every PackageReference."""
    out: dict[str, tuple[str, int, bool]] = {}
    for m in _REFERENCE.finditer(text):
        inc = _INCLUDE.search(m.group("body"))
        if not inc:
            continue
        pid = (inc.group(1) or inc.group(2)).strip()
        local = bool(_HAS_VERSION.search(m.group("body")) or _HAS_VERSION.search(m.group("inner") or ""))
        out.setdefault(pid.lower(), (pid, sca._line_of(text, m.start()), local))
    return out


def _central_line(model: ProjectModel, p: Project, pid: str) -> tuple[str, int] | None:
    """(relative path, line) of the PackageVersion that supplied pid's version, nearest file first."""
    rx = re.compile(r"<PackageVersion\b[^>]*\bInclude\s*=\s*[\"']" + re.escape(pid) + r"[\"']", re.I)
    for f in reversed(_props_chain(p.dir, model.root, "Directory.Packages.props")):
        try:
            text = sca._blank_comments(sca.read_source(f))
        except OSError:
            continue
        m = rx.search(text)
        if m:
            return model.rel(f), sca._line_of(text, m.start())
    return None


def _lock_line(text: str, pid: str) -> int:
    m = re.search(r"\"" + re.escape(pid) + r"\"\s*:", text, re.I)
    return sca._line_of(text, m.start()) if m else 1


def _vulnerable(subject_id: str, version: str, what: str, rel: str, line: int, extra: str = "") -> Finding | None:
    hits = sca._match(sca._advisories()["nuget"].get(subject_id.lower(), []), version)
    if not hits:
        return None
    sev, desc = sca._describe(f"NuGet package {subject_id} {version}", hits)
    return dnl_finding("DNL-SCA-001", sev, f"Vulnerable {what}NuGet package {subject_id} {version}",
                       desc + extra, rel, line)


def _check_references(model: ProjectModel, projects: list[Project], notes: list[str],
                      eol: dict[str, dict]) -> list[Finding]:
    """SCA-001 / SCA-006 per project (plus transitive lock entries) and SCA-003 per target framework."""
    findings: list[Finding] = []
    locks = _read_locks(model, projects, notes)
    seen_transitive: set[tuple[str, str, str]] = set()
    for p in projects:
        rel = model.rel(p.path)
        text = sca._blank_comments(sca._safe_read(p.path, notes))
        refs = _references(text)
        lock = locks.get(p.dir.resolve())
        for pkg, spec in p.packages.items():
            pid, line, local = refs.get(pkg, (pkg, 1, True))
            ent = lock["entries"].get(pkg) if lock else None
            origin = ""
            if ent:
                # The lock file is what restore actually resolved: it beats the project file.
                versions, how = ent["versions"], "lock"
                origin = f" Version resolved in {lock['rel']}."
            else:
                v, how = resolved_version(spec)
                versions = [v] if v else []
                if how == "range-lower":
                    origin = f" Version taken from the range lower bound of {spec.strip()} (restore picks the lowest applicable version)."
                elif how == "exact" and not local:
                    src = _central_line(model, p, pid)
                    origin = (f" Version comes from {src[0]} line {src[1]}." if src
                              else " Version comes from a props file.")
            if not versions:
                findings.append(dnl_finding(
                    "DNL-SCA-006", "low", f"NuGet package {pid} has no resolvable version",
                    f"{pid} is referenced with the version {spec.strip() or '(none)'!r}, which cannot be resolved "
                    "offline (floating `*`, an MSBuild property, no version and no central entry, or an "
                    "unparsable range), so it cannot be matched against advisories and is not known to be clean. "
                    "Pin an exact version, or commit packages.lock.json, and re-run (or confirm with --sca).",
                    rel, line, confidence="REVIEW"))
                continue
            for ver in versions:
                f = _vulnerable(pid, ver, "", rel, line, origin)
                if f:
                    findings.append(f)
        # Lock entries that no project file declares: transitive dependencies.
        if lock:
            for key, ent in lock["entries"].items():
                if key in p.packages:
                    continue
                for ver in ent["versions"]:
                    tag = (lock["rel"], key, ver)
                    if tag in seen_transitive:
                        continue
                    seen_transitive.add(tag)
                    f = _vulnerable(ent["id"], ver, "transitive ", lock["rel"], _lock_line(lock["text"], ent["id"]),
                                    " Pulled in transitively (not declared in the project file): upgrade the "
                                    "parent package or pin a fixed version directly.")
                    if f:
                        findings.append(f)
        m = _TFM_LINE.search(text)
        tfm_line = sca._line_of(text, m.start()) if m else 1
        done: set[str] = set()
        for raw in p.target_frameworks:
            tfm = _norm_tfm(raw)
            row = eol.get(tfm)
            if row is None or tfm in done:
                continue
            done.add(tfm)
            findings.append(dnl_finding(
                "DNL-SCA-003", "medium", f"Target framework {tfm} is past end of support",
                f"{p.name} targets {raw.strip()}. Microsoft ended support for {tfm} on {row['eol']} "
                f"({row['source']}), so it no longer receives security fixes; move to a supported release.",
                rel, tfm_line))
    return findings


def check(model: ProjectModel, today: datetime.date | None = None) -> tuple[list[Finding], list[str]]:
    """All SCA findings for the SDK projects of the model's root, plus notes (data problems,
    unreadable files, the date the end-of-support table was verified)."""
    today = today or datetime.date.today()
    notes: list[str] = []
    _index, err, skipped = sca._load(sca._DATA)
    if err:
        notes.append(f"advisory data unavailable ({err}); DNL-SCA-001/002 skipped")
    elif skipped:
        notes.append(f"{skipped} advisory entries skipped: invalid fields")
    as_of, rows = sca.eol_table()
    if as_of is None:
        notes.append("end-of-support table unavailable; DNL-SCA-003 skipped for ASP.NET Core projects")
    else:
        notes.append(f"end-of-support dates verified as of {as_of} (Microsoft .NET support policy)")
    eol = {r["tfm"]: r for r in rows if datetime.date.fromisoformat(r["eol"]) <= today}
    projects = [p for p in model.projects if p.path is not None and p.is_sdk]
    findings = _check_references(model, projects, notes, eol)
    declared_findings, declared = sca._check_packages(model, notes)
    findings += declared_findings
    findings += sca._check_projects(model, declared, notes)
    findings += sca._check_nuget_config(model, notes)
    findings += sca._check_js(model, notes)
    return findings, notes
