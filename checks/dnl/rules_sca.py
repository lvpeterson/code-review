"""Offline software-composition rules for legacy .NET (DNL-SCA-001..005).

Reads `data/dnl_advisories.json` (next to this module, shipped as package data;
a small, hand-verified advisory set, see the README "Advisory data" section)
and matches it against:
  - NuGet packages: `packages.config` entries and `packages\\<Id>.<Version>\\`
    HintPaths in project files (SCA-001),
  - bundled JavaScript identified by banner comments (SCA-002),
  - the project target framework (SCA-003),
  - binary references with no package manager entry (SCA-004),
  - `nuget.config` package sources over http (SCA-005).
Nothing here needs the Roslyn IR, so it also runs in degraded mode. The
online, authoritative path stays `--sca` (osv-scanner, checks/sca.py).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.findings import dnl_finding
from checks.dnl.project import ProjectModel
from core.models import Finding

_DATA = Path(__file__).resolve().parent / "data" / "dnl_advisories.json"
_SEV_ORDER = {"low": 0, "medium": 1, "high": 2}

# -- version comparison (NuGet / SemVer 2) --------------------------------

_VER = re.compile(r"^v?(\d+(?:\.\d+){0,3})(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def _parse_version(text: str):
    """Sortable key, or None when the text is not a version. 1-4 numeric parts
    (zero padded, so 2.0.10 == 2.0.10.0), then the prerelease: a release sorts
    above any prerelease of the same core; prerelease identifiers compare
    numerically when numeric, else lexically (case-insensitive), and numeric < alphanumeric."""
    m = _VER.match(text.strip())
    if not m:
        return None
    core = [int(p) for p in m.group(1).split(".")]
    core += [0] * (4 - len(core))
    if m.group(2) is None:
        pre: tuple = (1,)
    else:
        ids = tuple((0, int(i), "") if i.isdigit() else (1, 0, i.lower()) for i in m.group(2).split("."))
        pre = (0,) + ids
    return (tuple(core), pre)


_CMP = re.compile(r"^(<=|>=|<|>|=)?\s*(\S+)$")


def _cmp_ok(op: str, a, b) -> bool:
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b, "=": a == b}[op]


def version_in(range_: str, version: str) -> bool:
    """True when version satisfies the range: space separated comparators
    (`<`, `<=`, `>`, `>=`, `=`) are ANDed, `||` separates alternatives.
    An unparsable version or range never matches (the caller cannot tell, and
    a made-up match would be a false finding)."""
    v = _parse_version(version)
    if v is None:
        return False
    for alt in range_.split("||"):
        ok = True
        tokens = alt.split()
        if not tokens:
            continue
        for tok in tokens:
            m = _CMP.match(tok)
            bound = _parse_version(m.group(2)) if m else None
            if bound is None:
                ok = False
                break
            if not _cmp_ok(m.group(1) or "=", v, bound):
                ok = False
                break
        if ok:
            return True
    return False


# -- advisory lookup ------------------------------------------------------

def _range_valid(range_: object) -> bool:
    """True when every alternative has at least one comparator and every
    comparator is an operator (optional) plus a valid version."""
    if not isinstance(range_, str):
        return False
    for alt in range_.split("||"):
        tokens = alt.split()
        if not tokens:
            return False
        for tok in tokens:
            m = _CMP.match(tok)
            if not m or _parse_version(m.group(2)) is None:
                return False
    return True


def _entry_valid(e: object, key: str) -> bool:
    """Value-level check of one advisory entry (string fields, known severity, parsable range)."""
    if not isinstance(e, dict):
        return False
    if not all(isinstance(e.get(k), str) and e[k].strip() for k in (key, "advisory", "url", "summary")):
        return False
    sev = e.get("severity")
    return isinstance(sev, str) and sev in _SEV_ORDER and _range_valid(e.get("affected"))


@lru_cache(maxsize=None)
def _load(path: Path) -> tuple[dict, str | None, int]:
    """(index, error, skipped). A missing, unreadable or malformed data file
    yields an empty index and the reason; individual invalid entries are
    skipped and counted. Nothing here raises, so bad data never aborts a scan."""
    index: dict[str, dict[str, list[dict]]] = {"nuget": {}, "js": {}}
    skipped = 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        for kind, key in (("nuget", "id"), ("js", "library")):
            for e in data.get(kind, []):
                if _entry_valid(e, key):
                    index[kind].setdefault(e[key].lower(), []).append(e)
                else:
                    skipped += 1
    except (OSError, ValueError, TypeError, AttributeError) as ex:
        return {"nuget": {}, "js": {}}, f"{ex.__class__.__name__}: {ex}", 0
    return index, None, skipped


def _advisories() -> dict:
    return _load(_DATA)[0]


def _match(entries: list[dict], version: str) -> list[dict]:
    return [e for e in entries if version_in(e["affected"], version)]


def _describe(subject: str, hits: list[dict]) -> tuple[str, str]:
    """(severity, description) for a package / library hit on one or more advisories."""
    sev = max((h["severity"] for h in hits), key=lambda s: _SEV_ORDER[s])
    parts = [f"{h['advisory']} ({h['url']}): {h['summary']}; affected {h['affected']}" for h in hits]
    return sev, (f"{subject} is inside a known-vulnerable range. " + " | ".join(parts)
                 + ". Offline advisory data: confirm with --sca (osv-scanner) and upgrade to a fixed release.")


# -- text helpers ---------------------------------------------------------

_COMMENT = re.compile(r"<!--.*?-->", re.S)


def _blank_comments(text: str) -> str:
    """Replace XML comments by spaces, keeping newlines so line numbers hold."""
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _safe_read(path: Path, notes: list[str]) -> str:
    try:
        return read_source(path)
    except OSError as ex:
        notes.append(f"{path.name}: unreadable ({ex.__class__.__name__}); SCA skipped for it")
        return ""


# -- packages.config / HintPath -------------------------------------------

_PACKAGE_EL = re.compile(r"<package\b([^>]*?)/?>", re.S | re.I)
_ATTR = re.compile(r"([\w:.-]+)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')")
_MACRO = re.compile(r"\$\([^)]*\)")
# `$(NuGetPackageRoot)` is the packages root. `$(Pkg<Id>)` (GeneratePathProperty) is ONE package folder and
# any other `$(Pkg...)` is user defined: neither yields an id/version, so they are unmanaged references.
_PKG_ROOT_MACRO = re.compile(r"\$\(NuGetPackageRoot\)", re.I)
_PKG_DIR_MACRO = re.compile(r"\$\(Pkg[^)]*\)", re.I)
_HINTPATH = re.compile(r"<HintPath>\s*([^<]*?)\s*</HintPath>", re.I)
# NuGet restore folder `<Id>.<Version>`: the id is the longest prefix whose remainder is a version.
_PKG_DIR = re.compile(r"^(.+?)\.(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.\-]+)?)$")
_LIB_DIRS = {"lib", "libs", "library", "libraries", "thirdparty", "third_party", "third-party",
             "external", "vendor", "dependencies", "references"}


def _packages_config(text: str) -> list[tuple[str, str | None, int]]:
    """(id, version or None, line) for every <package> element."""
    text = _blank_comments(text)
    out = []
    for m in _PACKAGE_EL.finditer(text):
        attrs = {k.lower(): (a or b) for k, a, b in _ATTR.findall(m.group(1))}
        if attrs.get("id"):
            out.append((attrs["id"], attrs.get("version"), _line_of(text, m.start())))
    return out


def _package_findings(rel: str, pkg_id: str, version: str, line: int) -> Finding | None:
    hits = _match(_advisories()["nuget"].get(pkg_id.lower(), []), version)
    if not hits:
        return None
    sev, desc = _describe(f"NuGet package {pkg_id} {version}", hits)
    return dnl_finding("DNL-SCA-001", sev, f"Vulnerable NuGet package {pkg_id} {version}", desc, rel, line)


def _check_packages(model: ProjectModel, notes: list[str]) -> tuple[list[Finding], dict[Path, set[str]]]:
    """SCA-001 over packages.config; also returns the package ids declared per directory."""
    findings: list[Finding] = []
    declared: dict[Path, set[str]] = {}
    for path in iter_dnl_files(model.root, (".config",)):
        if path.name.lower() != "packages.config":
            continue
        text = _safe_read(path, notes)
        entries = _packages_config(text)
        declared[path.parent.resolve()] = {i.lower() for i, _v, _l in entries}
        for pkg_id, version, line in entries:
            if version:
                f = _package_findings(model.rel(path), pkg_id, version, line)
                if f:
                    findings.append(f)
    return findings, declared


def _check_projects(model: ProjectModel, declared: dict[Path, set[str]], notes: list[str]) -> list[Finding]:
    """SCA-001 for HintPath-only packages, SCA-003 target framework, SCA-004 unmanaged binaries."""
    findings: list[Finding] = []
    for p in model.projects:
        if p.path is None:
            continue
        rel = model.rel(p.path)
        text = _blank_comments(_safe_read(p.path, notes))
        ids = declared.get(p.dir.resolve(), set())
        seen: set[tuple[str, str]] = set()
        for m in _HINTPATH.finditer(text):
            hint = m.group(1)
            line = _line_of(text, m.start())
            # MSBuild macros ($(SolutionDir), $(MSBuildThisFileDirectory)) prefix a segment: drop them.
            segs = [_MACRO.sub("", s) for s in hint.replace("\\", "/").split("/")]
            # `$(NuGetPackageRoot)` / `$(Pkg...)` expand to the packages folder itself.
            anchored = bool(_PKG_ROOT_MACRO.match(hint.lstrip()))
            pkg_dir_macro = bool(_PKG_DIR_MACRO.match(hint.lstrip()))
            segs = [s for s in segs if s not in ("", ".", "..")]
            if anchored or pkg_dir_macro:
                segs.insert(0, "packages")
            stem = re.sub(r"\.(dll|exe)$", "", segs[-1], flags=re.I) if segs else ""
            low = [s.lower() for s in segs[:-1]]
            pkg: tuple[str, str] | None = None
            if "packages" in low and not pkg_dir_macro:
                nxt = segs[low.index("packages") + 1] if low.index("packages") + 1 < len(segs) - 1 else ""
                m_dir = _PKG_DIR.match(nxt)
                if m_dir:
                    pkg = (m_dir.group(1), m_dir.group(2))
                elif anchored and len(segs) > 3 and segs[2][:1].isdigit() and _parse_version(segs[2]):
                    # Global packages folder layout: <id>/<version>/...
                    pkg = (nxt, segs[2])
            if pkg:
                pkg_id, version = pkg
                # packages.config is authoritative for the project: only HintPath-only packages are new.
                if pkg_id.lower() in ids or (pkg_id.lower(), version) in seen:
                    continue
                seen.add((pkg_id.lower(), version))
                f = _package_findings(rel, pkg_id, version, line)
                if f:
                    findings.append(f)
            elif ("packages" in low or any(s in _LIB_DIRS for s in low)) and segs \
                    and segs[-1].lower().endswith((".dll", ".exe")) and stem.lower() not in ids:
                findings.append(dnl_finding(
                    "DNL-SCA-004", "low", f"Unmanaged binary dependency {segs[-1]}",
                    f"{hint} is referenced from a packages or library folder but has no packages.config entry "
                    "and no version in its path, so it cannot be matched against advisories. Confirm the "
                    "origin and version of the binary, or restore it as a NuGet package.",
                    rel, line, confidence="REVIEW"))
        # SCA-003: .NET Framework 4.6.1 and older are out of support (4.6.2 is the floor).
        if p.is_legacy and p.target_framework:
            tfv = _parse_version(p.target_framework)
            if tfv is not None and tfv[0] < (4, 6, 2, 0):
                m = re.search(r"<TargetFrameworkVersion>", text, re.I)
                findings.append(dnl_finding(
                    "DNL-SCA-003", "medium", f"Target framework {p.target_framework} is past end of support",
                    f"{p.name} targets .NET Framework {p.target_framework}. Versions before 4.6.2 no longer "
                    "receive security updates; retarget to 4.6.2 or later (4.8 recommended).",
                    rel, _line_of(text, m.start()) if m else 1))
    return findings


# -- nuget.config ---------------------------------------------------------

_SOURCES = re.compile(r"<packageSources\b.*?</packageSources\s*>", re.S | re.I)
_ADD = re.compile(r"<add\b[^>]*?\bvalue\s*=\s*(?:\"([^\"]*)\"|'([^']*)')[^>]*>", re.S | re.I)
_LOOPBACK = re.compile(r"^http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", re.I)


def _check_nuget_config(model: ProjectModel, notes: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_dnl_files(model.root, (".config",)):
        if path.name.lower() != "nuget.config":
            continue
        text = _blank_comments(_safe_read(path, notes))
        for sec in _SOURCES.finditer(text):
            for m in _ADD.finditer(text, sec.start(), sec.end()):
                url = (m.group(1) or m.group(2) or "").strip()
                if url.lower().startswith("http://") and not _LOOPBACK.match(url):
                    findings.append(dnl_finding(
                        "DNL-SCA-005", "medium", "NuGet package source over http",
                        f"nuget.config lists the package source {url}. Packages fetched over plain http can be "
                        "swapped in transit; use an https feed.", model.rel(path), _line_of(text, m.start())))
    return findings


# -- bundled JavaScript ---------------------------------------------------

_BUNDLE_DIRS = {"scripts", "content", "lib", "libs"}
_HEAD = 4096
_NUM = r"(\d+(?:\.\d+){1,3}(?:-[0-9A-Za-z.]+)?)"
# library -> banner pattern; each captures the version. All case-insensitive.
_BANNERS = {
    "jquery-ui": re.compile(r"^jQuery UI(?: - |\s+)v?" + _NUM, re.I | re.M),
    "jquery-validation": re.compile(r"^jQuery Validation Plugin(?: - |\s+)v?" + _NUM, re.I | re.M),
    "jquery": re.compile(r"^jQuery(?: JavaScript Library)? v" + _NUM, re.I | re.M),
    "bootstrap": re.compile(r"^Bootstrap v" + _NUM, re.I | re.M),
    "moment": re.compile(r"^moment\.js[ \t]*\n[ \t]*version[ \t]*:[ \t]*" + _NUM, re.I | re.M),
    "knockout": re.compile(r"^Knockout JavaScript library v" + _NUM, re.I | re.M),
    "angularjs": re.compile(r"^AngularJS v" + _NUM, re.I | re.M),
    "handlebars": re.compile(r"^handlebars(?:\.js)? v" + _NUM, re.I | re.M),
    "lodash": re.compile(r"^lodash(?:\.js)?\s+v?" + _NUM, re.I | re.M),
}
# When the file name names the library, the version may sit anywhere in a comment block.
# A library-named file also accepts a comment line led by the library name (`jQuery custom build, v1.12.4`)
# or a line that is just a version (`v1.12.4`); a mention such as `Tour for Bootstrap v3.3.7` never counts.
_LIBWORD = {"jquery-ui": r"jQuery UI", "jquery-validation": r"jQuery Validation",
            "jquery": r"jQuery(?!\s+(?:UI|Validation))", "bootstrap": r"Bootstrap", "moment": r"moment(?:\.js)?",
            "knockout": r"Knockout", "angularjs": r"Angular(?:JS)?", "handlebars": r"handlebars(?:\.js)?",
            "lodash": r"lodash(?:\.js)?"}
_LOOSE = {lib: (re.compile(r"^" + w + r"\b[^\n]*?\bv?" + _NUM, re.I | re.M),
                re.compile(r"^v?" + _NUM + r"[ \t]*$", re.I | re.M)) for lib, w in _LIBWORD.items()}
_FNAME = {
    "jquery-ui": re.compile(r"jquery[-.]ui", re.I), "jquery-validation": re.compile(r"jquery[-.]valid", re.I),
    "jquery": re.compile(r"jquery[-.]\d", re.I), "bootstrap": re.compile(r"bootstrap", re.I),
    "moment": re.compile(r"moment", re.I), "knockout": re.compile(r"knockout", re.I),
    "angularjs": re.compile(r"angular", re.I), "handlebars": re.compile(r"handlebars", re.I),
    "lodash": re.compile(r"lodash", re.I),
}
# Exact versioned file names (`jquery-1.12.4.min.js`, `bootstrap.3.3.7.js`); the last-resort version source.
_FNAME_STEM = {"jquery-ui": r"jquery[-.]ui", "jquery-validation": r"jquery[-.]validat(?:e|ion)", "jquery": r"jquery",
               "bootstrap": r"bootstrap", "moment": r"moment", "knockout": r"knockout",
               "angularjs": r"angular(?:js)?", "handlebars": r"handlebars", "lodash": r"lodash"}
_FNAME_VER = {lib: re.compile(r"^" + s + r"[-.]v?" + _NUM + r"(?:\.slim)?(?:\.min)?\.js$", re.I)
              for lib, s in _FNAME_STEM.items()}
# Comment decoration at the start of a banner line: `/*!`, `/**`, `*`, `//`, `//!`, then an optional `@license`.
_DECOR = re.compile(r"^[ \t]*(?:/\*+!?|\*+(?!/)|//!?)?[ \t]*(?:@license\b)?[ \t]*", re.M)


# Lines that name a dependency or a tested-against version are never a banner.
_NOT_BANNER = re.compile(r"requires|depends on|compatible with|tested with", re.I)
_BLOCK_COMMENT = re.compile(r"/\*.*?(?:\*/|\Z)", re.S)
_LINE_COMMENTS = re.compile(r"(?:^[ \t]*//[^\n]*(?:\n|\Z))+", re.M)


def _comment_blocks(head: str) -> list[str]:
    """Every comment block in the head (`/* */` and runs of `//` lines), with the
    decoration stripped and the lines that mention a dependency removed."""
    spans = [m.span() for m in _BLOCK_COMMENT.finditer(head)] + [m.span() for m in _LINE_COMMENTS.finditer(head)]
    out = []
    for a, b in sorted(spans):
        text = _DECOR.sub("", head[a:b].replace("\r\n", "\n"))
        out.append("\n".join(ln for ln in text.split("\n") if not _NOT_BANNER.search(ln)))
    return out


_DISPLAY = {"jquery-ui": "jQuery UI", "jquery-validation": "jQuery Validation", "jquery": "jQuery",
            "bootstrap": "Bootstrap", "moment": "Moment.js", "knockout": "Knockout", "angularjs": "AngularJS",
            "handlebars": "Handlebars", "lodash": "Lodash"}


def _check_js(model: ProjectModel, notes: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_dnl_files(model.root, (".js",)):
        try:
            parts = path.resolve().relative_to(model.root).parts[:-1]
        except ValueError:
            parts = ()
        if not any(p.lower() in _BUNDLE_DIRS for p in parts):
            continue
        try:
            with path.open("rb") as fh:
                head = fh.read(_HEAD).decode("utf-8", "replace")
        except OSError as ex:
            notes.append(f"{path.name}: unreadable ({ex.__class__.__name__}); SCA skipped for it")
            continue
        blocks = _comment_blocks(head)
        found = {}
        # Tier 1: strict banners, across every block, for every library.
        for lib, rx in _BANNERS.items():
            m = next((m for b in blocks for m in [rx.search(b)] if m), None)
            if m:
                found[lib] = m.group(1)
        strict_any = bool(found)
        # Tiers 2-4, only for a library-named file without a strict banner: a library-led
        # line in any block, then a bare version line in any block, then the version in an
        # exact `lib-X.Y.Z(.min).js` file name (only when no library's strict banner is present).
        for lib in _BANNERS:
            if lib in found or not _FNAME[lib].search(path.name):
                continue
            ver = None
            for pat in _LOOSE[lib]:
                m = next((m for b in blocks for m in [pat.search(b)] if m), None)
                if m:
                    ver = m.group(1)
                    break
            if ver is None and not strict_any:
                fm = _FNAME_VER[lib].match(path.name)
                ver = fm.group(1) if fm else None
            if ver:
                found[lib] = ver
        for lib, ver in found.items():
            hits = _match(_advisories()["js"].get(lib, []), ver)
            if hits:
                name = _DISPLAY[lib]
                sev, desc = _describe(f"Bundled {name} {ver}", hits)
                findings.append(dnl_finding(
                    "DNL-SCA-002", sev, f"Bundled {name} {ver} has known vulnerabilities",
                    desc, model.rel(path), 1))
    return findings


def check(model: ProjectModel) -> tuple[list[Finding], list[str]]:
    """All SCA findings for the model's root, plus notes (unreadable files)."""
    notes: list[str] = []
    _index, err, skipped = _load(_DATA)
    if err:
        notes.append(f"advisory data unavailable ({err}); DNL-SCA-001/002 skipped")
    elif skipped:
        notes.append(f"{skipped} advisory entries skipped: invalid fields")
    findings, declared = _check_packages(model, notes)
    findings += _check_projects(model, declared, notes)
    findings += _check_nuget_config(model, notes)
    findings += _check_js(model, notes)
    return findings, notes
