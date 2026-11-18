"""Solution model for the legacy .NET analyzer: projects from csproj/vbproj
plus the parsed IR of every source file, with cross-project type lookup.

The Roslyn helper compiles each project alone, so inheritance across files and
projects (HomeController : BaseController : Controller) is resolved here by
simple name over the IR.
"""
from __future__ import annotations

import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from checks.dnl import frontend_ts, helper
from checks.dnl.files import is_legacy_project, iter_dnl_files, read_source, resolve_ci
from checks.dnl.ir import FileIR, TypeIR, load_file_ir

LOOSE = "(loose)"
_LANG_EXT = {"cs": ".cs", "vb": ".vb"}
_PROJ_LANG = {".csproj": "cs", ".vbproj": "vb"}
# MSBuild item specs escape special characters as %XX (`@` -> %40, `;` -> %3B).
_MSBUILD_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


@dataclass
class Project:
    name: str
    path: Path | None
    language: str
    dir: Path
    target_framework: str | None = None
    # VB prepends it implicitly to every type name (see routes._page_type).
    root_namespace: str | None = None
    references: set[str] = field(default_factory=set)
    # VB project-level <Import> namespaces (implicit file imports).
    imports: list[str] = field(default_factory=list)
    project_refs: list[Path] = field(default_factory=list)
    compile_files: list[Path] = field(default_factory=list)
    content_files: list[Path] = field(default_factory=list)
    is_legacy: bool = False
    # SDK-style projects (Microsoft.NET.Sdk*): facts read from the project file,
    # Directory.Build.props and Directory.Packages.props.
    sdk: str | None = None
    target_frameworks: list[str] = field(default_factory=list)
    # Lower-cased package id -> version string ("" when no version could be resolved).
    packages: dict[str, str] = field(default_factory=dict)
    framework_refs: set[str] = field(default_factory=set)
    # Reference profile the helper compiles against ("net48" | "netcore").
    profile: str = "net48"
    # A multi-targeted SDK project (effective TargetFrameworks hold a net4x and a modern moniker):
    # `profile` / `owner` stay the primary (netcore) values, `profiles` / `owners` hold both.
    multi: bool = False
    global_usings: list[str] = field(default_factory=list)
    # SDK globbing inputs: `<Compile Remove>` patterns and EnableDefaultCompileItems.
    compile_remove: list[str] = field(default_factory=list)
    default_items: bool = True

    @property
    def owner(self) -> str:
        """The package that analyzes this project's code."""
        return "dotnet" if self.profile == "netcore" else "dotnet_legacy"

    @property
    def profiles(self) -> set[str]:
        """Every reference profile this project builds for."""
        return {"net48", "netcore"} if self.multi else {self.profile}

    @property
    def owners(self) -> set[str]:
        """Every package that analyzes this project's code (both for a multi-targeted project)."""
        return {"dotnet", "dotnet_legacy"} if self.multi else {self.owner}

    @property
    def is_sdk(self) -> bool:
        return self.path is not None and not self.is_legacy


# A test project's own name or folder: `Shop.Tests`, `shop-test`, `tests`, `MyUnitTests` (a capital T
# after another character; `Latest` is not one).
_TEST_NAME = re.compile(r"(?:^|[._-])(?i:tests?)$|[A-Za-z0-9]Tests?$")


@dataclass
class ProjectModel:
    root: Path
    projects: list[Project]
    files: dict[str, FileIR]
    degraded: str | None = None
    notes: list[str] = field(default_factory=list)
    # Per-model results shared by the analyzers (routes, filters, auth findings),
    # so mvc / webapi / webforms / config do the work once per scan.
    cache: dict = field(default_factory=dict)
    # Degraded mode only: VB sources (rel paths) for the vb_regex scan; the IR has none.
    vb_files: list[str] = field(default_factory=list)
    # Set on per-package views: the full model they were cut from.
    parent: ProjectModel | None = None
    owner: str | None = None
    # Multi-targeted projects only: rel path -> the FileIR parsed under the net48 profile (the legacy
    # view uses it; the Core view and `files` hold the netcore one).
    alt_files: dict[str, FileIR] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # Lazy indexes; built on first lookup.
        self._by_name: dict[str, list[TypeIR]] | None = None
        self._rel_proj: dict[str, Project] | None = None
        self._views: dict[str, ProjectModel] = {}
        self._real_dirs: list[tuple[Project, Path]] | None = None

    def view(self, owner: str) -> ProjectModel:
        """The projects (and their files) one package owns, as a model of its own.
        Shares root, degraded flag and the notes list; the cache is separate so each
        package's route and auth results are computed over its own code only."""
        cached = self._views.get(owner)
        if cached is not None:
            return cached

        def mine(rel: str) -> bool:
            proj = self.project_of(rel)
            # A file no project lists stays with the legacy package (the old behaviour).
            return owner in (proj.owners if proj is not None else {"dotnet_legacy"})

        def file_ir(rel: str, f: FileIR) -> FileIR:
            # The legacy view of a multi-targeted project reads the net48 build's IR.
            return self.alt_files.get(rel, f) if owner == "dotnet_legacy" else f

        v = ProjectModel(self.root, [p for p in self.projects if owner in p.owners],
                         {rel: file_ir(rel, f) for rel, f in self.files.items() if mine(rel)},
                         self.degraded, self.notes, vb_files=[r for r in self.vb_files if mine(r)],
                         parent=self, owner=owner)
        self._views[owner] = v
        return v

    def take_notes(self) -> list[str]:
        """Notes added since the last analyzer of this scan reported (one pointer for every package,
        kept on the full model), so a note appended after another analyzer reported is not lost."""
        shared = self.parent or self
        start = shared.cache.get("notes_reported", 0)
        shared.cache["notes_reported"] = len(self.notes)
        return list(self.notes[start:])

    def owns(self, path: Path) -> bool:
        """True when path belongs to this model's package: always on a full model; on a
        view, the project listing the file (else the deepest project dir holding it)
        decides, and files no project holds stay with the legacy package."""
        if self.parent is None:
            return True
        full = self.parent
        proj = full.project_of(full.rel(path))
        if proj is None:
            dirs = full._real_dirs
            if dirs is None:
                dirs = full._real_dirs = [(p, p.dir.resolve()) for p in full.projects if p.path is not None]
            here = path.resolve()
            hits = [(p, d) for p, d in dirs if here.is_relative_to(d)]
            proj = max(hits, key=lambda pd: len(pd[1].parts), default=(None, None))[0]
        return self.owner in (proj.owners if proj is not None else {"dotnet_legacy"})

    def iter_files(self, extensions: tuple[str, ...]) -> Iterator[Path]:
        """Files of the scan root with these suffixes that this model's package owns."""
        return (f for f in iter_dnl_files(self.root, extensions) if self.owns(f))

    def rel(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def types(self) -> Iterator[TypeIR]:
        for f in self.files.values():
            yield from f.types

    def find_types(self, simple_name: str) -> list[TypeIR]:
        if self._by_name is None:
            idx: dict[str, list[TypeIR]] = {}
            for t in self.types():
                idx.setdefault(t.name.split(".")[-1].lower(), []).append(t)
            self._by_name = idx
        return list(self._by_name.get(simple_name.lower(), []))

    def base_chain(self, t: TypeIR) -> list[str]:
        """Base names, transitive through project types. External names (e.g.
        Controller) are kept but not expanded; cycles stop at a seen name."""
        chain: list[str] = []
        seen = {t.name.split(".")[-1].lower()}

        def visit(cur: TypeIR) -> None:
            for b in cur.bases:
                if b.lower() not in {c.lower() for c in chain}:
                    chain.append(b)
                if b.lower() in seen:
                    continue
                seen.add(b.lower())
                for bt in self.find_types(b):
                    visit(bt)

        visit(t)
        return chain

    def derives_from(self, t: TypeIR, names: set[str]) -> bool:
        wanted = {n.lower() for n in names}
        return any(b.lower() in wanted for b in self.base_chain(t))

    def project_of(self, rel: str) -> Project | None:
        if self._rel_proj is None:
            m: dict[str, Project] = {}
            for p in self.projects:
                for f in p.compile_files:
                    m.setdefault(self.rel(f), p)
            self._rel_proj = m
        return self._rel_proj.get(rel)

    def is_core_file(self, rel: str) -> bool:
        """True when rel belongs to an ASP.NET Core / modern .NET project (never for legacy code)."""
        return self.core_project(self.project_of(rel))

    def core_project(self, proj: Project | None) -> bool:
        """True when proj is Core code as this model sees it: a multi-targeted project is legacy in the
        legacy view and Core in the Core view (and on the full model, where its primary profile holds)."""
        if proj is None:
            return False
        if proj.multi:
            return self.owner != "dotnet_legacy"
        return proj.owner == "dotnet"

    def is_core_test_file(self, rel: str) -> bool:
        """A modern .NET file of a test project: the project's own name or the folder of its project
        file is test-like (`Shop.Tests`, `MyUnitTests`, `tests`). A `Test` folder inside a production
        project does not count."""
        proj = self.project_of(rel)
        if not self.core_project(proj):
            return False
        return bool(_TEST_NAME.search(proj.name or "") or _TEST_NAME.search(proj.dir.name or ""))


# -- project loading ------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


_BASE_USINGS = ["System", "System.Collections.Generic", "System.IO", "System.Linq", "System.Net.Http",
                "System.Threading", "System.Threading.Tasks"]
_EXT_USINGS = ["Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection",
               "Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging"]
_WEB_USINGS = ["System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Hosting",
               "Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Routing"] + _EXT_USINGS

# net48-profile SDK projects name their MVC / Web API assemblies through NuGet; the
# legacy package reads the assembly names, so the package ids map onto them.
_PACKAGE_REFS = {"microsoft.aspnet.mvc": "system.web.mvc",
                 "microsoft.aspnet.webapi.core": "system.web.http",
                 "microsoft.aspnet.webpages": "system.web.webpages"}

_TFM_CORE = re.compile(r"^(?:netcoreapp\d|netstandard\d|net(\d+)\.\d+(?:-.+)?$)", re.I)
_TFM_FRAMEWORK = re.compile(r"^net\d{2,3}(?:-.+)?$", re.I)


def profile_for(tfms: list[str]) -> str:
    """Reference profile for a TargetFramework list: "netcore" when any entry is
    netcoreapp / netstandard / net5.0+, "net48" for .NET Framework monikers (net472,
    undotted) and for an empty list (a legacy project names no TargetFramework)."""
    for tfm in tfms:
        tfm = tfm.strip()
        m = _TFM_CORE.match(tfm)
        if m and (m.group(1) is None or int(m.group(1)) >= 5):
            return "netcore"
        if not m and not _TFM_FRAMEWORK.match(tfm):
            return "netcore"  # an unknown moniker on an SDK project is modern .NET
    return "net48"


def is_multi_target(tfms: list[str]) -> bool:
    """True when the list holds both a .NET Framework and a modern moniker (`net48;net8.0`)."""
    return len({profile_for([t]) for t in tfms if t.strip()}) > 1


def implicit_usings(sdk: str | None) -> list[str]:
    """Namespaces `<ImplicitUsings>enable` adds for each SDK."""
    name = (sdk or "").split("/")[0].lower()
    if name == "microsoft.net.sdk.web":
        return _BASE_USINGS + _WEB_USINGS
    if name == "microsoft.net.sdk.worker":
        return _BASE_USINGS + _EXT_USINGS
    if name.startswith("microsoft.net.sdk"):
        return list(_BASE_USINGS)
    return []


def _props_chain(start: Path, root: Path, name: str) -> list[Path]:
    """`name` files from the scan root down to start (farthest first, nearest last)."""
    out: list[Path] = []
    cur = start.resolve()
    root = root.resolve()
    while True:
        if cur.is_dir():
            try:
                hit = next((c for c in sorted(cur.iterdir()) if c.is_file() and c.name.lower() == name.lower()), None)
            except OSError:
                hit = None
            if hit is not None:
                out.append(hit)
        if cur == root or not cur.is_relative_to(root) or cur.parent == cur:
            break
        cur = cur.parent
    return out[::-1]


def _parse_xml(path: Path):
    try:
        return ET.fromstring(read_source(path).encode("utf-8"))
    except (ET.ParseError, OSError):
        return None


def _child_or_attr(el, name: str) -> str | None:
    val = el.get(name)
    if val is None:
        sub = next((c for c in el if _local(c.tag) == name), None)
        val = sub.text if sub is not None else None
    return val.strip() if val and val.strip() else None


@dataclass
class _Facts:
    sdk: str | None = None
    # Every framework named (conditional groups included): what end-of-support checks report.
    tfms: list[str] = field(default_factory=list)
    # The effective frameworks (unconditional values; nearest file wins): they decide profile and owner.
    effective: list[str] = field(default_factory=list)
    packages: dict[str, str] = field(default_factory=dict)
    framework_refs: set[str] = field(default_factory=set)
    usings: list[str] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    # File whose only TargetFramework values are conditional (no unconditional value anywhere).
    cond_only: str | None = None


_ABOVE = re.compile(r"GetPathOfFileAbove|GetDirectoryNameOfFileAbove", re.I)
_ABOVE_NAME = re.compile(r"GetPathOfFileAbove\(\s*['\"]?([^,'\")$]+)", re.I)


def _nearest_above(start: Path, root: Path, name: str) -> Path | None:
    """The nearest `name` file in start or a folder above it, never above the scan root."""
    chain = _props_chain(start, root, name)
    return chain[-1] if chain else None


def _props_layers(start: Path, root: Path) -> list:
    """(file name, parsed XML) layers of Directory.Build.props / Directory.Packages.props for a project in
    `start`, farthest first. As MSBuild does, only the NEAREST file of each name applies, unless it imports
    its parent (`GetPathOfFileAbove(..)`, `GetDirectoryNameOfFileAbove(..)` or an explicit
    `<Import Project="../Directory.Build.props">`), in which case the parent applies first. Other literal
    imports (`<Import Project="common.props">`) are followed and apply before their importer."""
    layers: list = []
    seen: set[Path] = set()
    rroot = root.resolve()

    def load(f: Path, depth: int, rank: int) -> None:
        f = f.resolve()
        if f in seen or depth > 6:
            return
        seen.add(f)
        t = _parse_xml(f)
        if t is None:
            return
        for el in t.iter():
            ref = (el.get("Project") or "").strip() if _local(el.tag) == "Import" else ""
            if not ref:
                continue
            parent = None
            if _ABOVE.search(ref):
                m = _ABOVE_NAME.search(ref)
                if f.parent != rroot and f.parent.parent.is_relative_to(rroot):
                    parent = _nearest_above(f.parent.parent, rroot, m.group(1).strip() if m else f.name)
            elif "$(" not in ref and "*" not in ref:
                target = (f.parent / ref.replace("\\", "/")).resolve()
                if target.is_file():
                    parent = target
            if parent is not None:
                load(parent, depth + 1, rank)
        layers.append((len(f.parent.parts), rank, (f.name, t)))

    for rank, name in enumerate(("Directory.Build.props", "Directory.Packages.props")):
        nearest = _nearest_above(start, rroot, name)
        if nearest is not None:
            load(nearest, 0, rank)
    layers.sort(key=lambda x: (x[0], x[1]))
    return [x for _d, _r, x in layers]


def _resolve_tfm(value: str, props: dict[str, str]) -> str | None:
    """A TargetFramework value with `$(X)` references replaced from the known properties; None when one
    stays unresolved."""
    for _ in range(5):
        if "$(" not in value:
            return value
        value = re.sub(r"\$\(([A-Za-z0-9_.]+)\)", lambda m: props.get(m.group(1), m.group(0)), value)
    return None if "$(" in value else value


def _sdk_facts(path: Path, tree, root: Path) -> _Facts:
    """Properties, packages and usings of an SDK project: the applicable Directory.Build.props files
    (nearest, plus parents it chains to), then the project file itself; central versions from
    the nearest Directory.Packages.props. A `VersionOverride` beats both. TargetFramework(s) of one
    file are the union over all its (conditional) property groups; a nearer file replaces a farther one."""
    props: dict[str, str] = {}
    refs: list[tuple[str, str | None, str | None]] = []
    usings: list[tuple[str, str]] = []
    fw: set[str] = set()
    # Per file with a TargetFramework(s): (name, [(values, conditional)] in order), farthest first.
    tfm_files: list[tuple[str, list[tuple[list[str], bool]]]] = []
    unresolved: list[str] = []
    for src_name, src in [*_props_layers(path.parent, root), (path.name, tree)]:
        if src is None:
            continue
        file_tfms: list[tuple[str, bool]] = []
        for pg in (e for e in src.iter() if _local(e.tag) == "PropertyGroup"):
            for c in pg:
                key, val = _local(c.tag), (c.text or "").strip()
                if not val:
                    continue
                if key in ("TargetFramework", "TargetFrameworks"):
                    file_tfms.append((val, bool(pg.get('Condition') or c.get('Condition'))))
                else:
                    props[key] = val
        if file_tfms:
            groups: list[tuple[list[str], bool]] = []
            for val, cond in file_tfms:
                vals: list[str] = []
                for tfm in (x.strip() for x in val.split(";")):
                    if not tfm:
                        continue
                    res = _resolve_tfm(tfm, props)
                    if res is None:
                        unresolved.append(f"{src_name}: {tfm}")
                    elif res not in vals:
                        vals.append(res)
                groups.append((vals, cond))
            tfm_files.append((src_name, groups))
        for el in src.iter():
            tag = _local(el.tag)
            if tag == "PackageReference" and el.get("Include"):
                refs.append((el.get("Include").strip(), _child_or_attr(el, "Version"), _child_or_attr(el, "VersionOverride")))
            elif tag == "FrameworkReference" and el.get("Include"):
                fw.add(el.get("Include").strip())
            elif tag == "Using":
                # Aliases and `static` usings are not namespace imports.
                if el.get("Include") and el.get("Alias") is None and el.get("Static") is None:
                    usings.append(("add", el.get("Include").strip()))
                elif el.get("Remove"):
                    usings.append(("remove", el.get("Remove").strip()))
    central: dict[str, str] = {}
    for f in _props_chain(path.parent, root, "Directory.Packages.props")[-1:]:
        t = _parse_xml(f)
        for el in (t.iter() if t is not None else ()):
            if _local(el.tag) == "PackageVersion" and el.get("Include"):
                v = _child_or_attr(el, "Version")
                if v:
                    central[el.get("Include").strip().lower()] = v
    facts = _Facts(sdk=(tree.get("Sdk") or "").strip() or None, framework_refs=fw)
    for el in tree.iter():
        if _local(el.tag) == "Sdk" and el.get("Name") and facts.sdk is None:
            facts.sdk = el.get("Name").strip()
    # Effective frameworks (profile and owner): the unconditional values of the nearest file that has
    # any; a file with only conditional values does not override a farther unconditional one. With no
    # unconditional value anywhere the last conditional group of the nearest file decides (as before),
    # and a note names the file. Reported frameworks (end of support): the effective ones plus every
    # value of the files from the one that supplied them down to the project file.
    plain_at = [i for i, (_n, g) in enumerate(tfm_files) if any(not c and v for v, c in g)]
    if plain_at:
        k = plain_at[-1]
        last_plain = [vals for vals, c in tfm_files[k][1] if not c and vals][-1]
        effective = list(last_plain)
        start = k
    elif any(v for _n, g in tfm_files for v, _c in g):
        k = max(i for i, (_n, g) in enumerate(tfm_files) if any(v for v, _c in g))
        effective = list([v for v, _c in tfm_files[k][1] if v][-1])
        start = 0
        if effective:
            facts.cond_only = tfm_files[k][0]
    else:
        effective, start = [], 0
    tfms = list(effective)
    for _n, groups in tfm_files[start:]:
        for vals, _c in groups:
            for v in vals:
                if v not in tfms:
                    tfms.append(v)
    facts.tfms = tfms
    facts.effective = effective
    facts.unresolved = unresolved
    for pid, ver, override in refs:
        facts.packages[pid.lower()] = override or ver or central.get(pid.lower(), "")
    if props.get("ImplicitUsings", "").lower() in ("enable", "true"):
        facts.usings = implicit_usings(facts.sdk)
    for kind, ns in usings:
        if kind == "add" and ns not in facts.usings:
            facts.usings.append(ns)
        elif kind == "remove" and ns in facts.usings:
            facts.usings.remove(ns)
    return facts


def sdk_profiles(path: Path, root: Path) -> set[str]:
    """Every reference profile of an SDK project file (both for `net48;net8.0`)."""
    tree = _parse_xml(path)
    facts = _sdk_facts(path, tree, root) if tree is not None else None
    if facts is None or not facts.effective:
        return {"netcore"}
    return {profile_for([t]) for t in facts.effective if t.strip()} or {"netcore"}


def sdk_profile(path: Path, root: Path) -> str:
    """Reference profile of an SDK project file (no TargetFramework anywhere = netcore)."""
    tree = _parse_xml(path)
    if tree is None:
        return "netcore"
    facts = _sdk_facts(path, tree, root)
    return profile_for(facts.effective) if facts.effective else "netcore"


def _glob_re(spec: str) -> re.Pattern:
    """MSBuild glob (`**`, `*`, `?`, `\\` or `/`) as a case-insensitive regex over a
    posix path relative to the project dir."""
    spec = spec.replace("\\", "/")
    out = ""
    i = 0
    while i < len(spec):
        if spec.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif spec.startswith("**", i):
            out += ".*"
            i += 2
        elif spec[i] == "*":
            out += "[^/]*"
            i += 1
        elif spec[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(spec[i])
            i += 1
    return re.compile(out + "$", re.I)


def _expand_include(base: Path, spec: str, exts: tuple[str, ...]) -> list[Path]:
    """Files matched by a wildcard `<Compile Include>` (the literal prefix is resolved
    case-insensitively, the rest is matched against a walk below it)."""
    segs = spec.replace("\\", "/").split("/")
    cut = next((i for i, s in enumerate(segs) if any(c in s for c in "*?")), len(segs))
    start = resolve_ci(base, "/".join(segs[:cut])) if cut else base
    if start is None or not start.is_dir():
        return []
    rx = _glob_re("/".join(segs[cut:]))
    return [f for f in iter_dnl_files(start, exts) if rx.match(f.relative_to(start).as_posix())]


def _unescape(inc: str) -> str:
    return _MSBUILD_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), inc)


def _load_project(path: Path, notes: list[str], root: Path | None = None) -> Project:
    text = read_source(path)
    proj = Project(name=path.stem, path=path, language=_PROJ_LANG[path.suffix.lower()], dir=path.parent,
                   is_legacy=is_legacy_project(text))
    sdk = proj.is_sdk
    try:
        tree = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as ex:
        notes.append(f"{path.name}: project file is not valid XML ({ex}); treated as empty")
        if sdk:
            proj.profile = "netcore"
        return proj
    exts = (_LANG_EXT[proj.language],)
    missing: dict[str, list[str]] = {}
    for el in tree.iter():
        tag = _local(el.tag)
        inc = el.get("Include")
        if tag == "TargetFrameworkVersion" and el.text:
            proj.target_framework = el.text.strip()
        elif tag == "RootNamespace" and el.text and el.text.strip():
            proj.root_namespace = el.text.strip()
        elif tag == "EnableDefaultCompileItems" and el.text and el.text.strip().lower() == "false":
            proj.default_items = False
        elif tag == "Reference" and inc:
            proj.references.add(inc.split(",")[0].strip().lower())
        elif tag == "Import" and inc and proj.language == "vb":
            proj.imports.append(inc.strip())
        elif tag == "Compile" and sdk and el.get("Remove"):
            proj.compile_remove.append(_unescape(el.get("Remove").strip()))
        elif tag == "Compile" and sdk and inc and any(c in inc for c in "*?"):
            proj.compile_files.extend(_expand_include(proj.dir, _unescape(inc), exts))
        elif tag in ("ProjectReference", "Compile", "Content") and inc:
            target = resolve_ci(proj.dir, _unescape(inc))
            if target is None:
                missing.setdefault(tag, []).append(inc)
            elif tag == "ProjectReference":
                proj.project_refs.append(target)
            elif tag == "Compile":
                proj.compile_files.append(target)
            else:
                proj.content_files.append(target)
    # One note per project and item kind: a stale project file can list hundreds of dead includes.
    for tag, incs in missing.items():
        if len(incs) == 1:
            notes.append(f"{path.name}: {tag} include not found: {incs[0]}")
        else:
            notes.append(f"{path.name}: {len(incs)} {tag} includes not found (first: {', '.join(incs[:3])})")
    if sdk:
        facts = _sdk_facts(path, tree, root or path.parent)
        proj.sdk, proj.target_frameworks, proj.packages = facts.sdk, facts.tfms, facts.packages
        proj.framework_refs = facts.framework_refs
        for u in facts.unresolved:
            notes.append(f"{path.name}: TargetFramework value could not be resolved ({u}); "
                         "end-of-support checks may miss it")
        if facts.cond_only:
            notes.append(f"{path.name}: TargetFramework is set only under a Condition ({facts.cond_only}); "
                         "the project's package is inferred from the last conditional value")
        if facts.effective:
            proj.profile = profile_for(facts.effective)
            proj.multi = is_multi_target(facts.effective)
        else:
            proj.profile = "netcore"
            why = ("TargetFramework could not be resolved" if facts.unresolved else
                   "no TargetFramework found (project file or Directory.*.props)")
            notes.append(f"{path.name}: {why}; assuming modern .NET")
        if proj.profile == "netcore":
            proj.global_usings = facts.usings
        if proj.profile != "netcore" or proj.multi:
            for pid, ref in _PACKAGE_REFS.items():
                if pid in proj.packages:
                    proj.references.add(ref)
    return proj


_CORE_SOURCE = re.compile(r"\bWebApplication(?:Builder)?\b|\busing\s+Microsoft\.AspNetCore\b|\bControllerBase\b"
                          r"|\bIEndpointRouteBuilder\b")


def is_core_source(text: str) -> bool:
    """True when C# text (comments ignored) is ASP.NET Core code: minimal hosting,
    an AspNetCore using, ControllerBase or endpoint routing."""
    return bool(_CORE_SOURCE.search(re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)))


def _is_core_file(path: Path) -> bool:
    try:
        return is_core_source(read_source(path))
    except OSError:
        return False


def load_projects(root: Path, notes: list[str] | None = None) -> list[Project]:
    """Every csproj/vbproj under root, plus "(loose)" projects for source files no
    project claims (C#: one per owning package; VB: legacy)."""
    notes = notes if notes is not None else []
    projects = [_load_project(p, notes, root) for p in iter_dnl_files(root, tuple(_PROJ_LANG))]
    # SDK-style projects glob their sources implicitly (even when they also list some
    # Compile items), minus `<Compile Remove>`; a file under a nested project's dir belongs
    # to that (deeper) project.
    for p in projects:
        if not p.is_sdk:
            continue
        here = p.dir.resolve()
        nested = [q.dir.resolve() for q in projects
                  if q is not p and q.dir.resolve() != here and q.dir.resolve().is_relative_to(here)]
        files = list(p.compile_files)
        if p.default_items:
            files += [f for f in iter_dnl_files(p.dir, (_LANG_EXT[p.language],))
                      if not any(f.resolve().is_relative_to(n) for n in nested)]
        removes = [_glob_re(r) for r in p.compile_remove]
        seen: set[Path] = set()
        p.compile_files = []
        for f in files:
            rel = Path(os.path.relpath(f, p.dir)).as_posix()
            if f.resolve() in seen or any(rx.match(rel) for rx in removes):
                continue
            seen.add(f.resolve())
            p.compile_files.append(f)
        if p.language == "vb" and p.profile == "netcore":
            notes.append(f"{p.path.name}: Visual Basic on modern .NET is not analyzed")
    claimed = {f.resolve() for p in projects for f in p.compile_files}
    for lang, ext in _LANG_EXT.items():
        loose = [f for f in iter_dnl_files(root, (ext,)) if f.resolve() not in claimed]
        if lang == "cs":
            core = [f for f in loose if _is_core_file(f)]
            if core:
                projects.append(Project(name=LOOSE, path=None, language=lang, dir=root, compile_files=core,
                                        profile="netcore"))
            loose = [f for f in loose if f not in core]
        if loose:
            projects.append(Project(name=LOOSE, path=None, language=lang, dir=root, compile_files=loose))
    return projects


# -- model building -------------------------------------------------------

_CACHE: dict[Path, ProjectModel] = {}


# Name suffix of the helper request entry that compiles a multi-targeted project's files under the net48
# profile; the IR coming back is routed to ProjectModel.alt_files and the suffix dropped again.
ALT_SUFFIX = "@net48"


def _request(projects: list[Project]) -> list[dict]:
    """Helper request: every project's files of its own language (legacy, SDK and
    loose), each with its reference profile; each file sent once (first project wins
    when includes overlap). VB on modern .NET is skipped (not analyzed)."""
    sent: set[Path] = set()
    out = []
    for p in projects:
        if p.language == "vb" and p.owner == "dotnet":
            continue
        ext = _LANG_EXT[p.language]
        files = []
        for f in p.compile_files:
            if f.suffix.lower() == ext and f.resolve() not in sent:
                sent.add(f.resolve())
                files.append(str(f))
        if files:
            req = {"name": p.name, "language": p.language, "files": files,
                   "references": sorted(p.references), "refs": p.profile}
            if p.language == "vb":
                req["imports"] = list(p.imports)
            if p.profile == "netcore":
                req["global_usings"] = list(p.global_usings)
            out.append(req)
            if p.multi:
                # The same files again under the net48 profile (no implicit usings), for the legacy view.
                out.append({"name": p.name + ALT_SUFFIX, "language": p.language, "files": list(files),
                            "references": sorted(p.references), "refs": "net48"})
    return out


_TYPE_WORD = re.compile(r"\b(?:class|struct|interface|enum|record)\b")


def _declares_types(path: Path) -> bool:
    """True when the file text (comments dropped) mentions a type keyword."""
    try:
        text = read_source(path)
    except OSError:
        return False
    text = re.sub(r"//[^\n]*|/\*.*?\*/", "", text, flags=re.S)
    return bool(_TYPE_WORD.search(text))


def _degraded_files(root: Path, projects: list[Project], notes: list[str]) -> tuple[dict[str, FileIR], list[str]]:
    """No helper: lower every C# file of the legacy / loose projects with tree-sitter
    (no `sym` / `type_full`); VB files are only listed, for the pattern scan."""
    files: dict[str, FileIR] = {}
    vb: list[str] = []
    for req in _request(projects):
        if req["name"].endswith(ALT_SUFFIX):
            continue  # degraded IR has no symbols: one lowering serves both views
        for f in req["files"]:
            path = Path(f)
            rel = path.resolve().relative_to(root).as_posix() if path.resolve().is_relative_to(root) else path.as_posix()
            if req["language"] == "vb":
                vb.append(rel)
                continue
            obj = frontend_ts.lower_file(path, rel, req["name"])
            fir = load_file_ir(obj)
            if fir is None:
                notes.append(f"{rel}: {obj.get('error', 'no IR produced')}")
            else:
                files[fir.path] = fir
                if fir.parse_errors:
                    notes.append(f"{rel}: {fir.parse_errors} C# parse errors in degraded mode; "
                                 "code in the affected region may be missing")
                if not fir.types and _declares_types(path):
                    notes.append(f"{rel}: C# file lowered to no types in degraded mode; its code was not analyzed")
    return files, vb


def _share_alt_files(model: ProjectModel) -> None:
    """Degraded mode: the tree-sitter IR carries no symbols, so the netcore IR serves the net48 view of
    a multi-targeted project too (the source is identical; only symbol resolution would differ)."""
    for p in model.projects:
        if not p.multi:
            continue
        shared = False
        for f in p.compile_files:
            fir = model.files.get(model.rel(f))
            if fir is not None:
                model.alt_files[fir.path] = fir
                shared = True
        if shared:
            model.notes.append(f"{p.path.name if p.path else p.name}: multi-target project (net4x + modern): "
                               "the legacy and Core views share one tree-sitter parse in degraded mode")


def prepare(target: Path, allow_degraded: bool) -> ProjectModel:
    """Preflight the helper, parse every project once and cache the model.
    Without a helper (allow_degraded) C# is lowered by tree-sitter and VB files
    are left for the pattern scan."""
    root = target.resolve()
    notes: list[str] = []
    projects = load_projects(root, notes)
    binary = helper.preflight(target, allow_degraded)
    if binary is None:
        files, vb = _degraded_files(root, projects, notes)
        model = ProjectModel(root, projects, files, helper.DEGRADED_REASON, notes, vb_files=vb)
        _share_alt_files(model)
    else:
        files: dict[str, FileIR] = {}
        alt: dict[str, FileIR] = {}
        for obj in helper.parse_projects(binary, root, _request(projects)):
            fir = load_file_ir(obj)
            if fir is None:
                notes.append(f"{obj.get('path', '?')}: {obj.get('error', 'no IR produced')}")
            elif fir.project.endswith(ALT_SUFFIX):
                fir.project = fir.project[:-len(ALT_SUFFIX)]
                alt[fir.path] = fir
            else:
                files[fir.path] = fir
        model = ProjectModel(root, projects, files, None, notes, alt_files=alt)
    _CACHE[root] = model
    return model


def get_model(target: Path, owner: str | None = None) -> ProjectModel:
    """The model prepared for target, else a fresh strict one; owner selects that
    package's view of it (None = the full model)."""
    model = _CACHE.get(target.resolve()) or prepare(target, False)
    return model.view(owner) if owner else model
