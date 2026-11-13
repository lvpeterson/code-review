"""Solution model for the legacy .NET analyzer: projects from csproj/vbproj
plus the parsed IR of every source file, with cross-project type lookup.

The Roslyn helper compiles each project alone, so inheritance across files and
projects (HomeController : BaseController : Controller) is resolved here by
simple name over the IR.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

from checks.dnl import helper
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

    def __post_init__(self) -> None:
        # Lazy indexes; built on first lookup.
        self._by_name: dict[str, list[TypeIR]] | None = None
        self._rel_proj: dict[str, Project] | None = None

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


# -- project loading ------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _load_project(path: Path, notes: list[str]) -> Project:
    text = read_source(path)
    proj = Project(name=path.stem, path=path, language=_PROJ_LANG[path.suffix.lower()], dir=path.parent,
                   is_legacy=is_legacy_project(text))
    try:
        tree = ET.fromstring(text.encode("utf-8"))
    except ET.ParseError as ex:
        notes.append(f"{path.name}: project file is not valid XML ({ex}); treated as empty")
        return proj
    missing: dict[str, list[str]] = {}
    for el in tree.iter():
        tag = _local(el.tag)
        inc = el.get("Include")
        if tag == "TargetFrameworkVersion" and el.text:
            proj.target_framework = el.text.strip()
        elif tag == "RootNamespace" and el.text and el.text.strip():
            proj.root_namespace = el.text.strip()
        elif tag == "Reference" and inc:
            proj.references.add(inc.split(",")[0].strip().lower())
        elif tag == "Import" and inc and proj.language == "vb":
            proj.imports.append(inc.strip())
        elif tag in ("ProjectReference", "Compile", "Content") and inc:
            target = resolve_ci(proj.dir, _MSBUILD_ESCAPE.sub(lambda m: chr(int(m.group(1), 16)), inc))
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
    return proj


def load_projects(root: Path, notes: list[str] | None = None) -> list[Project]:
    """Every csproj/vbproj under root, plus a "(loose)" project per language
    for source files no project claims."""
    notes = notes if notes is not None else []
    projects = [_load_project(p, notes) for p in iter_dnl_files(root, tuple(_PROJ_LANG))]
    # SDK-style projects glob their sources implicitly (even when they also list
    # some Compile items), so they own every source under their dir. They belong to the separate
    # dotnet analyzer: claimed here so they are not "(loose)", never parsed.
    for p in projects:
        if not p.is_legacy:
            p.compile_files = list(iter_dnl_files(p.dir, tuple(_LANG_EXT.values())))
    claimed = {f.resolve() for p in projects for f in p.compile_files}
    for lang, ext in _LANG_EXT.items():
        loose = [f for f in iter_dnl_files(root, (ext,)) if f.resolve() not in claimed]
        if loose:
            projects.append(Project(name=LOOSE, path=None, language=lang, dir=root, compile_files=loose))
    return projects


# -- model building -------------------------------------------------------

_CACHE: dict[Path, ProjectModel] = {}


def _request(projects: list[Project]) -> list[dict]:
    """Helper request: legacy and loose projects, files of their own language,
    each file sent once (first project wins when includes overlap)."""
    sent: set[Path] = set()
    out = []
    for p in projects:
        if not (p.is_legacy or p.path is None):
            continue
        ext = _LANG_EXT[p.language]
        files = []
        for f in p.compile_files:
            if f.suffix.lower() == ext and f.resolve() not in sent:
                sent.add(f.resolve())
                files.append(str(f))
        if files:
            req = {"name": p.name, "language": p.language, "files": files,
                   "references": sorted(p.references)}
            if p.language == "vb":
                req["imports"] = list(p.imports)
            out.append(req)
    return out


def prepare(target: Path, allow_degraded: bool) -> ProjectModel:
    """Preflight the helper, parse every project once and cache the model.
    Without a helper (allow_degraded) the model has projects but no IR."""
    root = target.resolve()
    notes: list[str] = []
    projects = load_projects(root, notes)
    binary = helper.preflight(target, allow_degraded)
    if binary is None:
        model = ProjectModel(root, projects, {}, helper.DEGRADED_REASON, notes)
    else:
        files: dict[str, FileIR] = {}
        for obj in helper.parse_projects(binary, root, _request(projects)):
            fir = load_file_ir(obj)
            if fir is None:
                notes.append(f"{obj.get('path', '?')}: {obj.get('error', 'no IR produced')}")
            else:
                files[fir.path] = fir
        model = ProjectModel(root, projects, files, None, notes)
    _CACHE[root] = model
    return model


def get_model(target: Path) -> ProjectModel:
    """The model prepared for target, else a fresh strict one."""
    return _CACHE.get(target.resolve()) or prepare(target, False)
