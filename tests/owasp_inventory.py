"""Static inventory of every rule id the scanner can emit outside the
dotnet_legacy (DNL-) analyzers, and which language families emit it.

Shared by tests/test_owasp_all_rules.py (every id is mapped) and
tests/test_owasp_readme.py (the README coverage table matches RULES).

Rule ids are found by reading source, not by running anything: any quoted
literal shaped like PREFIX-NNN / PREFIX-SUB-NNN in checks/, languages/ and
core/ (minus the DNL packages and the mapping tables themselves) counts.

Family membership (python, java, javascript, go, ruby, dotnet, sql, infra,
crypto, plus "sca" for the --sca osv-scanner path in main.py):
  1. A literal inside languages/<lang>/ belongs to <lang>.
  2. A literal inside a checks/ module belongs to the languages whose code
     reaches that module. When the literal sits in a top-level function
     that language code references by name (auth.insecure_cookie_finding
     called from the Spring analyzer), only the languages referencing that
     function count -- that keeps shared modules like checks/auth.py from
     claiming every language emits every rule in them.
  3. Otherwise the module's families are its importers' families,
     transitively (checks/secrets.py -> shell/terraform/... -> infra).
  4. main.py is the "sca" family. EXCLUDED_EDGES lists imports that exist
     only to correlate data, not to emit the importee's rules.
  5. DNL- ids are not in the scan above (dotnet_legacy owns them), except
     those in checks/dnl modules reachable by imports, transitively within
     checks/dnl, from languages/dotnet/*.py: they count for dotnet
     (dnl_ids_for_dotnet). Modules reached only from languages/dotnet_legacy
     do not count.
"""
from __future__ import annotations

import ast
import re
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Rule ids are found as quoted literals only: an emitter must spell its id out
# ("TF-S3-001"), never build it with an f-string or format(), or this
# inventory -- and the every-id-is-mapped test -- cannot see it.
# Same shape as every rule id in the tree (letters/dashes, trailing number).
ID_SHAPE = re.compile(r"^[A-Z]+(?:-[A-Z][A-Z0-9]*)*-\d+$")
_LITERAL = re.compile(r"""["']([A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+)["']""")

# Quoted tokens that match ID_SHAPE but are not rule ids (none today).
NOT_RULE_IDS: frozenset[str] = frozenset()

# Imports that correlate data rather than emit the importee's rules: the
# Lambda scanner asks tf_graph which role a handler runs as (LMB-019) but
# never emits POL-* itself. rules_crypto borrows rules_config's regexes for
# hardcoded credentials but never emits the Web.config rules (DNL-CFG-*);
# rules_logging borrows its package / config-file regexes the same way.
# rules_deser_xml imports rules_taint lazily and rules_resources imports rules_object; Core runs both
# (taint and object rules are wired into languages/dotnet/analyzers.py), so those edges are NOT excluded.
EXCLUDED_EDGES = {("aws_lambda", "tf_graph"), ("rules_crypto", "rules_config"), ("rules_logging", "rules_config")}

# Ids inside modules Core does run that do not fire on conventional SDK projects (see
# languages/dotnet/CARRIED_RULES.md for the edge layouts, e.g. a stray .aspx inside an SDK project
# directory, or a user type named like OWIN's AuthenticationManager): they do not count towards the dotnet row.
CORE_NEVER_EMITTED = {"DNL-INT-004", "DNL-XXE-002", "DNL-SESS-006", "DNL-SESS-007", "DNL-LOG-002"}

# Families whose analyzers can mark a finding as sitting on an API surface
# (see core.owasp_web.api_surface_for); the rest only get API tags from
# "always" rules.
API_CAPABLE = {"python", "java", "javascript", "go", "dotnet"}

FAMILIES = ["python", "java", "javascript", "go", "ruby", "dotnet", "sql", "infra", "crypto", "sca"]


def _sources() -> list[Path]:
    out = []
    for base in ("checks", "languages", "core"):
        for p in (ROOT / base).rglob("*.py"):
            parts = p.relative_to(ROOT).parts
            if "dnl" in parts or "dotnet_legacy" in parts or "__pycache__" in parts:
                continue
            if p.name in ("owasp_web.py", "owasp_isr.py"):
                continue
            out.append(p)
    out.append(ROOT / "main.py")
    return out


def _rel(p: Path) -> str:
    return p.relative_to(ROOT).as_posix()


def _enclosing_functions(tree: ast.AST) -> dict[int, str | None]:
    """line -> name of the top-level function containing it (else None)."""
    spans = {}
    for node in tree.body:  # type: ignore[attr-defined]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                spans[ln] = node.name
    return spans


@lru_cache(maxsize=1)
def _scan() -> tuple[dict[str, set[tuple[str, str | None]]], dict[str, set[str]], dict[str, set[str]]]:
    """(id -> {(file, function)}, file -> imported checks modules, file -> referenced names)."""
    id_sites: dict[str, set[tuple[str, str | None]]] = {}
    imports: dict[str, set[str]] = {}
    names: dict[str, set[str]] = {}
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        rel = _rel(path)
        funcs = _enclosing_functions(tree)
        imps: set[str] = set()
        refs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "checks":
                    imps.update(a.name for a in node.names)
                elif node.module.startswith("checks."):
                    imps.add(node.module.split(".")[1])
            elif isinstance(node, ast.Import):
                imps.update(a.name.split(".")[1] for a in node.names if a.name.startswith("checks."))
            elif isinstance(node, ast.Attribute):
                refs.add(node.attr)
            elif isinstance(node, ast.Name):
                refs.add(node.id)
        imports[rel] = imps
        names[rel] = refs
        for m in _LITERAL.finditer(text):
            rid = m.group(1)
            if ID_SHAPE.match(rid) and rid not in NOT_RULE_IDS:
                line = text.count("\n", 0, m.start()) + 1
                id_sites.setdefault(rid, set()).add((rel, funcs.get(line)))
    return id_sites, imports, names


def rule_ids() -> set[str]:
    """Every non-DNL rule id literal in the sources."""
    return {i for i in _scan()[0] if not i.startswith("DNL-")}


def _dnl_imports(path: Path) -> set[str]:
    """Module stems of checks/dnl that `path` imports (absolute or relative)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    in_dnl = "dnl" in path.relative_to(ROOT).parts
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level and in_dnl:
                if node.module:
                    out.add(node.module.split(".")[0])
                else:
                    out.update(a.name for a in node.names)
            elif node.module == "checks.dnl":
                out.update(a.name for a in node.names)
            elif node.module and node.module.startswith("checks.dnl."):
                out.add(node.module.split(".")[2])
        elif isinstance(node, ast.Import):
            out.update(a.name.split(".")[2] for a in node.names
                       if a.name.startswith("checks.dnl.") and a.name.count(".") >= 2)
    return out


def dnl_ids_for_dotnet() -> set[str]:
    """DNL- id literals in checks/dnl modules reachable by imports from
    languages/dotnet/*.py (the dotnet package; dotnet_legacy is not a root)."""
    dnl_dir = ROOT / "checks" / "dnl"
    available = {p.stem: p for p in dnl_dir.glob("*.py")}
    todo: list[str] = []
    for src in (ROOT / "languages" / "dotnet").glob("*.py"):
        todo.extend(m for m in _dnl_imports(src) if m in available)
    seen: set[str] = set()
    ids: set[str] = set()
    while todo:
        mod = todo.pop()
        if mod in seen:
            continue
        seen.add(mod)
        text = available[mod].read_text(encoding="utf-8")
        ids.update(m.group(1) for m in _LITERAL.finditer(text)
                   if m.group(1).startswith("DNL-") and ID_SHAPE.match(m.group(1)))
        todo.extend(m for m in _dnl_imports(available[mod])
                    if m in available and m != mod and (mod, m) not in EXCLUDED_EDGES)
    return ids - CORE_NEVER_EMITTED


def _lang_of(rel: str) -> str | None:
    parts = rel.split("/")
    return parts[1] if parts[0] == "languages" and len(parts) > 2 else None


def _module_families(module: str, seen: frozenset[str] = frozenset()) -> set[str]:
    _, imports, _ = _scan()
    fams: set[str] = set()
    for rel, imps in imports.items():
        if module not in imps or (Path(rel).stem, module) in EXCLUDED_EDGES:
            continue
        if _lang_of(rel):
            fams.add(_lang_of(rel))
        elif rel == "main.py":
            fams.add("sca")
        elif rel.startswith("checks/"):
            stem = Path(rel).stem
            if stem != module and stem not in seen:
                fams |= _module_families(stem, seen | {module})
    return fams


def families_of(rid: str) -> set[str]:
    """Language families that can emit `rid`."""
    if rid.startswith("DNL-"):
        return {"dotnet"} if rid in dnl_ids_for_dotnet() else set()
    _, imports, names = _scan()
    fams: set[str] = set()
    for rel, func in _scan()[0][rid]:
        lang = _lang_of(rel)
        if lang:
            fams.add(lang)
        elif rel == "main.py":
            fams.add("sca")
        elif rel.startswith("checks/"):
            module = Path(rel).stem
            by_func = set()
            if func and not func.startswith("_"):
                by_func = {_lang_of(r) for r, n in names.items()
                           if _lang_of(r) and func in n and module in imports[r]}
            fams |= by_func or _module_families(module)
    return fams & set(FAMILIES)


# -- README coverage table ---------------------------------------------------

TABLE_HEADER = (
    "| Family | Rules | Web 2025 covered | Web 2025 gaps | API 2023 covered | API 2023 gaps |\n"
    "|---|---|---|---|---|---|"
)


def _codes(codes) -> str:
    return " ".join(sorted(codes, key=lambda c: int("".join(ch for ch in c if ch.isdigit())))) or "none"


def coverage_rows(rules: dict) -> list[str]:
    """One markdown row per language family: how many rules it can emit and
    which Web 2025 / API 2023 categories at least one of them maps to.

    An API 2023 tag only reaches a finding when the rule is "always" or the
    family can mark an API surface (API_CAPABLE), so a rule that is
    "api_surface" only counts for those families.
    """
    from core.owasp_web import TITLES

    by_family: dict[str, list[str]] = {f: [] for f in FAMILIES}
    for rid in sorted(rule_ids() | dnl_ids_for_dotnet()):
        for fam in families_of(rid):
            by_family[fam].append(rid)
    rows = []
    for fam in FAMILIES:
        ids = [i for i in by_family[fam] if i in rules]
        web = {rules[i][0] for i in ids}
        api = {rules[i][2] for i in ids if rules[i][2] and (rules[i][3] == "always" or fam in API_CAPABLE)}
        web_gaps = set(TITLES["2025"]) - web
        api_gaps = set(TITLES["api2023"]) - api
        rows.append(f"| {fam} | {len(ids)} | {_codes(web)} | {_codes(web_gaps)} | {_codes(api)} | {_codes(api_gaps)} |")
    return rows
