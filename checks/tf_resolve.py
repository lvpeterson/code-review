"""Resolve Terraform `var.*`, `local.*` and module-input references in place.

The Terraform rules compare attribute values against literals
(`acl == "public-read"`, `publicly_accessible == true`). Real configs rarely
write literals inline -- they write `acl = var.bucket_acl` and set the value
in a .tfvars file, a variable default, or the calling module block. This
pass rewrites each Attr.value to the value it resolves to, so every
existing rule sees through variables without changing, and records where
the value came from in Attr.raw / Attr.via for the finding text.

Where a variable's value comes from, in Terraform's own precedence order:
  1. .tfvars in the module's directory (terraform.tfvars and *.auto.tfvars
     first, then any other *.tfvars -- e.g. per-environment files passed
     with -var-file). A .tfvars in a directory with no .tf files (an
     `envs/` folder) applies to every root module.
  2. The argument a calling `module "x" { source = "./modules/y" }` block
     passes (only local module sources can be followed).
  3. The variable's `default`.
When several .tfvars / callers set different values, the first is used and
the others are listed in the provenance note, so per-environment
differences stay visible.

Supported expressions: bare `var.x` / `local.x`, "${var.x}" interpolation
inside strings, refs inside lists/objects, `var.x ? a : b` once the
condition resolves, and chains (a local that refers to a variable that a
caller passes from its own variable...). Anything else (functions, resource
attributes, count/for_each) is left as is.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from checks.hcl import Block, parse_hcl

MAX_DEPTH = 8
_BARE = re.compile(r"^(var|local)\.([A-Za-z_][\w-]*)$")
_INTERP = re.compile(r"\$\{\s*(var|local)\.([A-Za-z_][\w-]*)\s*\}")
_INLINE_REF = re.compile(r"(?<![\w.\"$])(var|local)\.([A-Za-z_][\w-]*)(?![\w-]|\s*[\[(]|\.)")
_TERNARY = re.compile(r"^\s*(true|false)\s*\?\s*(.+?)\s*:\s*(.+?)\s*$", re.S)
_MODULE_META = {"source", "version", "providers", "count", "for_each", "depends_on"}


@dataclass
class Candidate:
    text: str
    where: str   # human-readable origin: "terraform.tfvars:3", "default in variables.tf:12"
    dir: Path    # directory the text itself must be resolved in


def _strip_strings(text: str) -> str:
    return re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)


def is_literal(text: str) -> bool:
    """A value with no references or function calls left: "x", 1, true,
    ["a", "b"], { k = "v" }."""
    t = text.strip()
    if not t or t in ("null",):
        return False
    if t.startswith("<<"):
        return "${" not in t
    if "${" in t:
        return False
    bare = _strip_strings(t)
    if re.search(r"[A-Za-z_][\w-]*\s*\(", bare):
        return False
    if re.search(r"\b[A-Za-z_][\w-]*\.[A-Za-z_*]", bare):
        return False
    if re.search(r"[?:]\s", bare) and not t.startswith("{"):
        return False
    return True


def _scalar_inner(text: str) -> Optional[str]:
    """Content to splice into a string interpolation, or None if not scalar."""
    t = text.strip()
    if len(t) >= 2 and t[0] == t[-1] == '"' and t.count('"') == 2:
        return t[1:-1]
    if re.fullmatch(r"-?\d+(?:\.\d+)?|true|false", t):
        return t
    return None


def _short(text: str, n: int = 60) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else t[: n - 3] + "..."


def _hcl_from_json(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, str):
        return json.dumps(v)
    return json.dumps(v)  # lists / objects: JSON is valid HCL expression syntax for our purposes


class Resolver:
    def __init__(self, root: Path):
        self.root = root
        self.vars: dict[Path, dict[str, Candidate]] = defaultdict(dict)
        self.locals: dict[Path, dict[str, Candidate]] = defaultdict(dict)
        self.tfvars: dict[Path, dict[str, list[Candidate]]] = defaultdict(lambda: defaultdict(list))
        self.inputs: dict[Path, dict[str, list[Candidate]]] = defaultdict(lambda: defaultdict(list))
        self.resolved_count = 0

    # ── indexing ──────────────────────────────────────────────────────────

    def index(self, blocks: list[Block], tfvars_files: dict[Path, str], tf_dirs: set[Path]) -> None:
        module_targets: set[Path] = set()
        for b in blocks:
            d = b.file.parent.resolve()
            if b.kind == "variable" and b.labels:
                dflt = b.attr("default")
                if dflt is not None and dflt.value.strip() not in ("null", '""'):
                    self.vars[d][b.labels[0]] = Candidate(dflt.value, f"default in {b.file.name}:{dflt.line}", d)
            elif b.kind == "locals":
                for name, a in b.attrs.items():
                    self.locals[d][name] = Candidate(a.value, f"locals in {b.file.name}:{a.line}", d)
            elif b.kind == "module" and b.labels:
                src = b.attr("source").literal() if b.attr("source") else None
                if src and src.startswith(("./", "../")):
                    target = (d / src).resolve()
                    module_targets.add(target)
                    for name, a in b.attrs.items():
                        if name not in _MODULE_META:
                            self.inputs[target][name].append(
                                Candidate(a.value, f"module.{b.labels[0]} in {b.file.name}:{a.line}", d))

        resolved_tf_dirs = {p.resolve() for p in tf_dirs}
        root_modules = sorted(resolved_tf_dirs - module_targets) or sorted(resolved_tf_dirs)

        def order(p: Path):
            auto = p.name == "terraform.tfvars" or p.name.endswith((".auto.tfvars", ".auto.tfvars.json"))
            return (0 if auto else 1, str(p))

        for path in sorted(tfvars_files, key=order):
            d = path.parent.resolve()
            targets = [d] if d in resolved_tf_dirs else root_modules
            for name, cand in self._read_tfvars(path, tfvars_files[path]):
                for t in targets:
                    self.tfvars[t][name].append(cand)

    def _read_tfvars(self, path: Path, text: str):
        d = path.parent.resolve()
        if path.name.endswith(".json"):
            try:
                data = json.loads(text)
            except ValueError:
                return
            for k, v in (data.items() if isinstance(data, dict) else []):
                yield k, Candidate(_hcl_from_json(v), path.name, d)
            return
        wrapped = parse_hcl("__tfvars__ {\n" + text + "\n}\n", path)
        if not wrapped:
            return
        for name, a in wrapped[0].attrs.items():
            yield name, Candidate(a.value, f"{path.name}:{a.line - 1}", d)

    # ── resolution ────────────────────────────────────────────────────────

    def _ref(self, kind: str, name: str, d: Path, depth: int, seen: frozenset) -> Optional[tuple[str, str]]:
        key = (kind, name, d)
        if depth > MAX_DEPTH or key in seen:
            return None
        seen = seen | {key}
        if kind == "var":
            cands = list(self.tfvars[d].get(name, [])) + list(self.inputs[d].get(name, []))
            if name in self.vars[d]:
                cands.append(self.vars[d][name])
        else:
            cands = [self.locals[d][name]] if name in self.locals[d] else []
        results = []
        for c in cands:
            r = self.resolve_text(c.text, c.dir, depth + 1, seen)
            text, via = r if r else (c.text, "")
            if is_literal(text):
                results.append((text, c.where, via))
        if not results:
            return None
        text, where, via = results[0]
        note = f"{kind}.{name} = {_short(text)} ({where})"
        others = [f"{_short(t, 30)} in {w}" for t, w, _ in results[1:] if t.strip() != text.strip()]
        if others:
            note += f" [other values: {'; '.join(others[:3])}]"
        if via:
            note += f" <- {via}"
        return text, note

    def resolve_text(self, text: str, d: Path, depth: int = 0, seen: frozenset = frozenset()) -> Optional[tuple[str, str]]:
        """(new_text, provenance) if any reference in `text` was substituted."""
        if "var." not in text and "local." not in text:
            return None
        notes: list[str] = []
        t = text.strip()

        m = _BARE.match(t)
        if m:
            r = self._ref(m.group(1), m.group(2), d, depth, seen)
            if not r:
                return None
            return r[0], r[1]

        changed = False

        def interp(mm: re.Match) -> str:
            nonlocal changed
            r = self._ref(mm.group(1), mm.group(2), d, depth, seen)
            inner = _scalar_inner(r[0]) if r else None
            if inner is None:
                return mm.group(0)
            changed = True
            notes.append(r[1])
            return inner

        t2 = _INTERP.sub(interp, t)

        # Bare refs outside strings: [var.cidr], { key = local.x }, var.flag ? a : b
        out, i = [], 0
        for sm in re.finditer(r'"(?:[^"\\]|\\.)*"', t2):
            out.append(("code", t2[i:sm.start()]))
            out.append(("str", sm.group(0)))
            i = sm.end()
        out.append(("code", t2[i:]))

        def inline(mm: re.Match) -> str:
            nonlocal changed
            r = self._ref(mm.group(1), mm.group(2), d, depth, seen)
            if not r:
                return mm.group(0)
            changed = True
            notes.append(r[1])
            return r[0]

        t3 = "".join(_INLINE_REF.sub(inline, s) if kind == "code" else s for kind, s in out)

        tm = _TERNARY.match(t3)
        if tm:
            t3 = tm.group(2) if tm.group(1) == "true" else tm.group(3)
            changed = True

        if not changed:
            return None
        return t3, "; ".join(dict.fromkeys(notes))

    def apply(self, blocks: list[Block]) -> None:
        for top in blocks:
            if top.kind in ("variable", "locals"):
                continue
            d = top.file.parent.resolve()
            for b in top.walk():
                for a in b.attrs.values():
                    r = self.resolve_text(a.value, d)
                    if r and r[0].strip() != a.value.strip():
                        a.raw, a.value, a.via = a.value, r[0], r[1]
                        self.resolved_count += 1


def resolve_project(root: Path, blocks: list[Block], tfvars_files: dict[Path, str], tf_dirs: set[Path]) -> Resolver:
    r = Resolver(root)
    r.index(blocks, tfvars_files, tf_dirs)
    r.apply(blocks)
    return r
