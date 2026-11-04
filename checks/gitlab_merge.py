"""Resolve GitLab CI job inheritance without a YAML loader (so line numbers
stay exact): `extends:` (single, list, multi-level), YAML anchors merged
with `<<: *name`, `!reference [.tmpl, key]`, top-level `default:`, and
`include: local:` files. Each job gets an *effective* text -- its own keys
plus every inherited key it doesn't override -- which the GL rules read for
logic (rules/when/environment/id_tokens), while line numbers still come
from the job's own text.

Not resolvable from the repo: `include: project:` / `remote:` /
`template:` / `component:` content. Templates that live there are listed in
Effective.unresolved so findings can say so.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from core.fsutil import _SKIP_DIRS, read_text_safe
from core.rulescan import mask_comments

_TOP_KEY = re.compile(r"^([^\s#\-][^:]*?):(?:\s|$)")
_ANCHOR_DEF = re.compile(r"^(?P<indent>\s*)(?:-\s+)?(?P<key>[^\s:#][^:]*?)\s*:\s*&(?P<name>[\w.-]+)\s*$")
_GLOBAL_KEYS = {"stages", "variables", "include", "default", "workflow", "image", "services",
                "before_script", "after_script", "cache", "spec"}


@dataclass
class JobDef:
    name: str
    file: Path
    start: int          # 1-based line of the job key
    text: str           # masked text incl. the "name:" line
    keys: dict = field(default_factory=dict)   # key -> body text (incl. its own "key:" line)


@dataclass
class Effective:
    text: str
    sources: list[str] = field(default_factory=list)     # "extends .tf_base (ci/templates.yml:3)"
    unresolved: list[str] = field(default_factory=list)  # template names not found in the repo
    inherited_keys: dict = field(default_factory=dict)   # key -> source description


def child_keys(body_lines: list[str]) -> dict[str, str]:
    """Split the lines under a mapping into {key: text} at the first indent level."""
    indent = None
    for ln in body_lines:
        if ln.strip() and not ln.lstrip().startswith("#"):
            indent = len(ln) - len(ln.lstrip())
            break
    if indent is None:
        return {}
    keys: dict[str, list[str]] = {}
    current = None
    for ln in body_lines:
        if ln.strip():
            ind = len(ln) - len(ln.lstrip())
            m = re.match(r"^\s*([^\s:#][^:]*?)\s*:(?:\s|$)", ln)
            if ind == indent and m:
                current = m.group(1).strip().strip("'\"")
                keys.setdefault(current, [])
                keys[current].append(ln)
                continue
            if ind < indent:
                current = None
        if current is not None:
            keys[current].append(ln)
    return {k: "\n".join(v) for k, v in keys.items()}


def _split(masked: str, path: Path) -> list[JobDef]:
    lines = masked.split("\n")
    starts = []
    for i, ln in enumerate(lines):
        m = _TOP_KEY.match(ln)
        if m:
            starts.append((i, m.group(1).strip().strip("'\"")))
    out = []
    for k, (i, name) in enumerate(starts):
        end = (starts[k + 1][0] - 1) if k + 1 < len(starts) else len(lines) - 1
        body = lines[i:end + 1]
        jd = JobDef(name, path, i + 1, "\n".join(body))
        jd.keys = child_keys(body[1:])
        out.append(jd)
    return out


def _anchors(masked: str) -> dict[str, dict[str, str]]:
    """anchor name -> its mapping's child keys."""
    lines = masked.split("\n")
    out = {}
    for i, ln in enumerate(lines):
        m = _ANCHOR_DEF.match(ln)
        if not m:
            continue
        base = len(m.group("indent"))
        body = []
        for nxt in lines[i + 1:]:
            if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= base:
                break
            body.append(nxt)
        out[m.group("name")] = child_keys(body)
    return out


def _list_value(text: str, key: str) -> list[str]:
    """`key: x`, `key: [a, b]` or a block list under key -> values."""
    m = re.search(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*:[ \t]*(.*)$", text)
    if not m:
        return []
    inline = m.group(1).strip()
    if inline.startswith("["):
        return [v.strip().strip("'\"") for v in inline.strip("[]").split(",") if v.strip()]
    if inline:
        return [inline.strip("'\"")]
    vals = []
    for ln in text[m.end():].split("\n")[1:]:
        lm = re.match(r"^\s*-\s+['\"]?([^'\"#\s]+)", ln)
        if lm:
            vals.append(lm.group(1))
        elif ln.strip():
            break
    return vals


def _local_includes(masked: str, base: Path, root: Path) -> list[Path]:
    out = []
    for m in re.finditer(r"(?m)^\s*(?:-\s+)?(?:local\s*:\s*)?['\"]?(/?[\w./-]+\.ya?ml)['\"]?\s*$", masked):
        p = m.group(1)
        cand = (root / p.lstrip("/")) if p.startswith("/") else (base.parent / p)
        if cand.is_file():
            out.append(cand.resolve())
    return out


class Registry:
    """All jobs/templates/anchors across the repo's CI files."""

    def __init__(self, root: Path, files: list[Path]):
        self.root = root
        self.jobs: dict[str, JobDef] = {}
        self.by_file: dict[Path, list[JobDef]] = {}
        self.anchors: dict[str, dict[str, str]] = {}
        self.defaults: dict[str, str] = {}
        self.default_src = ""
        self.workflow = ""
        self.global_vars = ""
        seen: set[Path] = set()
        queue = [p.resolve() for p in files]
        while queue:
            p = queue.pop(0)
            if p in seen or any(x in _SKIP_DIRS for x in p.parts):
                continue
            seen.add(p)
            masked = mask_comments(read_text_safe(p), "hash")
            jobs = _split(masked, p)
            self.by_file[p] = jobs
            for j in jobs:
                if j.name == "default":
                    for k, v in j.keys.items():
                        self.defaults.setdefault(k, v)
                    self.default_src = f"{self._rel(p)}:{j.start}"
                elif j.name == "workflow":
                    self.workflow += j.text + "\n"
                elif j.name == "variables":
                    self.global_vars += j.text + "\n"
                elif j.name not in _GLOBAL_KEYS:
                    self.jobs.setdefault(j.name, j)
            self.anchors.update(_anchors(masked))
            queue += _local_includes(masked, p, root)

    def _rel(self, p: Path) -> str:
        try:
            return str(p.relative_to(self.root.resolve()))
        except ValueError:
            return str(p)

    def effective(self, job: JobDef, depth: int = 0) -> Effective:
        merged: dict[str, str] = dict(job.keys)
        eff = Effective("")
        if depth > 10:
            eff.text = job.text
            return eff

        # YAML merge keys: <<: *a  /  <<: [*a, *b]
        for m in re.finditer(r"<<\s*:\s*(\[[^\]]*\]|\*[\w.-]+)", job.text):
            for name in re.findall(r"\*([\w.-]+)", m.group(1)):
                body = self.anchors.get(name)
                if body is None:
                    eff.unresolved.append(f"*{name}")
                    continue
                for k, v in body.items():
                    if k not in merged and k != "<<":
                        merged[k] = v
                        eff.inherited_keys[k] = f"anchor *{name}"
                eff.sources.append(f"anchor *{name}")
        merged.pop("<<", None)

        # extends: later entries override earlier ones; the job overrides all.
        for t in reversed(_list_value(merged.get("extends", ""), "extends")):
            tj = self.jobs.get(t)
            if tj is None:
                eff.unresolved.append(t)
                continue
            sub = self.effective(tj, depth + 1)
            eff.unresolved += sub.unresolved
            src = f"extends {t} ({self._rel(tj.file)}:{tj.start})"
            eff.sources.append(src)
            for k, v in child_keys(sub.text.split("\n")[1:]).items():
                if k not in merged and k != "extends":
                    merged[k] = v
                    eff.inherited_keys[k] = sub.inherited_keys.get(k, src)

        # !reference [.tmpl, key, (subkey)]
        def ref(m: re.Match) -> str:
            parts = [x.strip().strip("'\"") for x in m.group(1).split(",")]
            tj = self.jobs.get(parts[0])
            if tj is None:
                eff.unresolved.append(parts[0])
                return m.group(0)
            body = self.effective(tj, depth + 1)
            keys = child_keys(body.text.split("\n")[1:])
            val = keys.get(parts[1], "") if len(parts) > 1 else ""
            eff.sources.append(f"!reference {parts[0]}.{parts[1] if len(parts) > 1 else ''}")
            return "\n".join(val.split("\n")[1:]) or m.group(0)

        for k in list(merged):
            if "!reference" in merged[k]:
                merged[k] = re.sub(r"!reference\s*\[([^\]]+)\]", ref, merged[k])

        # default: unless `inherit: default: false`
        inherit = merged.get("inherit", "")
        if not re.search(r"default\s*:\s*false", inherit):
            for k, v in self.defaults.items():
                if k not in merged:
                    merged[k] = v
                    eff.inherited_keys[k] = f"default ({self.default_src})"

        eff.text = f"{job.name}:\n" + "\n".join(merged.values())
        return eff

