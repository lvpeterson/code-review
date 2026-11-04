"""Dependency-free, line-accurate HCL (Terraform) block reader.

Not a full HCL parser -- it finds `type "label" "label" { ... }` blocks and
`name = value` attributes, with real nesting and line numbers, which is all
the Terraform rules need. Strings (including ${...} interpolation), heredocs
and comments are blanked out before brace matching so a "{" inside a value
can't throw the structure off.

Also has a best-effort HCL-expression -> Python converter (`expr_to_py`) so
an inline `policy = jsonencode({...})` can be fed to the same IAM policy
checks as a .json file. Anything it can't evaluate (function calls,
references, conditionals) comes back as an opaque "${...}" string.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.rulescan import mask_comments

_BLOCK_HEADER = re.compile(r'^\s*([A-Za-z_][\w-]*)((?:\s+(?:"[^"\n]*"|[A-Za-z_][\w-]*))*)\s*$')
_ATTR = re.compile(r"^(\s*)([A-Za-z_][\w-]*)\s*=(?!=)\s*")
_HEREDOC = re.compile(r"<<-?\s*([A-Za-z_]\w*)")


@dataclass
class Attr:
    name: str
    value: str  # source text of the value (comments masked); var/local refs substituted by tf_resolve
    line: int
    raw: Optional[str] = None   # original text when tf_resolve substituted references
    via: Optional[str] = None   # where the substituted value came from

    def literal(self) -> Optional[str]:
        """The string value if this is a plain "..." literal with no interpolation."""
        v = self.value.strip()
        if len(v) >= 2 and v[0] == '"' and v[-1] == '"' and "${" not in v and v.count('"') == 2:
            return v[1:-1]
        return None

    def as_bool(self) -> Optional[bool]:
        v = self.value.strip().strip('"').lower()
        if v == "true":
            return True
        if v == "false":
            return False
        return None

    def as_number(self) -> Optional[float]:
        try:
            return float(self.value.strip().strip('"'))
        except ValueError:
            return None


@dataclass
class Block:
    kind: str
    labels: list[str]
    file: Path
    line: int
    end_line: int
    attrs: dict[str, Attr] = field(default_factory=dict)
    children: list["Block"] = field(default_factory=list)
    parent: Optional["Block"] = None
    text: str = ""  # full masked source of the block, header included

    @property
    def address(self) -> str:
        return ".".join([self.kind, *self.labels]) if self.kind not in ("resource",) else ".".join(self.labels)

    def attr(self, name: str) -> Optional[Attr]:
        return self.attrs.get(name)

    def blocks(self, kind: str) -> list["Block"]:
        return [c for c in self.children if c.kind == kind]

    def block(self, kind: str) -> Optional["Block"]:
        found = self.blocks(kind)
        return found[0] if found else None

    def walk(self):
        yield self
        for c in self.children:
            yield from c.walk()


def _structure_mask(text: str) -> tuple[str, list[tuple[int, int]]]:
    """Blank string contents (keeping the quotes) and heredoc bodies. Returns
    the masked text plus the (start, end) spans of every heredoc body."""
    out = list(text)
    heredocs: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "<" and text.startswith("<<", i):
            m = _HEREDOC.match(text, i)
            if m:
                tag = m.group(1)
                body_start = text.find("\n", m.end())
                if body_start != -1:
                    end_rx = re.compile(r"^\s*" + re.escape(tag) + r"\s*$", re.MULTILINE)
                    em = end_rx.search(text, body_start + 1)
                    body_end = em.start() if em else n
                    heredocs.append((body_start + 1, body_end))
                    for j in range(body_start + 1, body_end):
                        if out[j] != "\n":
                            out[j] = " "
                    i = em.end() if em else n
                    continue
        if ch == '"':
            j = i + 1
            interp = 0
            while j < n:
                c = text[j]
                if c == "\\":
                    j += 2
                    continue
                if c == "$" and text.startswith("${", j):
                    interp += 1
                    j += 2
                    continue
                if c == "}" and interp:
                    interp -= 1
                elif c == '"' and not interp:
                    break
                elif c == "\n" and not interp:
                    break
                j += 1
            for k in range(i + 1, min(j, n)):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out), heredocs


def parse_hcl(text: str, path: Path) -> list[Block]:
    """Return the top-level blocks of one .tf/.hcl file."""
    commentless = mask_comments(text, "hcl")
    struct, _ = _structure_mask(commentless)

    # Match every brace/bracket.
    match: dict[int, int] = {}
    stack: list[int] = []
    for i, ch in enumerate(struct):
        if ch in "{[(":
            stack.append(i)
        elif ch in "}])" and stack:
            match[stack.pop()] = i

    line_starts = [0] + [m.end() for m in re.finditer("\n", struct)]

    def line_no(idx: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    def parse_region(start: int, end: int, parent: Optional[Block]) -> list[Block]:
        blocks: list[Block] = []
        i = start
        while i < end:
            nl = struct.find("\n", i, end)
            line_end = end if nl == -1 else nl
            line = struct[i:line_end]
            brace = line.rfind("{")
            am = _ATTR.match(line)
            if am:
                # name = value -- value may span lines via an open bracket/heredoc.
                value_start = i + am.end()
                value_end = line_end
                k = value_start
                while k < line_end:
                    if struct[k] in "{[(" and k in match:
                        k = match[k] + 1
                        value_end = max(value_end, struct.find("\n", k) if struct.find("\n", k) != -1 else len(struct))
                        continue
                    k += 1
                hd = _HEREDOC.match(commentless, value_start)
                if hd:
                    tag = hd.group(1)
                    em = re.compile(r"^\s*" + re.escape(tag) + r"\s*$", re.MULTILINE).search(commentless, value_start)
                    if em:
                        value_end = em.end()
                value_end = min(value_end, end)
                if parent is not None:
                    name = am.group(2)
                    parent.attrs.setdefault(name, Attr(name, commentless[value_start:value_end].strip(), line_no(i)))
                i = value_end + 1
                continue
            if brace != -1 and (i + brace) in match:
                header = line[:brace]
                hm = _BLOCK_HEADER.match(header) if header.strip() else None
                open_idx = i + brace
                close_idx = match[open_idx]
                if hm:
                    raw_labels = re.findall(r'"([^"\n]*)"|([A-Za-z_][\w-]*)', hm.group(2))
                    # Header labels are blanked in `struct`; read them from the comment-masked text.
                    real_header = commentless[i:i + brace]
                    real_labels = re.findall(r'"([^"\n]*)"|([A-Za-z_][\w-]*)', real_header)[1:]
                    labels = [a or b for a, b in real_labels] if real_labels else [a or b for a, b in raw_labels]
                    blk = Block(
                        kind=hm.group(1),
                        labels=labels,
                        file=path,
                        line=line_no(i),
                        end_line=line_no(close_idx),
                        parent=parent,
                        text=commentless[i:close_idx + 1],
                    )
                    blk.children = parse_region(open_idx + 1, close_idx, blk)
                    blocks.append(blk)
                nxt = struct.find("\n", close_idx)
                i = end if nxt == -1 else nxt + 1
                continue
            i = line_end + 1
        return blocks

    return parse_region(0, len(struct), None)


# ── HCL expression -> Python (for jsonencode({...}) policies) ──────────────

_TOKEN = re.compile(
    r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<num>-?\d+(?:\.\d+)?)|(?P<punct>[{}\[\]=:,])'
    r"|(?P<ident>[A-Za-z_][\w.\-\[\]*\"]*(?:\([^()]*\))?)|(?P<nl>\n))",
)


class _Opaque(str):
    pass


def expr_to_py(src: str) -> Any:
    """Best-effort conversion of an HCL object/list/string literal to Python.
    Returns None if the expression isn't an object/list literal at all."""
    src = src.strip()
    m = re.match(r"jsonencode\s*\(", src)
    if m:
        src = src[m.end():].rstrip()
        if src.endswith(")"):
            src = src[:-1]
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(src):
        tm = _TOKEN.match(src, pos)
        if not tm or tm.end() == pos:
            # Unknown char (operators, ?:) -> treat as opaque text.
            tokens.append(("ident", src[pos]))
            pos += 1
            continue
        pos = tm.end()
        kind = tm.lastgroup
        if kind == "nl":
            tokens.append(("punct", ","))
        elif kind:
            tokens.append((kind, tm.group(kind)))
    idx = 0

    def peek():
        return tokens[idx] if idx < len(tokens) else ("eof", "")

    def skip_commas():
        nonlocal idx
        while peek() == ("punct", ","):
            idx += 1

    def value():
        nonlocal idx
        skip_commas()
        kind, text = peek()
        if (kind, text) == ("punct", "{"):
            idx += 1
            obj = {}
            while True:
                skip_commas()
                k, t = peek()
                if (k, t) == ("punct", "}") or k == "eof":
                    idx += 1
                    return obj
                idx += 1
                key = json.loads(t) if k == "str" else t
                skip = peek()
                if skip in (("punct", "="), ("punct", ":")):
                    idx += 1
                obj[str(key)] = value()
        if (kind, text) == ("punct", "["):
            idx += 1
            arr = []
            while True:
                skip_commas()
                k, t = peek()
                if (k, t) == ("punct", "]") or k == "eof":
                    idx += 1
                    return arr
                arr.append(value())
        idx += 1
        if kind == "str":
            try:
                return json.loads(text)
            except ValueError:
                return text.strip('"')
        if kind == "num":
            return float(text) if "." in text else int(text)
        if text in ("true", "false"):
            return text == "true"
        return _Opaque("${" + text + "}")

    if not tokens:
        return None
    result = value()
    return result if isinstance(result, (dict, list)) else None


def heredoc_body(value: str) -> Optional[str]:
    m = _HEREDOC.match(value.strip())
    if not m:
        return None
    body = value.strip()[m.end():]
    body = re.sub(r"\n\s*" + re.escape(m.group(1)) + r"\s*$", "", body)
    return body


def load_policy_value(value: str) -> Any:
    """Turn a Terraform `policy = ...` value into a Python dict when possible:
    a heredoc of JSON, a jsonencode({...}) literal, or a quoted JSON string."""
    body = heredoc_body(value)
    if body is not None:
        return _loads_templated_json(body)
    v = value.strip()
    if v.startswith("jsonencode"):
        return expr_to_py(v)
    return None


def _loads_templated_json(body: str) -> Any:
    # ${...} inside a JSON string is fine; a bare ${...} (e.g. a list) is not.
    cleaned = re.sub(r'(?<!")\$\{[^}]*\}(?!")', '"${ref}"', body)
    try:
        return json.loads(cleaned)
    except ValueError:
        return None
