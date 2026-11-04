"""Small regex rule engine shared by the file-oriented (no-route) analyzers:
Terraform, GitLab CI, shell, IAM policy JSON, Java/PHP crypto, AWS Lambda.

Each LineRule is matched line-by-line against comment-masked text (comments
blanked out, string literals left visible -- most of these rules need to see
inside a string: a hardcoded password, a "DES/ECB/..." transformation, an
"image: foo:latest" value). A rule with `multiline=True` runs against the
whole masked file instead and reports the line its match starts on.

Like every other check in this tool, a hit is a pointer for a human, not a
verdict.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from core.models import Finding

# Comment styles understood by mask_comments():
#   "hash"  -- '#' to end of line (shell, YAML, Python)
#   "c"     -- '//' to end of line and /* ... */ (Java)
#   "hcl"   -- both of the above (Terraform/HCL, PHP)
#   "none"  -- nothing masked (JSON)
COMMENT_STYLES = ("hash", "c", "hcl", "none")


@dataclass
class LineRule:
    id: str
    severity: str  # high | medium | low | info
    title: str
    pattern: str
    note: str
    confidence: Optional[str] = None  # "REVIEW" when a human has to decide
    # Drop the hit when this matches the same line (e.g. a placeholder value).
    exclude: Optional[str] = None
    # Only apply the rule when this matches somewhere in the (masked) file.
    file_require: Optional[str] = None
    # Drop every hit when this matches somewhere in the (masked) file -- for
    # "X without Y" rules where Y anywhere in the file is the mitigation.
    file_suppress: Optional[str] = None
    multiline: bool = False
    # Last-chance filter: gets the match object, returns False to drop it.
    keep: Optional[Callable[[re.Match], bool]] = None
    _compiled: dict = field(default_factory=dict, repr=False)

    def rx(self, name: str = "pattern") -> Optional[re.Pattern]:
        source = getattr(self, name)
        if source is None:
            return None
        if name not in self._compiled:
            flags = re.MULTILINE | (re.DOTALL if self.multiline and name == "pattern" else 0)
            self._compiled[name] = re.compile(source, flags)
        return self._compiled[name]


def mask_comments(text: str, style: str) -> str:
    """Blank out comments (replaced by spaces, newlines kept) so line/column
    positions stay identical to the original. String literals are tracked so a
    '#' or '//' inside a quoted value isn't mistaken for a comment; strings
    never span lines here (true for everything these rules target), which also
    stops a stray apostrophe in YAML/shell prose from swallowing the file.
    """
    if style == "none":
        return text
    hash_comments = style in ("hash", "hcl")
    c_comments = style in ("c", "hcl")
    out = list(text)
    i, n = 0, len(text)
    quote: Optional[str] = None
    while i < n:
        ch = text[i]
        if ch == "\n":
            quote = None
            i += 1
            continue
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ('"', "'"):
            # In shell/YAML a lone apostrophe inside a word (don't) is prose,
            # not a string opener.
            prev = text[i - 1] if i else " "
            if ch == "'" and (prev.isalnum()) and style == "hash":
                i += 1
                continue
            quote = ch
            i += 1
            continue
        if c_comments and text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end == -1 else end + 2
            for j in range(i, end):
                if out[j] != "\n":
                    out[j] = " "
            i = end
            continue
        is_line_comment = False
        if c_comments and text.startswith("//", i) and (i == 0 or text[i - 1] != ":"):
            # "https://..." outside quotes (YAML/HCL bare URLs) isn't a comment.
            is_line_comment = True
        elif hash_comments and ch == "#":
            prev = text[i - 1] if i else "\n"
            # '#' only starts a comment at the start of a word: $# / ${#x} /
            # foo#bar in shell, or a URL fragment, are not comments.
            if prev in " \t\n;|&(" or style == "hcl":
                is_line_comment = True
        if is_line_comment:
            end = text.find("\n", i)
            end = n if end == -1 else end
            for j in range(i, end):
                out[j] = " "
            i = end
            continue
        i += 1
    return "".join(out)


def line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def scan_text(
    text: str,
    rules: Iterable[LineRule],
    relative_file: str,
    comment_style: str,
) -> list[Finding]:
    masked = mask_comments(text, comment_style)
    lines = masked.split("\n")
    findings: list[Finding] = []
    seen: set[tuple[str, int]] = set()

    for rule in rules:
        if rule.file_require and not rule.rx("file_require").search(masked):
            continue
        if rule.file_suppress and rule.rx("file_suppress").search(masked):
            continue
        exclude = rule.rx("exclude")
        if rule.multiline:
            for m in rule.rx().finditer(masked):
                line_no = line_of(masked, m.start())
                if exclude and exclude.search(lines[line_no - 1]):
                    continue
                if rule.keep and not rule.keep(m):
                    continue
                _add(findings, seen, rule, relative_file, line_no)
            continue
        pattern = rule.rx()
        for idx, line in enumerate(lines, start=1):
            m = pattern.search(line)
            if not m:
                continue
            if exclude and exclude.search(line):
                continue
            if rule.keep and not rule.keep(m):
                continue
            _add(findings, seen, rule, relative_file, idx)
    return findings


def scan_file(path: Path, root: Path, rules: Iterable[LineRule], comment_style: str) -> list[Finding]:
    from core.fsutil import read_text_safe

    return scan_text(read_text_safe(path), rules, rel(path, root), comment_style)


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def make_finding(
    check_id: str,
    severity: str,
    title: str,
    description: str,
    file: str,
    line: int,
    confidence: Optional[str] = None,
) -> Finding:
    from core.owasp_isr import isr_for

    return Finding(
        check_id=check_id,
        severity=severity,
        title=title,
        description=description,
        file=file,
        line=line,
        route=None,
        confidence=confidence,
        category=isr_for(check_id),
    )


def _add(findings, seen, rule: LineRule, relative_file: str, line_no: int) -> None:
    key = (rule.id, line_no)
    if key in seen:
        return
    seen.add(key)
    findings.append(make_finding(rule.id, rule.severity, rule.title, rule.note, relative_file, line_no, rule.confidence))


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Drop exact (check_id, file, line) duplicates, keeping the first."""
    seen: set[tuple[str, str, int]] = set()
    out = []
    for f in findings:
        key = (f.check_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out
