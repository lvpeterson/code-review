"""Razor and ASPX template scanning for the legacy .NET analyzer.

`scan` lists the places a template writes a value without HTML-encoding it:
Razor `@Html.Raw(..)`, `@(new HtmlString(..))` and `@MvcHtmlString.Create(..)`
(also inside `@{ }` code blocks), and the ASPX/ASCX/Master `<%= %>` and `<%# %>`
blocks. Plain Razor `@expr` and ASPX `<%: %>` are encoded by the framework; the
ASPX ones are returned with `encoded=True` for completeness, Razor ones are not
returned. An output whose whole expression is an HtmlEncode-style call also
comes back with `encoded=True`. `views_for` / `view_for` map an MVC action to the
Razor view it renders by convention.

Expression extraction is a small scanner, not a parser: it balances parentheses
while skipping string literals (C# regular and verbatim, VB doubled quotes) and
C# char literals, so `Html.Raw(fn("a)b"))` yields `fn("a)b")`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from checks.dnl.files import read_source, resolve_ci
from checks.dnl.ir import call_name, literal_str, receiver_text, walk

RAZOR_EXT = (".cshtml", ".vbhtml")
ASPX_EXT = (".aspx", ".ascx", ".master")
TEMPLATE_EXT = RAZOR_EXT + ASPX_EXT


@dataclass
class Output:
    file: str
    line: int       # 1-based
    expr: str
    encoded: bool
    kind: str       # razor_raw | razor_helper | aspx_raw | aspx_encoded | aspx_bind


# `X.HtmlEncode(..)` style wrappers that make the whole expression HTML-safe.
_ENCODER = re.compile(
    r"(?is)^(?:(?:System\.Web\.|System\.Net\.)?(?:HttpUtility|Server|WebUtility|AntiXssEncoder|Encoder)\.(?:HtmlEncode|HtmlAttributeEncode)"
    r"|(?:System\.Web\.Mvc\.)?Html\.Encode|(?:Microsoft\.Security\.Application\.)?Sanitizer\.GetSafeHtmlFragment"
    r"|Json\.Encode)\s*\(")
_CHAR_LIT = re.compile(r"'(?:\\.|[^'\\\n])'")
_NON_LITERAL = re.compile(r"^[\s+&()\d.]*$")
_STR_LIT = re.compile(r'@?"(?:[^"\\]|\\.|"")*"')
# Framework helpers that emit trusted markup / URLs when every argument is a constant.
_BENIGN_CALL = re.compile(
    r"(?is)^(?:ResolveUrl|ResolveClientUrl|Url\s*\.\s*(?:Action|Content|RouteUrl)"
    r"|Html\s*\.\s*(?:Partial|Action|RenderPartial|RenderAction|AntiForgeryToken|ActionLink|BeginForm)"
    r"|Scripts\s*\.\s*Render|Styles\s*\.\s*Render)\s*\(")
_TAINT_NAMES = re.compile(r"(?i)\b(?:Model|ViewBag|ViewData|Request|Eval|Bind)\b")
_CONST_TOKEN = re.compile(r"(?i)\b(?:true|false|null|nothing)\b|\d+(?:\.\d+)?")


def _skip_string(text: str, i: int, vb: bool) -> int:
    """Index just past the string literal opening at text[i] (a double quote); end of text when unterminated."""
    verbatim = i > 0 and text[i - 1] == "@" and not vb
    j = i + 1
    while j < len(text):
        c = text[j]
        if c == '"':
            if j + 1 < len(text) and text[j + 1] == '"' and (vb or verbatim):
                j += 2
                continue
            return j + 1
        if c == "\\" and not vb and not verbatim:
            j += 2
            continue
        j += 1
    return len(text)


def _balanced(text: str, open_idx: int, vb: bool) -> tuple[str, int] | None:
    """(inner text, index of the closing paren) for the `(` at open_idx, or None when unbalanced."""
    depth, i = 1, open_idx + 1
    while i < len(text):
        c = text[i]
        if c == '"':
            i = _skip_string(text, i, vb)
            continue
        if c == "'" and not vb:
            mo = _CHAR_LIT.match(text, i)
            if mo:
                i = mo.end()
                continue
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i].strip(), i
        i += 1
    return None


def _expr_at(text: str, open_idx: int, vb: bool) -> str:
    """The balanced expression after `(` at open_idx; when the scanner cannot balance it, the rest of
    the line, so the output is still reported (as unknown provenance) instead of dropped."""
    got = _balanced(text, open_idx, vb)
    if got:
        return got[0]
    eol = text.find("\n", open_idx)
    return text[open_idx + 1:eol if eol >= 0 else len(text)].strip()


def is_encoded_wrapper(expr: str) -> bool:
    """True when the whole expression is one HtmlEncode-style call."""
    e = expr.strip()
    mo = _ENCODER.match(e)
    if not mo:
        return False
    got = _balanced(e, mo.end() - 1, vb=False)
    return got is not None and got[1] == len(e) - 1


def is_benign_helper(expr: str) -> bool:
    """True when the whole expression is one allowlisted helper call (`Url.Content`, `Html.Partial`,
    `Scripts.Render`, ...) with only constant arguments. Anything naming Model / ViewBag / ViewData /
    Request / Eval, or passing a non-constant argument, is never benign."""
    e = expr.strip()
    mo = _BENIGN_CALL.match(e)
    if not mo or _TAINT_NAMES.search(e):
        return False
    got = _balanced(e, mo.end() - 1, vb=False)
    if got is None or got[1] != len(e) - 1:
        return False
    rest = _CONST_TOKEN.sub("", _STR_LIT.sub("", got[0]))
    return not rest.strip(" \t\r\n,")


def is_literal(expr: str) -> bool:
    """True for a constant-only expression: string literals joined with `+` / `&`, numbers."""
    e = expr.strip()
    return bool(e) and _NON_LITERAL.match(_STR_LIT.sub("", e)) is not None


# -- Razor ----------------------------------------------------------------

_RAZOR_COMMENT = re.compile(r"@\*.*?\*@", re.DOTALL)
# `Html.Raw(` anywhere (it also appears bare inside code blocks); the helpers need their `@` transition.
_RAZOR_RAW = re.compile(r"(?<![\w.])Html\s*\.\s*Raw\s*\(", re.IGNORECASE)
_RAZOR_HELPER = re.compile(
    r"(?<![\w@])@(?:\(\s*new\s+(?:System\.Web\.)?HtmlString\s*\(|(?:System\.Web\.Mvc\.)?MvcHtmlString\s*\.\s*Create\s*\()",
    re.IGNORECASE)


def _blank(mo: re.Match) -> str:
    return re.sub(r"[^\n]", " ", mo.group(0))


def _scan_razor(text: str, rel: str, vb: bool) -> list[Output]:
    text = _RAZOR_COMMENT.sub(_blank, text)
    found: list[tuple[int, str, str]] = []
    for mo in _RAZOR_RAW.finditer(text):
        if text[max(0, mo.start() - 2):mo.start()] == "@@":
            continue  # `@@Html.Raw(x)` is a literal "@" followed by text
        found.append((mo.start(), "razor_raw", _expr_at(text, mo.end() - 1, vb)))
    for mo in _RAZOR_HELPER.finditer(text):
        found.append((mo.start(), "razor_helper", _expr_at(text, mo.end() - 1, vb)))
    return [Output(rel, text.count("\n", 0, pos) + 1, expr, is_encoded_wrapper(expr), kind)
            for pos, kind, expr in sorted(found)]


# -- ASPX -----------------------------------------------------------------

def _aspx_end(text: str, i: int) -> int:
    """Index of the `%>` closing the block whose body starts at i, ignoring `%>` inside strings; -1 if none."""
    while i < len(text) - 1:
        if text[i] == '"':
            i = _skip_string(text, i, vb=True)
            continue
        if text[i] == "%" and text[i + 1] == ">":
            return i
        i += 1
    return -1


_RESPONSE_WRITE = re.compile(r"(?<![\w.])(?:HttpContext\.Current\.)?Response\s*\.\s*Write\s*\(", re.IGNORECASE)


def _scan_aspx(text: str, rel: str) -> list[Output]:
    out: list[Output] = []
    i = 0
    while True:
        i = text.find("<%", i)
        if i < 0:
            break
        if text.startswith("<%--", i):
            end = text.find("--%>", i + 4)
            i = len(text) if end < 0 else end + 4
            continue
        body = i + 2
        kind, encoded = None, False
        if text.startswith("=", body):
            kind, body = "aspx_raw", body + 1
        elif text.startswith(":", body):
            kind, encoded, body = "aspx_encoded", True, body + 1
        elif text.startswith("#:", body):
            kind, encoded, body = "aspx_bind", True, body + 2
        elif text.startswith("#", body):
            kind, body = "aspx_bind", body + 1
        end = _aspx_end(text, body)
        if end < 0:
            break
        if kind is None and not text.startswith(("@", "$"), body):
            # `<% ... %>` code block: only Response.Write(..) calls write output.
            for mo in _RESPONSE_WRITE.finditer(text, body, end):
                expr = _expr_at(text[:end], mo.end() - 1, vb=False)
                out.append(Output(rel, text.count("\n", 0, mo.start()) + 1, expr, is_encoded_wrapper(expr), "aspx_raw"))
        if kind:
            expr = text[body:end].strip()
            out.append(Output(rel, text.count("\n", 0, i) + 1, expr, encoded or is_encoded_wrapper(expr), kind))
        i = end + 2
    return out


def scan(path: Path, rel: str) -> list[Output]:
    """Unencoded (and, for ASPX, encoded) outputs of one template file, in source order."""
    suffix = path.suffix.lower()
    if suffix not in TEMPLATE_EXT:
        return []
    text = read_source(path)
    if suffix in RAZOR_EXT:
        return _scan_razor(text, rel, vb=suffix == ".vbhtml")
    return _scan_aspx(text, rel)


# -- view resolution ------------------------------------------------------

_AREA_NS = re.compile(r"(?:^|\.)Areas\.([^.]+)(?:\.|$)", re.IGNORECASE)


def _own_call(fn: dict) -> bool:
    """`View(..)` or `this.View(..)` / `Me.View(..)`; a call on another object is not the action's own."""
    if fn.get("k") == "name":
        return True
    obj = fn.get("obj")
    return fn.get("k") == "member" and (obj is None or obj.get("k") == "this"
                                        or receiver_text(obj).lower() in ("this", "me"))


def _find_view(base: Path, rel: str) -> Path | None:
    exts = ("",) if rel.lower().endswith(RAZOR_EXT) else RAZOR_EXT
    for ext in exts:
        hit = resolve_ci(base, rel + ext)
        if hit is not None and hit.is_file():
            return hit
    return None


def views_for(model, ref) -> list[Path]:
    """Razor views the MVC action renders: one per `View(..)` / `PartialView(..)` call in its body,
    by convention `Views/<Controller>/<Name or Action>` then `Views/Shared/<Name>`."""
    if ref.method is None or ref.type is None or ref.route.meta.get("kind") != "mvc":
        return []
    base = ref.project.dir if ref.project is not None else model.root
    controller = ref.type.name.split(".")[-1]
    if controller.lower().endswith("controller"):
        controller = controller[: -len("controller")]
    area = _AREA_NS.search(ref.type.namespace)
    roots = ([f"Areas/{area.group(1)}/Views"] if area else []) + ["Views"]
    found: list[Path] = []
    for n in walk(ref.method.body):
        if n.get("k") != "call" or (call_name(n) or "").lower() not in ("view", "partialview"):
            continue
        if not _own_call(n.get("fn") or {}):
            continue
        args = n.get("args") or []
        name = (literal_str(args[0]) if args else None) or ref.method.name
        if name.startswith("~/"):
            cands = [name[2:]]
        else:
            cands = [f"{r}/{controller}/{name}" for r in roots] + [f"{r}/Shared/{name}" for r in roots]
        for c in cands:
            hit = _find_view(base, c)
            if hit is not None:
                if hit not in found:
                    found.append(hit)
                break
    return found


def view_for(model, ref) -> Path | None:
    """The first view `views_for` finds, or None."""
    got = views_for(model, ref)
    return got[0] if got else None
