"""Markup integrity rules: DNL-INT-003 (external script/stylesheet without SRI) and
DNL-INT-004 (page/control/master directives that weaken ViewState protection).

Both are text scans over .cshtml/.vbhtml/.master/.aspx/.ascx/.html/.htm files, so they need no
IR. Comments are blanked first (Razor `@* *@`, ASPX `<%-- --%>`, HTML `<!-- -->`, except IE
conditional comments, which still load their content). A finding in a routed WebForms page
(.aspx) carries that page's route; layouts, masters, controls and static files are route-less
and the analyzers place them.
"""
from __future__ import annotations

import re
from pathlib import Path

from checks.dnl.files import iter_dnl_files, read_source
from checks.dnl.findings import dnl_finding
from checks.dnl.routes import _DIRECTIVE_ATTR
from checks.dnl.templates import _RAZOR_COMMENT, _blank
from core.models import Finding

EXTS = (".cshtml", ".vbhtml", ".master", ".aspx", ".ascx", ".html", ".htm")

_ASPX_COMMENT = re.compile(r"<%--.*?--%>", re.DOTALL)
# `<!--[if ...]>` conditional comments are kept: their content is real markup for some browsers.
_HTML_COMMENT = re.compile(r"<!--(?!\[if).*?-->", re.DOTALL)
# An opening tag; `<% .. %>` blocks and quoted values may contain `>`.
_TAG = re.compile(r"<(script|link)\b((?:<%.*?%>|\"[^\"]*\"|'[^']*'|[^>\"'])*)>", re.IGNORECASE | re.DOTALL)
_ATTR = re.compile(r"""([^\s=/>"']+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?""")
_DIRECTIVE = re.compile(r"<%@\s*(page|control|master)\b(.*?)%>", re.IGNORECASE | re.DOTALL)
_EXTERNAL = re.compile(r"(?i)^(?:https?:)?//")


def _clean(text: str) -> str:
    for rx in (_RAZOR_COMMENT, _ASPX_COMMENT, _HTML_COMMENT):
        text = rx.sub(_blank, text)
    return text


def _attrs(body: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for mo in _ATTR.finditer(body):
        v = mo.group(2) if mo.group(2) is not None else mo.group(3) if mo.group(3) is not None else mo.group(4)
        out.setdefault(mo.group(1).lower(), (v or "").strip())
    return out


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _sri(text: str, rel: str) -> list[tuple[int, str]]:
    """(line, description) per line holding at least one external tag without integrity."""
    by_line: dict[int, list[str]] = {}
    for mo in _TAG.finditer(text):
        tag, a = mo.group(1).lower(), _attrs(mo.group(2))
        if tag == "script":
            url = a.get("src", "")
        elif "stylesheet" in a.get("rel", "").lower().split():
            url = a.get("href", "")
        else:
            continue
        # Razor `@Url.Content("~/..")`, `<%: ResolveUrl("~/..") %>`, `~/x` and `/x` never match.
        if not _EXTERNAL.match(url) or a.get("integrity"):
            continue
        by_line.setdefault(_line(text, mo.start()), []).append(url)
    return [(ln, f"{'; '.join(urls)} loaded without an integrity (SRI) attribute")
            for ln, urls in sorted(by_line.items())]


def _viewstate(text: str) -> list[tuple[int, str, str]]:
    """(line, severity, description) per weakened-ViewState directive attribute."""
    out = []
    for d in _DIRECTIVE.finditer(text):
        base = d.start(2)
        for mo in _DIRECTIVE_ATTR.finditer(d.group(2)):
            key, val = mo.group(1).lower(), (mo.group(2) or mo.group(3) or "").strip().lower()
            line = _line(text, base + mo.start())
            if key == "enableviewstatemac" and val == "false":
                out.append((line, "high", "EnableViewStateMac=\"false\" turns off the ViewState MAC, so a "
                                          "tampered ViewState is accepted (and can lead to deserialization attacks)"))
            elif key == "viewstateencryptionmode" and val == "never":
                out.append((line, "low", "ViewStateEncryptionMode=\"Never\" leaves ViewState readable by the client"))
    return out


def check(model, refs=()) -> list[Finding]:
    pages = {r.route.file: r.route for r in refs or [] if r.route.meta.get("kind") == "webforms"}
    out: list[Finding] = []
    for f in iter_dnl_files(model.root, EXTS):
        rel = model.rel(f)
        route = pages.get(rel) if f.suffix.lower() == ".aspx" else None
        api = bool(route.meta.get("api_surface")) if route else False
        text = _clean(read_source(f))
        for line, desc in _sri(text, rel):
            out.append(dnl_finding("DNL-INT-003", "medium", "External resource without Subresource Integrity",
                                   f"{desc} ({rel}:{line}); a compromised host could serve altered code.",
                                   rel, line, route=route, api_surface=api))
        if f.suffix.lower() in (".aspx", ".ascx", ".master"):
            for line, sev, desc in _viewstate(text):
                out.append(dnl_finding("DNL-INT-004", sev, "ViewState protection weakened",
                                       f"{desc} ({rel}:{line}).", rel, line, route=route, api_surface=api))
    return out
