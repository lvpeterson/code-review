"""Generates a single self-contained HTML report.

Each route renders as a collapsible card; expanding it shows the full
handler source (file, line numbers, and a jump-to-IDE link) plus whatever
baseline findings were raised against it. No external assets/CDNs -- this
needs to open straight from disk, including on an air-gapped machine.
"""
from __future__ import annotations

import hashlib
import html
import itertools
import json
import re
from datetime import datetime
from pathlib import Path

from pygments import highlight as pygments_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.util import ClassNotFound

from core.models import Finding, Route, ScanResult
from core.paths import extract_path_param_names
from core.sarif_report import build_sarif

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}
_ROUTE_SORT_RANK = {**_SEVERITY_RANK, "clean": 4}  # "clean" only applies to routes, never to a Finding
_METHOD_ORDER = {"GET": 0, "POST": 1, "PUT": 2, "PATCH": 3, "DELETE": 4, "OPTIONS": 5, "HEAD": 6}

# night-owl's own background (#011627) already sits in the same navy family
# as this report's palette, so its token colors blend in once we force the
# background transparent below and let our own --surface show through.
_PYGMENTS_STYLE = "night-owl"
_LEXER_NAME_BY_LANGUAGE = {"python": "python", "java": "java", "javascript": "javascript"}


def _get_lexer(language: str, filename: str):
    try:
        return get_lexer_for_filename(filename, stripnl=False)
    except ClassNotFound:
        pass
    name = _LEXER_NAME_BY_LANGUAGE.get(language)
    if name:
        try:
            return get_lexer_by_name(name, stripnl=False)
        except ClassNotFound:
            pass
    return get_lexer_by_name("text", stripnl=False)


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _worst_severity(findings: list[Finding]) -> str:
    if not findings:
        return "clean"
    return min(findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 9)).severity


def _is_auth_finding(finding: Finding) -> bool:
    return finding.check_id.startswith("AUTH-")


def _non_auth_findings_for_route(route: Route, findings: list[Finding]) -> list[Finding]:
    """Findings tied to `route`, excluding the AUTH-* family -- those live
    exclusively in the Authentication tab now (see `_render_auth_tab`), so
    a route card's border color/sort rank/tag list should reflect only its
    input/validation findings, matching what's actually visible on it.
    """
    return [f for f in findings if f.route is route and not _is_auth_finding(f)]


def _vscode_uri(target_path: Path, file_rel: str, line: int) -> str:
    full = (target_path / file_rel).resolve()
    return f"vscode://file/{str(full).replace(chr(92), '/')}:{line}"


def _read_lines(target_path: Path, file_rel: str, start: int, end: int) -> tuple[list[tuple[int, str]], str | None]:
    full_path = target_path / file_rel
    try:
        text = full_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        return [], f"couldn't read {file_rel}: {exc}"

    lines = text.split("\n")
    start = max(1, start)
    end = min(len(lines), end)
    if start > end:
        return [], "line range out of bounds"
    return [(n, lines[n - 1]) for n in range(start, end + 1)], None


def _highlight_params(highlighted_html: str, param_names: list[str]) -> str:
    """Mark every occurrence of a route's path-parameter names in already
    syntax-highlighted Pygments output -- pure visual aid pointing at where
    user-controlled input enters the handler, not a claim about what
    happens to it afterward (no dataflow/sink tracing here).

    Works by matching Pygments' own per-identifier <span> tags exactly --
    every name reference (python "n", java "n", javascript "nx", ...) is
    already wrapped in its own complete <span class="...">exact_text</span>,
    so anchoring on that (rather than a raw substring search over the HTML)
    guarantees this only ever marks whole-identifier matches. It naturally
    can't match text inside a string or comment token, since those spans
    contain the surrounding quote characters/comment marker too and so
    never have content exactly equal to a bare parameter name.
    """
    names = {n for n in param_names if n}
    if not names:
        return highlighted_html

    pattern = re.compile(
        r'<span class="([^"]*)">(' + "|".join(re.escape(n) for n in names) + r")</span>"
    )
    return pattern.sub(
        r'<span class="\1 param-highlight" title="path parameter -- user-controlled input">\2</span>',
        highlighted_html,
    )


def _render_code_block(target_path: Path, route: Route, language: str) -> str:
    source_file = route.source_file or route.file
    start = route.source_start_line
    end = route.source_end_line
    unresolved = start is None or end is None

    if unresolved:
        # Couldn't resolve the handler's full body -- fall back to just the
        # registration line so there's still something to look at.
        start = end = route.line

    numbered_lines, error = _read_lines(target_path, source_file, start, end)
    ide_link = _vscode_uri(target_path, source_file, route.line)

    header = f"""
    <div class="code-header">
      <span class="code-path">{_esc(source_file)}:{route.line}</span>
      <a class="ide-link" href="{_esc(ide_link)}">open in editor &rarr;</a>
    </div>"""

    if error:
        return header + f'<p class="code-error">{_esc(error)}</p>'
    note = '<p class="code-note">handler body not automatically resolved -- showing the registration line only.</p>' if unresolved else ""

    code_text = "\n".join(text for _, text in numbered_lines)
    hl_lines = [route.line - start + 1] if start <= route.line <= end else []
    formatter = HtmlFormatter(
        style=_PYGMENTS_STYLE,
        linenos="inline",
        linenostart=start,
        hl_lines=hl_lines,
    )
    highlighted = pygments_highlight(code_text, _get_lexer(language, source_file), formatter)
    # Union the URL-side placeholder names with each param's actual code
    # identifier -- they diverge whenever an explicit binding is used
    # (Spring: `@PathVariable("order-id") Long orderId`), and only the code
    # identifier ever appears as a bare token in the handler body; the
    # URL-side name shows up only inside an annotation's string literal.
    highlight_names = list(dict.fromkeys(extract_path_param_names(route.path) + route.path_variable_binding_names))
    highlighted = _highlight_params(highlighted, highlight_names)

    return header + note + f'<div class="code-block">{highlighted}</div>'


def _render_finding(finding: Finding) -> str:
    return f"""
    <div class="finding sev-{_esc(finding.severity)}">
      <span class="finding-tag">{_esc(finding.check_id)}</span>
      <span class="finding-sev">{_esc(_SEVERITY_LABEL.get(finding.severity, finding.severity))}</span>
      <p class="finding-title">{_esc(finding.title)}</p>
      <p class="finding-desc">{_esc(finding.description)}</p>
    </div>"""


def _render_input_note(route: Route) -> str:
    """"user input: orderId (path) · region (query)" -- an always-present,
    quick-glance callout of every attacker-controlled value flowing into the
    handler, regardless of whether it looks like an object id (IDOR-001 only
    fires for id-like names) or is otherwise interesting. The code view
    already visually underlines path params on expand (see
    `_highlight_params`), but that requires opening the card and hovering;
    this puts the same fact in plain text at the top of the route body.
    Framework-agnostic: `route.path` template params and
    `route.extra_param_names` are populated by every analyzer, not just
    Spring's.
    """
    path_params = extract_path_param_names(route.path)
    if not path_params and not route.extra_param_names:
        return ""

    # `class_validated` is only ever set (to True/False, never left None) by
    # the Spring analyzer, so its presence is a cheap "this route came from
    # Spring" signal -- letting us label @RequestParam vs @RequestBody
    # precisely there while other frameworks fall back to the honest,
    # unresolved "query/body" label.
    is_spring_route = route.class_validated is not None

    parts = [f"{_esc(name)} (path)" for name in path_params]
    for name in route.extra_param_names:
        if name in route.request_body_validations:
            label = "body"
        elif is_spring_route:
            label = "query"
        else:
            label = "query/body"
        parts.append(f"{_esc(name)} ({label})")

    return f'<p class="input-note">user input: {" &middot; ".join(parts)}</p>'


def _render_validation_note(route: Route) -> str:
    """"validation: @Validated (class-wide) · orderId: @Positive · dto (body): @Valid"
    -- a quick-glance line, parallel to `_render_input_note`, so a reviewer
    can see every half of Bean Validation coverage at once: is the class wired up to
    enforce @PathVariable/@RequestParam constraints, does each such param
    actually carry one, and does each @RequestBody param carry the @Valid
    that's needed to cascade into its own field constraints. Only rendered
    when the analyzer populated `param_validations`/`request_body_validations`
    (currently just Spring); silently omitted for every other framework.

    The class-wide @Validated label is shown whenever this is a Spring route
    at all (`class_validated is not None`), even on a route with only a
    @RequestBody param and no @PathVariable/@RequestParam -- otherwise a
    body-only route with no @Valid shows just "dto (body): NOT @Valid" with
    no visible connection to the class annotation sitting right above it in
    the code, which reads as a false positive to anyone who (reasonably)
    assumes class-level @Validated covers @RequestBody too. It doesn't --
    the two are unrelated mechanisms -- so showing both side by side here
    makes that explicit instead of leaving it to the finding text alone.
    """
    if not route.param_validations and not route.request_body_validations:
        return ""

    parts: list[str] = []
    gap = False

    if route.class_validated is not None:
        class_label = "@Validated (class-wide)" if route.class_validated else "NOT @Validated"
        parts.append(class_label)

    if route.param_validations:
        gap = gap or (any(anns for anns in route.param_validations.values()) and not route.class_validated)
        parts += [
            f"{_esc(name)}{' (body)' if name in route.request_body_validations else ''}: "
            f"{' '.join('@' + _esc(a) for a in anns) if anns else 'no constraint'}"
            for name, anns in sorted(route.param_validations.items())
        ]

    if route.request_body_validations:
        gap = gap or any(not has_valid for has_valid in route.request_body_validations.values())
        parts += [
            f"{_esc(name)} (body): {'@Valid' if has_valid else 'NOT @Valid'}"
            for name, has_valid in sorted(route.request_body_validations.items())
        ]

    if not parts:
        return ""

    css_class = "validation-note validation-warn" if gap else "validation-note"
    return f'<p class="{css_class}">validation: {" &middot; ".join(parts)}</p>'


def _route_search_blob(route: Route) -> str:
    return _esc(" ".join([route.path, route.handler_name, route.file, " ".join(route.methods)]).lower())


def _render_route(route: Route, findings: list[Finding], target_path: Path, language: str, route_id: str) -> str:
    route_findings = _non_auth_findings_for_route(route, findings)
    worst = _worst_severity(route_findings)

    method_badges = "".join(f'<span class="method m-{_esc(m.lower())}">{_esc(m)}</span>' for m in route.methods)
    methods_attr = " ".join(m.lower() for m in route.methods)
    finding_tags = "".join(
        f'<span class="tag sev-{_esc(f.severity)}">{_esc(f.check_id)}</span>' for f in route_findings
    )
    input_html = _render_input_note(route)
    validation_html = _render_validation_note(route)

    findings_html = "".join(_render_finding(f) for f in route_findings) or '<p class="no-findings">No baseline findings on this route.</p>'
    code_html = _render_code_block(target_path, route, language)

    return f"""
      <details class="route-card sev-{worst}" data-severity="{worst}" data-methods="{_esc(methods_attr)}" data-file="{_esc(route.file)}" data-search="{_route_search_blob(route)}">
        <summary>
          <input type="checkbox" class="review-toggle" data-item-id="{_esc(route_id)}" title="Mark reviewed" aria-label="Mark this route reviewed">
          <span class="methods">{method_badges}</span>
          <span class="path">{_esc(route.path)}</span>
          <span class="handler">{_esc(route.handler_name)}</span>
          <span class="tags">{finding_tags}</span>
        </summary>
        <div class="route-body">
          {input_html}
          {validation_html}
          <div class="findings">{findings_html}</div>
          {code_html}
        </div>
      </details>"""


def _render_group(result: ScanResult, target_path: Path, route_ids: itertools.count) -> str:
    # Worst-first by default -- the JS "Sort by" control lets the reader
    # reorder interactively, but the first thing anyone sees on open should
    # already be what needs attention most. AUTH-* findings are excluded
    # (see _non_auth_findings_for_route) since they no longer render on the
    # card at all -- sorting by a severity the reader can't see on this tab
    # would be confusing.
    sorted_routes = sorted(
        result.routes,
        key=lambda r: _ROUTE_SORT_RANK.get(
            _worst_severity(_non_auth_findings_for_route(r, result.findings)), 9
        ),
    )
    routes_html = "".join(
        _render_route(r, result.findings, target_path, result.language, f"route-{next(route_ids)}")
        for r in sorted_routes
    )
    notes_html = "".join(f'<p class="group-note">{_esc(n)}</p>' for n in result.notes)

    version_html = ""
    if result.framework_version:
        vfile, vline, vdescription = result.framework_version_source
        ide_link = _vscode_uri(target_path, vfile, vline)
        version_finding = next(
            (f for f in result.findings if f.check_id == "CONFIG-003" and f.file == vfile and f.line == vline),
            None,
        )
        sev = version_finding.severity if version_finding else "info"
        version_html = (
            f'<a class="version-badge sev-{_esc(sev)}" href="{_esc(ide_link)}" '
            f'title="{_esc(vdescription)} ({_esc(vfile)}:{vline})">'
            f'{_esc(result.framework_version_label)} {_esc(result.framework_version)}</a>'
        )

    return f"""
    <section class="group" data-lang="{_esc(result.language)}">
      <h2 class="group-title">{_esc(result.language)} / {_esc(result.framework)}
        {version_html}
        <span class="count">{len(result.routes)} route{"s" if len(result.routes) != 1 else ""}</span>
      </h2>
      {notes_html}
      {routes_html or '<p class="no-findings">No routes extracted.</p>'}
    </section>"""


def _render_standalone_finding(finding: Finding, target_path: Path, item_id: str) -> str:
    """A project-wide finding (route=None) -- these have nowhere to attach
    in the route-card view, so unlike `_render_finding` this includes its
    own file:line + "open in editor" link, plus a reviewed-toggle: these
    are exactly the checks most likely to need a human's "confirmed a
    false positive" pass (presence-only sink checks especially), and
    there can be many of them, so tracking progress the same way route
    cards already do matters here too.
    """
    ide_link = _vscode_uri(target_path, finding.file, finding.line)
    return f"""
    <div class="finding sev-{_esc(finding.severity)}">
      <div class="finding-head">
        <input type="checkbox" class="review-toggle" data-item-id="{_esc(item_id)}" title="Mark reviewed" aria-label="Mark this finding reviewed">
        <span class="finding-tag">{_esc(finding.check_id)}</span>
        <span class="finding-sev">{_esc(_SEVERITY_LABEL.get(finding.severity, finding.severity))}</span>
        <a class="ide-link finding-loc" href="{_esc(ide_link)}">{_esc(finding.file)}:{finding.line} &rarr;</a>
      </div>
      <p class="finding-title">{_esc(finding.title)}</p>
      <p class="finding-desc">{_esc(finding.description)}</p>
    </div>"""


def _render_auth_route_row(route: Route, auth_finding: Finding | None, target_path: Path) -> str:
    ide_link = _vscode_uri(target_path, route.file, route.line)
    methods_badges = "".join(f'<span class="method m-{_esc(m.lower())}">{_esc(m)}</span>' for m in route.methods)

    if route.auth_decorators:
        status_sev = "clean"
        status_text = ", ".join(f"@{d}" for d in route.auth_decorators)
    elif route.explicit_access == "PermitAll":
        status_sev = "info"
        status_text = "explicitly public (@PermitAll)"
    elif route.explicit_access == "DenyAll":
        status_sev = "info"
        status_text = "explicitly denied (@DenyAll)"
    elif auth_finding is not None:
        status_sev = auth_finding.severity
        status_text = auth_finding.title
    else:
        status_sev = "clean"
        status_text = "covered"

    return f"""
      <tr class="auth-row sev-{_esc(status_sev)}" data-severity="{_esc(status_sev)}" data-search="{_route_search_blob(route)}">
        <td>{methods_badges}</td>
        <td class="path">{_esc(route.path)}</td>
        <td class="handler">{_esc(route.handler_name)}</td>
        <td class="auth-status sev-{_esc(status_sev)}">{_esc(status_text)}</td>
        <td><a class="ide-link" href="{_esc(ide_link)}">{_esc(route.file)}:{route.line} &rarr;</a></td>
      </tr>"""


def _render_auth_tab(results: list[ScanResult], target_path: Path, item_ids: itertools.count) -> str:
    """The Authentication tab: every AUTH-* finding gathered in one place,
    split into project-wide config findings (AUTH-002/003/004/005 -- no
    single route to attach to) and a per-route table (AUTH-001, plus routes
    with no finding at all because they're already covered by a
    recognized annotation). Kept deliberately separate from the Routes tab
    so severity/sort there reflects only input/validation coverage, not a
    mix of two different concerns.
    """
    all_findings = [f for r in results for f in r.findings]
    project_findings = sorted(
        (f for f in all_findings if _is_auth_finding(f) and f.route is None),
        key=lambda f: _SEVERITY_RANK.get(f.severity, 9),
    )
    project_html = "".join(
        _render_standalone_finding(f, target_path, f"finding-{next(item_ids)}") for f in project_findings
    )

    global_auth_html = ""
    for result in results:
        if not result.global_auth_source:
            continue
        gfile, gline, gdescription = result.global_auth_source
        ide_link = _vscode_uri(target_path, gfile, gline)
        global_auth_html += f"""
      <p class="group-note global-auth-note">
        Global auth mechanism detected: <a class="ide-link" href="{_esc(ide_link)}">{_esc(gfile)}:{gline}</a>
        &mdash; {_esc(gdescription)}.
      </p>"""

    rows_html = ""
    total_routes = 0
    for result in results:
        for route in result.routes:
            total_routes += 1
            auth_finding = next(
                (f for f in result.findings if f.check_id == "AUTH-001" and f.route is route), None
            )
            rows_html += _render_auth_route_row(route, auth_finding, target_path)

    table_html = f"""
    <table class="auth-table">
      <thead>
        <tr><th>Method</th><th>Path</th><th>Handler</th><th>Status</th><th>Location</th></tr>
      </thead>
      <tbody>
        {rows_html or '<tr><td colspan="5" class="no-findings">No routes extracted.</td></tr>'}
      </tbody>
    </table>"""

    return f"""
    <section class="auth-section">
      <h2 class="section-title">Project-wide<span class="count">{len(project_findings)} finding{"s" if len(project_findings) != 1 else ""}</span><span class="section-reviewed">0 / {len(project_findings)} reviewed</span></h2>
      {global_auth_html}
      {project_html or '<p class="no-findings">No project-wide authentication findings.</p>'}
    </section>
    <section class="auth-section">
      <h2 class="section-title">Per-route coverage<span class="count">{total_routes} route{"s" if total_routes != 1 else ""}</span></h2>
      {table_html}
    </section>"""


def _render_findings_tab(results: list[ScanResult], target_path: Path, item_ids: itertools.count) -> str:
    """Every other project-wide finding (route=None, not AUTH-*) gathered
    in one place -- dangerous-sink checks (SQLI/CMD/PATH/SSRF/DESER), AOP
    proxy-bypass, and general config findings (debug mode, CORS) all live
    here, since none of them attach to a single route the way IDOR/VALID
    findings do, and none of them are specifically about authentication
    the way the Auth tab's own project-wide section is.
    """
    all_findings = [f for r in results for f in r.findings]
    findings = sorted(
        (f for f in all_findings if f.route is None and not _is_auth_finding(f)),
        key=lambda f: _SEVERITY_RANK.get(f.severity, 9),
    )
    findings_html = "".join(
        _render_standalone_finding(f, target_path, f"finding-{next(item_ids)}") for f in findings
    )

    return f"""
    <section class="auth-section">
      <h2 class="section-title">Findings<span class="count">{len(findings)} finding{"s" if len(findings) != 1 else ""}</span><span class="section-reviewed">0 / {len(findings)} reviewed</span></h2>
      {findings_html or '<p class="no-findings">No project-wide findings outside routes/authentication.</p>'}
    </section>"""


def render_html(results: list[ScanResult], target_path: Path) -> str:
    all_findings = [f for r in results for f in r.findings]
    all_routes = [rt for r in results for rt in r.routes]
    # Scoped to findings that actually attach to a route card -- the
    # sidebar's severity filter/stat block belongs to the Routes tab, which
    # no longer shows AUTH-* at all, and route=None findings (dangerous
    # sinks, config checks) don't render as a tag on any card either, so
    # counting them here would make the sidebar disagree with what's
    # actually visible on the cards.
    routes_tab_findings = [f for f in all_findings if f.route is not None and not _is_auth_finding(f)]
    severity_counts = {sev: sum(1 for f in routes_tab_findings if f.severity == sev) for sev in _SEVERITY_RANK}
    auth_findings = [f for f in all_findings if _is_auth_finding(f)]
    auth_attention_count = sum(1 for f in auth_findings if f.severity in ("high", "medium"))
    general_findings = [f for f in all_findings if f.route is None and not _is_auth_finding(f)]
    general_attention_count = sum(1 for f in general_findings if f.severity in ("high", "medium"))
    languages = sorted({r.language for r in results})
    methods_present = sorted(
        {m for r in all_routes for m in r.methods},
        key=lambda m: (_METHOD_ORDER.get(m, 99), m),
    )

    lang_filters = "".join(
        f'<label><input type="checkbox" class="f-lang" value="{_esc(lang)}" checked> {_esc(lang)}</label>'
        for lang in languages
    )
    sev_filters = "".join(
        f'<label><input type="checkbox" class="f-sev" value="{sev}" checked> {label} '
        f'<span class="sidebar-count">{severity_counts[sev]}</span></label>'
        for sev, label in _SEVERITY_LABEL.items()
    )
    method_filters = "".join(
        f'<label><input type="checkbox" class="f-method" value="{m.lower()}" checked> {_esc(m)}</label>'
        for m in methods_present
    )

    route_ids = itertools.count(1)
    groups_html = "".join(_render_group(r, target_path, route_ids) for r in results) or '<p class="no-findings">No supported language/framework detected in target.</p>'
    item_ids = itertools.count(1)
    auth_tab_html = _render_auth_tab(results, target_path, item_ids)
    findings_tab_html = _render_findings_tab(results, target_path, item_ids)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")
    # Namespaces this report's "reviewed" checklist in localStorage so two
    # different reports opened in the same browser (file:// pages can share
    # one storage bucket) don't clobber each other's progress. Stable across
    # re-runs against the same target, so re-scanning doesn't wipe progress.
    report_id = hashlib.sha256(str(target_path.resolve()).encode("utf-8")).hexdigest()[:12]
    # Embedded so "Download SARIF" works standalone from the already-open
    # report with no server/re-run needed -- "</script" is escaped since a
    # finding's own text (a route path, a query snippet) could otherwise
    # prematurely close this script tag.
    sarif_json = json.dumps(build_sarif(results)).replace("</script", "<\\/script")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Appsec review -- {_esc(target_path.name)}</title>
<style>
{HtmlFormatter(style=_PYGMENTS_STYLE).get_style_defs(".highlight")}
{_CSS}
</style>
</head>
<body>
<div class="page">
  <header class="topbar">
    <div class="brand">
      <span class="brand-mark">&sect;</span>
      <div>
        <h1>Appsec Review</h1>
        <p class="meta">{_esc(target_path.name)} &middot; generated {generated_at} &middot; {len(all_routes)} route{"s" if len(all_routes) != 1 else ""}</p>
      </div>
    </div>
    <div class="topbar-actions">
      <input id="search" type="search" placeholder="filter by path, handler, file&hellip;" autocomplete="off">
      <select id="sort-select" title="Sort routes within each section">
        <option value="severity">Sort: severity</option>
        <option value="path">Sort: path</option>
        <option value="method">Sort: method</option>
        <option value="file">Sort: file</option>
      </select>
      <button id="expand-all" type="button">Expand all</button>
      <button id="collapse-all" type="button">Collapse all</button>
      <label class="hide-reviewed-toggle"><input type="checkbox" id="hide-reviewed"> Hide reviewed</label>
      <button id="reset-reviewed" type="button">Reset reviewed</button>
      <button id="download-sarif" type="button" title="Download all findings as SARIF -- open in VS Code's SARIF Viewer extension, or upload to GitHub Code Scanning, to triage them one by one">Download SARIF</button>
    </div>
  </header>

  <nav class="tabs">
    <button class="tab-button active" id="tab-btn-routes" data-tab="routes" type="button">
      Routes <span class="tab-count">{len(all_routes)}</span>
    </button>
    <button class="tab-button" id="tab-btn-auth" data-tab="auth" type="button" title="{auth_attention_count} needing attention (high/medium) of {len(auth_findings)} total auth finding{"s" if len(auth_findings) != 1 else ""}">
      Authentication <span class="tab-count{" tab-count-warn" if auth_attention_count else ""}">{auth_attention_count}</span>
    </button>
    <button class="tab-button" id="tab-btn-findings" data-tab="findings" type="button" title="{general_attention_count} needing attention (high/medium) of {len(general_findings)} total finding{"s" if len(general_findings) != 1 else ""}">
      Findings <span class="tab-count{" tab-count-warn" if general_attention_count else ""}">{general_attention_count}</span>
    </button>
  </nav>

  <div class="tab-panel" id="tab-panel-routes" data-tab="routes">
    <div class="layout">
      <aside class="sidebar">
        <div class="stat-block">
          <div class="stat"><span class="stat-value">{len(all_routes)}</span><span class="stat-label">routes</span></div>
          <div class="stat sev-high"><span class="stat-value">{severity_counts["high"]}</span><span class="stat-label">high</span></div>
          <div class="stat sev-medium"><span class="stat-value">{severity_counts["medium"]}</span><span class="stat-label">medium</span></div>
          <div class="stat sev-low"><span class="stat-value">{severity_counts["low"]}</span><span class="stat-label">low</span></div>
          <div class="stat stat-reviewed"><span class="stat-value" id="reviewed-stat">0 / {len(all_routes)}</span><span class="stat-label">reviewed</span></div>
        </div>

        <div class="filter-group">
          <h2>Severity</h2>
          {sev_filters}
          <label><input type="checkbox" class="f-sev" value="clean" checked> No findings</label>
        </div>

        <div class="filter-group">
          <h2>Method</h2>
          {method_filters}
        </div>

        <div class="filter-group">
          <h2>Language</h2>
          {lang_filters}
        </div>
      </aside>

      <main class="content">
        {groups_html}
      </main>
    </div>
  </div>

  <div class="tab-panel" id="tab-panel-auth" data-tab="auth" hidden>
    <main class="content auth-content">
      {auth_tab_html}
    </main>
  </div>

  <div class="tab-panel" id="tab-panel-findings" data-tab="findings" hidden>
    <main class="content auth-content">
      {findings_tab_html}
    </main>
  </div>
</div>

<script>
const REPORT_ID = "{report_id}";
const SARIF_DATA = {sarif_json};
{_JS}
</script>
</body>
</html>"""


_CSS = """
:root {
  --bg: #10141c;
  --surface: #171d29;
  --surface-raised: #1e2534;
  --border: #2a3244;
  --text: #e6e9f0;
  --text-muted: #8890a3;
  --accent: #5ec8d8;
  --sev-high: #ef5b5b;
  --sev-medium: #f2a94e;
  --sev-low: #7fb3e8;
  --sev-info: #7c8397;
  --sev-clean: #4fb477;
  --mono: ui-monospace, "Cascadia Code", "JetBrains Mono", Consolas, "Courier New", monospace;
  --sans: ui-sans-serif, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  font-size: 14px;
  line-height: 1.5;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  padding: 18px 28px;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
  flex-wrap: wrap;
}

.brand { display: flex; align-items: center; gap: 14px; }
.brand-mark {
  font-family: var(--mono);
  font-size: 22px;
  color: var(--accent);
  border: 1px solid var(--border);
  width: 38px; height: 38px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 4px;
}
.brand h1 { font-size: 16px; margin: 0; letter-spacing: 0.02em; }
.brand .meta { margin: 2px 0 0; color: var(--text-muted); font-size: 12.5px; font-family: var(--mono); }

.topbar-actions { display: flex; gap: 10px; align-items: center; }
#search {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 12.5px;
  width: 260px;
}
#search:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

#sort-select {
  background: var(--bg);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 10px;
  border-radius: 4px;
  font-family: var(--mono);
  font-size: 12.5px;
}
#sort-select:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

button {
  background: var(--surface-raised);
  border: 1px solid var(--border);
  color: var(--text);
  padding: 8px 12px;
  border-radius: 4px;
  font-family: var(--sans);
  font-size: 12.5px;
  cursor: pointer;
}
button:hover { border-color: var(--accent); }
button:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; }

.hide-reviewed-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--text-muted);
  cursor: pointer;
  user-select: none;
}
.hide-reviewed-toggle input { accent-color: var(--accent); cursor: pointer; }

.tabs {
  display: flex;
  gap: 4px;
  padding: 12px 28px 0;
  border-bottom: 1px solid var(--border);
  background: var(--surface);
}
.tab-button {
  background: transparent;
  border: 1px solid transparent;
  border-bottom: none;
  color: var(--text-muted);
  padding: 10px 16px;
  border-radius: 4px 4px 0 0;
  font-family: var(--sans);
  font-size: 13px;
  cursor: pointer;
}
.tab-button:hover { color: var(--text); }
.tab-button.active {
  color: var(--text);
  background: var(--bg);
  border-color: var(--border);
}
.tab-count {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 7px;
  border-radius: 10px;
  background: var(--surface-raised);
  color: var(--text-muted);
  font-family: var(--mono);
  font-size: 11px;
}
.tab-count-warn { background: var(--sev-high); color: var(--bg); }
.tab-panel[hidden] { display: none; }

.layout { display: flex; align-items: flex-start; }

.sidebar {
  width: 220px;
  flex-shrink: 0;
  padding: 24px 20px;
  position: sticky;
  top: 0;
  border-right: 1px solid var(--border);
  min-height: calc(100vh - 75px);
}

.stat-block { display: flex; flex-direction: column; gap: 4px; margin-bottom: 24px; }
.stat { display: flex; justify-content: space-between; align-items: baseline; padding: 4px 0; }
.stat-value { font-family: var(--mono); font-size: 18px; font-weight: 600; }
.stat-label { color: var(--text-muted); font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.06em; }
.stat.sev-high .stat-value { color: var(--sev-high); }
.stat.sev-medium .stat-value { color: var(--sev-medium); }
.stat.sev-low .stat-value { color: var(--sev-low); }
.stat-reviewed { border-top: 1px solid var(--border); margin-top: 4px; padding-top: 8px; }
.stat-reviewed .stat-value { color: var(--sev-clean); }

.filter-group { margin-bottom: 22px; }
.filter-group h2 {
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-muted);
  margin: 0 0 8px;
}
.filter-group label {
  display: flex;
  align-items: center;
  gap: 7px;
  font-size: 12.5px;
  padding: 4px 0;
  cursor: pointer;
  font-family: var(--mono);
}
.sidebar-count { margin-left: auto; color: var(--text-muted); }

.content { flex: 1; padding: 24px 28px 64px; min-width: 0; }

.group { margin-bottom: 30px; }
.group-title {
  font-family: var(--mono);
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin: 0 0 14px;
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.group-title .count { color: var(--text); font-size: 12px; text-transform: none; letter-spacing: 0; }
.version-badge {
  font-family: var(--mono);
  font-size: 11px;
  text-transform: none;
  letter-spacing: 0;
  padding: 2px 8px;
  border-radius: 3px;
  border: 1px solid var(--border);
  color: var(--sev-info);
  text-decoration: none;
}
.version-badge:hover { text-decoration: underline; }
.version-badge.sev-high { color: var(--sev-high); border-color: var(--sev-high); }
.version-badge.sev-medium { color: var(--sev-medium); border-color: var(--sev-medium); }
.version-badge.sev-low { color: var(--sev-low); border-color: var(--sev-low); }
.group-note { color: var(--text-muted); font-size: 12.5px; font-style: italic; margin: 0 0 10px; }
.global-auth-note {
  font-style: normal;
  color: var(--text);
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent);
  border-radius: 4px;
  padding: 10px 14px;
  margin: 0 0 14px;
}
.global-auth-note .ide-link { font-family: var(--mono); }

.route-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--sev-clean);
  border-radius: 4px;
  margin-bottom: 8px;
  overflow: hidden;
}
.route-card.sev-high { border-left-color: var(--sev-high); }
.route-card.sev-medium { border-left-color: var(--sev-medium); }
.route-card.sev-low { border-left-color: var(--sev-low); }
.route-card.sev-info { border-left-color: var(--sev-info); }

.route-card.reviewed { opacity: 0.45; }
.route-card.reviewed:hover { opacity: 0.8; }
.route-card.reviewed .path, .route-card.reviewed .handler { text-decoration: line-through; }

.route-card summary {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 11px 16px;
  cursor: pointer;
  list-style: none;
  font-family: var(--mono);
  font-size: 12.5px;
}
.route-card summary::-webkit-details-marker { display: none; }
.route-card summary:hover { background: var(--surface-raised); }
.route-card summary:focus-visible { outline: 2px solid var(--accent); outline-offset: -2px; }

.review-toggle {
  width: 15px;
  height: 15px;
  flex-shrink: 0;
  accent-color: var(--sev-clean);
  cursor: pointer;
}

.methods { display: flex; gap: 4px; flex-shrink: 0; }
.method {
  border: 1px solid var(--border);
  padding: 1px 6px;
  border-radius: 3px;
  font-size: 10.5px;
  color: var(--text-muted);
}
.method.m-get { color: var(--sev-low); border-color: var(--sev-low); }
.method.m-post { color: var(--sev-clean); border-color: var(--sev-clean); }
.method.m-put, .method.m-patch { color: var(--sev-medium); border-color: var(--sev-medium); }
.method.m-delete { color: var(--sev-high); border-color: var(--sev-high); }

.path { color: var(--accent); flex-shrink: 0; }
.handler { color: var(--text-muted); flex-shrink: 0; }
.handler::before { content: "\\2192"; margin-right: 6px; }

.tags { display: flex; gap: 4px; flex-shrink: 0; margin-left: auto; }
.tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  border: 1px solid var(--border);
}
.tag.sev-high { color: var(--sev-high); border-color: var(--sev-high); }
.tag.sev-medium { color: var(--sev-medium); border-color: var(--sev-medium); }
.tag.sev-low { color: var(--sev-low); border-color: var(--sev-low); }
.tag.sev-info { color: var(--sev-info); border-color: var(--sev-info); }

.route-body {
  border-top: 1px solid var(--border);
  padding: 16px;
  background: var(--bg);
}

.input-note { font-family: var(--mono); font-size: 12px; color: var(--sev-medium); margin: 0 0 4px; }
.validation-note { font-family: var(--mono); font-size: 12px; color: var(--text-muted); margin: 0 0 12px; }
.validation-note.validation-warn { color: var(--sev-medium); }
.findings { display: flex; flex-direction: column; gap: 8px; margin-bottom: 14px; }
.finding {
  border: 1px solid var(--border);
  border-left: 3px solid var(--sev-info);
  border-radius: 3px;
  padding: 8px 12px;
  background: var(--surface);
}
.finding.sev-high { border-left-color: var(--sev-high); }
.finding.sev-medium { border-left-color: var(--sev-medium); }
.finding.sev-low { border-left-color: var(--sev-low); }
.finding-tag { font-family: var(--mono); font-size: 11px; color: var(--text-muted); }
.finding-sev { font-family: var(--mono); font-size: 11px; margin-left: 8px; text-transform: uppercase; letter-spacing: 0.04em; }
.finding-title { margin: 6px 0 2px; font-weight: 600; font-size: 13px; }
.finding-desc { margin: 0; color: var(--text-muted); font-size: 12.5px; }
.no-findings { color: var(--text-muted); font-size: 12.5px; font-style: italic; margin: 0; }

.auth-content { max-width: 1100px; }
.auth-section { margin-bottom: 32px; }
.section-title {
  font-family: var(--mono);
  font-size: 13px;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--text-muted);
  border-bottom: 1px solid var(--border);
  padding-bottom: 8px;
  margin: 0 0 14px;
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.section-title .count { color: var(--text); font-size: 12px; text-transform: none; letter-spacing: 0; }
.section-title .section-reviewed { margin-left: auto; color: var(--sev-clean); font-size: 12px; text-transform: none; letter-spacing: 0; }
.auth-section .finding { margin-bottom: 8px; }
.finding.reviewed { opacity: 0.45; }
.finding.reviewed:hover { opacity: 0.8; }
.finding.reviewed .finding-title { text-decoration: line-through; }
.finding-head { display: flex; align-items: center; gap: 8px; }
.finding-head .review-toggle { flex-shrink: 0; accent-color: var(--sev-clean); cursor: pointer; }
.finding-loc { margin-left: auto; font-family: var(--mono); font-size: 11px; }

.auth-table { width: 100%; border-collapse: collapse; font-family: var(--mono); font-size: 12.5px; }
.auth-table th {
  text-align: left;
  color: var(--text-muted);
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  padding: 8px 10px;
  border-bottom: 1px solid var(--border);
}
.auth-table td { padding: 9px 10px; border-bottom: 1px solid var(--border); vertical-align: top; }
.auth-row:hover { background: var(--surface); }
.auth-row .path { color: var(--accent); }
.auth-row .handler { color: var(--text-muted); }
.auth-status { border-left: 3px solid var(--sev-clean); padding-left: 8px; }
.auth-status.sev-high { border-left-color: var(--sev-high); color: var(--sev-high); }
.auth-status.sev-medium { border-left-color: var(--sev-medium); color: var(--sev-medium); }
.auth-status.sev-low { border-left-color: var(--sev-low); color: var(--sev-low); }
.auth-status.sev-info { border-left-color: var(--sev-info); color: var(--sev-info); }
.auth-status.sev-clean { color: var(--sev-clean); }

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text-muted);
  margin-bottom: 8px;
}
.code-path { color: var(--text); }
.ide-link { color: var(--accent); text-decoration: none; }
.ide-link:hover { text-decoration: underline; }
.code-note, .code-error {
  font-size: 12px;
  color: var(--sev-medium);
  font-style: italic;
  margin: 0 0 8px;
}
.code-error { color: var(--sev-high); }

.code-block {
  border: 1px solid var(--border);
  border-radius: 4px;
  overflow: hidden;
}
.code-block .highlight {
  background: var(--surface) !important;
  margin: 0;
  overflow-x: auto;
}
.code-block .highlight pre {
  margin: 0;
  padding: 10px 0;
  font-family: var(--mono);
  font-size: 12.5px;
  line-height: 1.45;
}
.code-block .linenos {
  padding: 0 14px 0 16px;
  color: var(--text-muted) !important;
  user-select: none;
}
.code-block .hll {
  display: block;
  background: rgba(94, 200, 216, 0.12);
}
.param-highlight {
  background: rgba(242, 169, 78, 0.16);
  border-bottom: 1px dotted var(--sev-medium);
  border-radius: 2px;
  cursor: help;
}

@media (max-width: 860px) {
  .layout { flex-direction: column; }
  .sidebar { width: 100%; position: static; border-right: none; border-bottom: 1px solid var(--border); }
  .route-card summary { flex-wrap: wrap; }
}

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; }
}
"""

_JS = """
// --- Tabs ---
const tabButtons = document.querySelectorAll('.tab-button');
const tabPanels = document.querySelectorAll('.tab-panel');
tabButtons.forEach(btn => {
  btn.addEventListener('click', () => {
    tabButtons.forEach(b => b.classList.toggle('active', b === btn));
    tabPanels.forEach(panel => { panel.hidden = panel.dataset.tab !== btn.dataset.tab; });
  });
});

document.getElementById('expand-all').addEventListener('click', () => {
  document.querySelectorAll('details.route-card').forEach(d => d.open = true);
});
document.getElementById('collapse-all').addEventListener('click', () => {
  document.querySelectorAll('details.route-card').forEach(d => d.open = false);
});

const search = document.getElementById('search');
const sevBoxes = document.querySelectorAll('.f-sev');
const langBoxes = document.querySelectorAll('.f-lang');
const methodBoxes = document.querySelectorAll('.f-method');
const hideReviewed = document.getElementById('hide-reviewed');

function applyFilters() {
  const q = search.value.trim().toLowerCase();
  const activeSev = new Set([...sevBoxes].filter(b => b.checked).map(b => b.value));
  const activeLang = new Set([...langBoxes].filter(b => b.checked).map(b => b.value));
  const activeMethod = new Set([...methodBoxes].filter(b => b.checked).map(b => b.value));
  const hideDone = hideReviewed.checked;

  document.querySelectorAll('section.group').forEach(section => {
    let anyVisible = false;
    const langOk = activeLang.has(section.dataset.lang);
    section.querySelectorAll('details.route-card').forEach(card => {
      const textOk = !q || card.dataset.search.includes(q);
      const sevOk = activeSev.has(card.dataset.severity);
      const methods = card.dataset.methods ? card.dataset.methods.split(' ') : [];
      const methodOk = methods.length === 0 || methods.some(m => activeMethod.has(m));
      const reviewedOk = !hideDone || !card.classList.contains('reviewed');
      const visible = langOk && textOk && sevOk && methodOk && reviewedOk;
      card.style.display = visible ? '' : 'none';
      if (visible) anyVisible = true;
    });
    section.style.display = anyVisible ? '' : 'none';
  });
}

search.addEventListener('input', applyFilters);
sevBoxes.forEach(b => b.addEventListener('change', applyFilters));
langBoxes.forEach(b => b.addEventListener('change', applyFilters));
methodBoxes.forEach(b => b.addEventListener('change', applyFilters));
hideReviewed.addEventListener('change', applyFilters);

// --- Sort ---
const SORT_SEVERITY_RANK = { high: 0, medium: 1, low: 2, info: 3, clean: 4 };
const sortSelect = document.getElementById('sort-select');

function sortValue(card, key) {
  if (key === 'severity') return SORT_SEVERITY_RANK[card.dataset.severity] ?? 9;
  if (key === 'path') return card.querySelector('.path').textContent.trim().toLowerCase();
  if (key === 'method') return (card.dataset.methods || '').split(' ')[0] || '';
  if (key === 'file') return (card.dataset.file || '').toLowerCase();
  return 0;
}

function applySort() {
  const key = sortSelect.value;
  document.querySelectorAll('section.group').forEach(section => {
    const cards = [...section.querySelectorAll('details.route-card')];
    cards.sort((a, b) => {
      const va = sortValue(a, key), vb = sortValue(b, key);
      if (va < vb) return -1;
      if (va > vb) return 1;
      return 0;
    });
    cards.forEach(c => section.appendChild(c));
  });
}

sortSelect.addEventListener('change', applySort);

// --- Reviewed checklist (persisted per-report in localStorage) ---
const STORAGE_KEY = 'appsec-review:' + REPORT_ID + ':reviewed';

function loadReviewed() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return new Set(raw ? JSON.parse(raw) : []);
  } catch (e) {
    return new Set();
  }
}

function saveReviewed() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify([...reviewed]));
  } catch (e) {
    // storage unavailable (private browsing, restrictive file:// policy,
    // storage full, ...) -- reviewed state just won't persist on reload.
  }
}

let reviewed = loadReviewed();
// One shared pool covers both route cards and standalone project-wide
// findings -- item ids are prefixed distinctly ("route-N" vs "finding-N")
// so they never collide even if the numbers coincide.
const reviewToggles = document.querySelectorAll('.review-toggle');

function updateReviewedStat() {
  const stat = document.getElementById('reviewed-stat');
  if (stat) {
    const routeToggles = document.querySelectorAll('.route-card .review-toggle');
    const routeReviewed = [...routeToggles].filter(cb => cb.checked).length;
    stat.textContent = routeReviewed + ' / ' + routeToggles.length;
  }
  // Each standalone-finding section (Auth tab's Project-wide, the whole
  // Findings tab) gets its own "X / Y reviewed" count, scoped to just the
  // toggles inside that section -- a route's own reviewed state doesn't
  // belong in either of these counts.
  document.querySelectorAll('.auth-section').forEach(section => {
    const span = section.querySelector('.section-reviewed');
    if (!span) return;
    const toggles = section.querySelectorAll('.finding .review-toggle');
    if (toggles.length === 0) return;
    const done = [...toggles].filter(cb => cb.checked).length;
    span.textContent = done + ' / ' + toggles.length + ' reviewed';
  });
}

function applyReviewedState() {
  reviewToggles.forEach(cb => {
    const isReviewed = reviewed.has(cb.dataset.itemId);
    cb.checked = isReviewed;
    const container = cb.closest('.route-card, .finding');
    if (container) container.classList.toggle('reviewed', isReviewed);
  });
  updateReviewedStat();
}

reviewToggles.forEach(cb => {
  cb.addEventListener('click', (e) => {
    // Without this, clicking a route card's checkbox also toggles its
    // parent <details> open/closed, since the click bubbles up through
    // <summary>. Harmless no-op for a finding's checkbox (not inside a
    // <summary>), so applied unconditionally.
    e.stopPropagation();
    const id = cb.dataset.itemId;
    if (cb.checked) reviewed.add(id); else reviewed.delete(id);
    const container = cb.closest('.route-card, .finding');
    if (container) container.classList.toggle('reviewed', cb.checked);
    saveReviewed();
    updateReviewedStat();
    if (hideReviewed.checked) applyFilters();
  });
});

document.getElementById('reset-reviewed').addEventListener('click', () => {
  reviewed.clear();
  saveReviewed();
  applyReviewedState();
  if (hideReviewed.checked) applyFilters();
});

document.getElementById('download-sarif').addEventListener('click', () => {
  const blob = new Blob([JSON.stringify(SARIF_DATA, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'appsec-review.sarif';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

applyReviewedState();
"""


def write_html(results: list[ScanResult], target_path: Path, out_path: Path) -> None:
    out_path.write_text(render_html(results, target_path), encoding="utf-8")
