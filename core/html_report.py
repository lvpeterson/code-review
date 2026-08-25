"""Generates a single self-contained HTML report.

Each route renders as a collapsible card; expanding it shows the full
handler source (file, line numbers, and a jump-to-IDE link) plus whatever
baseline findings were raised against it. No external assets/CDNs -- this
needs to open straight from disk, including on an air-gapped machine.
"""
from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path

from pygments import highlight as pygments_highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, get_lexer_for_filename
from pygments.util import ClassNotFound

from core.models import Finding, Route, ScanResult

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_SEVERITY_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

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

    return header + note + f'<div class="code-block">{highlighted}</div>'


def _render_finding(finding: Finding) -> str:
    return f"""
    <div class="finding sev-{_esc(finding.severity)}">
      <span class="finding-tag">{_esc(finding.check_id)}</span>
      <span class="finding-sev">{_esc(_SEVERITY_LABEL.get(finding.severity, finding.severity))}</span>
      <p class="finding-title">{_esc(finding.title)}</p>
      <p class="finding-desc">{_esc(finding.description)}</p>
    </div>"""


def _route_search_blob(route: Route) -> str:
    return _esc(" ".join([route.path, route.handler_name, route.file, " ".join(route.methods)]).lower())


def _render_route(route: Route, findings: list[Finding], target_path: Path, language: str) -> str:
    route_findings = [f for f in findings if f.route is route]
    worst = _worst_severity(route_findings)

    method_badges = "".join(f'<span class="method m-{_esc(m.lower())}">{_esc(m)}</span>' for m in route.methods)
    finding_tags = "".join(
        f'<span class="tag sev-{_esc(f.severity)}">{_esc(f.check_id)}</span>' for f in route_findings
    )
    auth_note = ", ".join(route.auth_decorators) if route.auth_decorators else "none detected"

    findings_html = "".join(_render_finding(f) for f in route_findings) or '<p class="no-findings">No baseline findings on this route.</p>'
    code_html = _render_code_block(target_path, route, language)

    return f"""
      <details class="route-card sev-{worst}" data-severity="{worst}" data-search="{_route_search_blob(route)}">
        <summary>
          <span class="methods">{method_badges}</span>
          <span class="path">{_esc(route.path)}</span>
          <span class="handler">{_esc(route.handler_name)}</span>
          <span class="loc">{_esc(route.file)}:{route.line}</span>
          <span class="tags">{finding_tags}</span>
        </summary>
        <div class="route-body">
          <p class="auth-note">auth: {_esc(auth_note)}</p>
          <div class="findings">{findings_html}</div>
          {code_html}
        </div>
      </details>"""


def _render_group(result: ScanResult, target_path: Path) -> str:
    routes_html = "".join(_render_route(r, result.findings, target_path, result.language) for r in result.routes)
    notes_html = "".join(f'<p class="group-note">{_esc(n)}</p>' for n in result.notes)
    return f"""
    <section class="group" data-lang="{_esc(result.language)}">
      <h2 class="group-title">{_esc(result.language)} / {_esc(result.framework)}
        <span class="count">{len(result.routes)} route{"s" if len(result.routes) != 1 else ""}</span>
      </h2>
      {notes_html}
      {routes_html or '<p class="no-findings">No routes extracted.</p>'}
    </section>"""


def render_html(results: list[ScanResult], target_path: Path) -> str:
    all_findings = [f for r in results for f in r.findings]
    all_routes = [rt for r in results for rt in r.routes]
    severity_counts = {sev: sum(1 for f in all_findings if f.severity == sev) for sev in _SEVERITY_RANK}
    languages = sorted({r.language for r in results})

    lang_filters = "".join(
        f'<label><input type="checkbox" class="f-lang" value="{_esc(lang)}" checked> {_esc(lang)}</label>'
        for lang in languages
    )
    sev_filters = "".join(
        f'<label><input type="checkbox" class="f-sev" value="{sev}" checked> {label} '
        f'<span class="sidebar-count">{severity_counts[sev]}</span></label>'
        for sev, label in _SEVERITY_LABEL.items()
    )

    groups_html = "".join(_render_group(r, target_path) for r in results) or '<p class="no-findings">No supported language/framework detected in target.</p>'

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

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
      <button id="expand-all" type="button">Expand all</button>
      <button id="collapse-all" type="button">Collapse all</button>
    </div>
  </header>

  <div class="layout">
    <aside class="sidebar">
      <div class="stat-block">
        <div class="stat"><span class="stat-value">{len(all_routes)}</span><span class="stat-label">routes</span></div>
        <div class="stat sev-high"><span class="stat-value">{severity_counts["high"]}</span><span class="stat-label">high</span></div>
        <div class="stat sev-medium"><span class="stat-value">{severity_counts["medium"]}</span><span class="stat-label">medium</span></div>
        <div class="stat sev-low"><span class="stat-value">{severity_counts["low"]}</span><span class="stat-label">low</span></div>
      </div>

      <div class="filter-group">
        <h2>Severity</h2>
        {sev_filters}
        <label><input type="checkbox" class="f-sev" value="clean" checked> No findings</label>
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

<script>
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
.group-note { color: var(--text-muted); font-size: 12.5px; font-style: italic; margin: 0 0 10px; }

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
.loc { color: var(--text-muted); margin-left: auto; flex-shrink: 0; }

.tags { display: flex; gap: 4px; flex-shrink: 0; }
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

.auth-note { font-family: var(--mono); font-size: 12px; color: var(--text-muted); margin: 0 0 12px; }
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

@media (max-width: 860px) {
  .layout { flex-direction: column; }
  .sidebar { width: 100%; position: static; border-right: none; border-bottom: 1px solid var(--border); }
  .route-card summary { flex-wrap: wrap; }
  .loc { margin-left: 0; }
}

@media (prefers-reduced-motion: reduce) {
  * { transition: none !important; }
}
"""

_JS = """
document.getElementById('expand-all').addEventListener('click', () => {
  document.querySelectorAll('details.route-card').forEach(d => d.open = true);
});
document.getElementById('collapse-all').addEventListener('click', () => {
  document.querySelectorAll('details.route-card').forEach(d => d.open = false);
});

const search = document.getElementById('search');
const sevBoxes = document.querySelectorAll('.f-sev');
const langBoxes = document.querySelectorAll('.f-lang');

function applyFilters() {
  const q = search.value.trim().toLowerCase();
  const activeSev = new Set([...sevBoxes].filter(b => b.checked).map(b => b.value));
  const activeLang = new Set([...langBoxes].filter(b => b.checked).map(b => b.value));

  document.querySelectorAll('section.group').forEach(section => {
    let anyVisible = false;
    const langOk = activeLang.has(section.dataset.lang);
    section.querySelectorAll('details.route-card').forEach(card => {
      const textOk = !q || card.dataset.search.includes(q);
      const sevOk = activeSev.has(card.dataset.severity);
      const visible = langOk && textOk && sevOk;
      card.style.display = visible ? '' : 'none';
      if (visible) anyVisible = true;
    });
    section.style.display = anyVisible ? '' : 'none';
  });
}

search.addEventListener('input', applyFilters);
sevBoxes.forEach(b => b.addEventListener('change', applyFilters));
langBoxes.forEach(b => b.addEventListener('change', applyFilters));
"""


def write_html(results: list[ScanResult], target_path: Path, out_path: Path) -> None:
    out_path.write_text(render_html(results, target_path), encoding="utf-8")
