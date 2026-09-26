"""
Render an AnalysisResult to Markdown or HTML.

Log content is untrusted (an SSH login attempt can put arbitrary text in auth.log),
so every piece of log text is escaped: backslash escapes in Markdown, and the HTML
converter escapes everything before applying the small Markdown subset we emit.
"""
import html
import re
from datetime import datetime
from typing import List, Optional

from . import __version__
from .analyzer import AnalysisResult, Event
from .patterns import PATTERNS

_SEV_ICON = {
    'CRITICAL': '⛔',
    'ERROR':    '🔴',
    'WARNING':  '⚠️',
    'INFO':     'ℹ️',
    'DEBUG':    '🔵',
}
_SEV_ORDER = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']
_TIMELINE_LIMIT = 50

# ── Escaping ──────────────────────────────────────────────────────────────────

_MD_SPECIAL = re.compile(r'([\\`*_\[\]<>|#~])')


def md_text(s: str, limit: Optional[int] = None) -> str:
    """Untrusted text → Markdown that renders literally (one line, no HTML, no formatting)."""
    s = ' '.join(str(s).split())
    if limit and len(s) > limit:
        s = s[:limit - 1] + '…'
    return _MD_SPECIAL.sub(r'\\\1', s)


def md_code(s: str) -> str:
    """Untrusted identifier (service name) → inline code span."""
    return '`' + str(s).replace('`', "'").replace('|', '\\|') + '`'

# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(dt: datetime) -> str:
    return dt.strftime('%H:%M:%S')


def _duration(since: datetime, until: datetime) -> str:
    h, rem = divmod(int((until - since).total_seconds()), 3600)
    m = rem // 60
    parts = [f"{h}h"] if h else []
    if m:
        parts.append(f"{m}m")
    return ' '.join(parts) or '< 1m'


def _repeat(ev: Event) -> str:
    """' _(×12, until 10:55:02)_' for repeated events."""
    if ev.count <= 1:
        return ''
    until = f", until {_ts(ev.last_timestamp)}" if ev.last_timestamp else ''
    return f" _(×{ev.count}{until})_"


def _overall_severity(result: AnalysisResult) -> str:
    if result.by_severity.get('CRITICAL'):
        return 'Critical'
    if result.by_severity.get('ERROR'):
        return 'High'
    if result.by_severity.get('WARNING'):
        return 'Medium'
    return 'Low'


def _timeline_events(result: AnalysisResult) -> List[Event]:
    """Warnings and above; when there are too many, keep the most severe, in time order."""
    events = [e for e in result.timeline if e.severity in ('CRITICAL', 'ERROR', 'WARNING')]
    if len(events) <= _TIMELINE_LIMIT:
        return events
    rank = {s: i for i, s in enumerate(_SEV_ORDER)}
    keep = sorted(events, key=lambda e: (rank[e.severity], e.timestamp))[:_TIMELINE_LIMIT]
    return sorted(keep, key=lambda e: e.timestamp)

# ── Markdown renderer ─────────────────────────────────────────────────────────

def render_markdown(result: AnalysisResult, title: str, since: datetime, until: datetime,
                    services: Optional[list] = None) -> str:
    fmt = '%Y-%m-%d %H:%M'
    affected = ', '.join(md_code(s) for s in result.services_affected) or '_none detected_'
    lines = [
        f"# Postmortem: {md_text(title)}",
        "",
        "| | |",
        "|---|---|",
        f"| **Date** | {since.strftime('%Y-%m-%d')} |",
        f"| **Window** | {since.strftime(fmt)} → {until.strftime(fmt)} |",
        f"| **Duration** | {_duration(since, until)} |",
        f"| **Severity** | {_overall_severity(result)} |",
        "| **Status** | Draft |",
        f"| **Services analysed** | {', '.join(md_code(s) for s in services) if services else 'all'} |",
        f"| **Services affected** | {affected} |",
        "",
        "---",
        "",
    ]

    # ── Summary
    summary = [f"Analysis of **{result.total_raw:,} raw log entries** "
               f"({len(result.timeline):,} unique events after deduplication) "
               f"across **{len(result.by_service)} services**."]
    if result.first_anomaly:
        fa = result.first_anomaly
        summary.append(f"First anomaly detected at **{_ts(fa.timestamp)}** in {md_code(fa.service)} ({fa.severity}).")
    if result.peak_window:
        summary.append(f"Highest error density at **{result.peak_window.strftime('%H:%M')}**.")
    lines += ["## Summary", "", ' '.join(summary), "",
              "> *Auto-generated draft — review all sections before sharing.*", "", "---", ""]

    # ── Timeline
    lines += ["## Timeline", ""]
    show = _timeline_events(result)
    if show:
        lines += ["| Time | Service | Severity | Event |", "|------|---------|----------|-------|"]
        for ev in show:
            cnt = _repeat(ev)
            lines.append(f"| {_ts(ev.timestamp)} | {md_code(ev.service)} | "
                         f"{_SEV_ICON.get(ev.severity, '')} {ev.severity} | {md_text(ev.message, 140)}{cnt} |")
        total = sum(1 for e in result.timeline if e.severity in ('CRITICAL', 'ERROR', 'WARNING'))
        if total > len(show):
            lines += ["", f"_Showing the {len(show)} most severe of {total} events. "
                          "The full list is in the sections below._"]
    else:
        lines.append("_No warnings or errors found in the specified window._")
    lines += ["", "---", ""]

    # ── Events by severity
    lines += ["## Events by Severity", ""]
    for sev in _SEV_ORDER:
        evs = result.by_severity.get(sev, [])
        if not evs:
            continue
        lines += [f"### {_SEV_ICON.get(sev, '')} {sev} ({len(evs)} event{'s' if len(evs) != 1 else ''})", ""]
        for ev in evs[:30]:
            cnt = _repeat(ev)
            pats = f" `[{', '.join(p.label for p in ev.patterns)}]`" if ev.patterns else ""
            lines.append(f"- `[{_ts(ev.timestamp)}]` {md_code(ev.service)} — {md_text(ev.message, 160)}{cnt}{pats}")
        if len(evs) > 30:
            lines += ["", f"_...and {len(evs) - 30} more {sev} events._"]
        lines.append("")
    lines += ["---", ""]

    # ── Pattern analysis
    if result.pattern_counts:
        lines += ["## Pattern Analysis", "",
                  "| Pattern | Occurrences | Affected services |",
                  "|---------|-------------|-------------------|"]
        labels = {p.name: p.label for p in PATTERNS}
        for name, count in sorted(result.pattern_counts.items(), key=lambda x: -x[1]):
            svcs = sorted({e.service for e in result.timeline if any(p.name == name for p in e.patterns)})
            svc_str = ', '.join(md_code(s) for s in svcs[:5]) + (f' +{len(svcs) - 5} more' if len(svcs) > 5 else '')
            lines.append(f"| {labels.get(name, name)} | {count} | {svc_str} |")
        lines += ["", "---", ""]

    # ── Contributing factors
    lines += ["## Contributing Factors", "",
              "> *Auto-detected from log patterns — verify each before including in final report.*", ""]
    lines += [f"- {f}" for f in result.contributing_factors]
    lines += ["", "---", ""]

    # ── Manual sections
    lines += [
        "## Impact Assessment", "", "<!-- Fill in manually -->", "",
        f"- **Affected services:** {affected}",
        "- **Affected users:** ", "- **Data loss:** ", "- **Downtime:** ", "- **Revenue impact:** ",
        "", "---", "",
        "## Root Cause Analysis", "", "<!-- Fill in manually after investigation -->", "",
        "### What happened?", "", "### Why did it happen?", "", "### Why wasn't it caught earlier?", "",
        "---", "",
        "## Action Items", "",
    ]
    if result.action_items:
        lines += ["_Generated from detected patterns — assign owner and priority._", ""]
        lines += [f"- [ ] {item}" for item in result.action_items]
    else:
        lines.append("- [ ] ")
    lines += [
        "", "---", "",
        "## Lessons Learned", "", "<!-- Fill in manually -->", "", "---", "",
        f"*Generated by [syslog-postmortem](https://github.com/serber-info/syslog-postmortem) "
        f"v{__version__} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
    ]
    return '\n'.join(lines) + '\n'

# ── HTML renderer ─────────────────────────────────────────────────────────────

_CSS = """
    :root { color-scheme: light dark; --fg: #24292e; --bg: #fff; --muted: #6a737d; --line: #e1e4e8; --soft: #f6f8fa; }
    @media (prefers-color-scheme: dark) {
      :root { --fg: #e6edf3; --bg: #0d1117; --muted: #8b949e; --line: #30363d; --soft: #161b22; }
    }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; line-height: 1.5;
           max-width: 1000px; margin: 40px auto; padding: 0 20px; color: var(--fg); background: var(--bg); }
    h1 { border-bottom: 2px solid var(--line); padding-bottom: 12px; }
    h2 { border-bottom: 1px solid var(--line); padding-bottom: 8px; margin-top: 32px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; display: block; overflow-x: auto; }
    th { background: var(--soft); text-align: left; }
    th, td { border: 1px solid var(--line); padding: 6px 12px; font-size: 14px; vertical-align: top; }
    tr:nth-child(even) td { background: var(--soft); }
    code { background: var(--soft); border-radius: 3px; padding: 1px 5px; font-size: 90%; }
    blockquote { border-left: 4px solid var(--line); margin: 0; padding: 4px 16px; color: var(--muted); }
    hr { border: 0; border-top: 1px solid var(--line); margin: 24px 0; }
    ul { padding-left: 24px; } li { margin: 4px 0; } li.task { list-style: none; margin-left: -20px; }
"""

_INLINE = [
    (re.compile(r'(?<!\\)`(.+?)(?<!\\)`'), r'<code>\1</code>'),
    (re.compile(r'(?<!\\)\*\*(.+?)(?<!\\)\*\*'), r'<strong>\1</strong>'),
    (re.compile(r'(?<![\\\w])\*(.+?)(?<!\\)\*(?!\w)'), r'<em>\1</em>'),
    (re.compile(r'(?<![\\\w])_(.+?)(?<!\\)_(?!\w)'), r'<em>\1</em>'),
    (re.compile(r'\[([^\]]+)\]\((https?://[^)\s]+)\)'), r'<a href="\2">\1</a>'),
]
_UNESCAPE = re.compile(r'\\([\\`*_\[\]|#~]|&lt;|&gt;)')


def _inline(text: str) -> str:
    """Escape first, then apply inline Markdown, then drop backslash escapes."""
    out = html.escape(text, quote=False)
    for regex, repl in _INLINE:
        out = regex.sub(repl, out)
    return _UNESCAPE.sub(r'\1', out)


def _cells(row: str) -> List[str]:
    return [c.strip() for c in re.split(r'(?<!\\)\|', row.strip().strip('|'))]


def markdown_to_html(md: str) -> str:
    """Convert the Markdown subset produced by render_markdown into safe HTML."""
    out: List[str] = []
    lines = md.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.fullmatch(r'<!--[^<>]*-->', line):          # our own "fill in" hints
            out.append(line)
        elif line.startswith('#'):
            level = len(line) - len(line.lstrip('#'))
            out.append(f"<h{level}>{_inline(line[level:].strip())}</h{level}>")
        elif line == '---':
            out.append('<hr>')
        elif line.startswith('> '):
            out.append(f"<blockquote>{_inline(line[2:])}</blockquote>")
        elif line.startswith('|'):
            rows = []
            while i < len(lines) and lines[i].startswith('|'):
                rows.append(lines[i])
                i += 1
            header, body = _cells(rows[0]), [r for r in rows[1:] if not re.fullmatch(r'[|\s:-]+', r)]
            table = ['<table>', '<thead><tr>' + ''.join(f'<th>{_inline(c)}</th>' for c in header) + '</tr></thead>',
                     '<tbody>']
            table += ['<tr>' + ''.join(f'<td>{_inline(c)}</td>' for c in _cells(r)) + '</tr>' for r in body]
            out += table + ['</tbody>', '</table>']
            continue
        elif line.startswith('- '):
            items = []
            while i < len(lines) and lines[i].startswith('- '):
                item = lines[i][2:]
                if item.startswith('[ ] '):
                    items.append(f'<li class="task">☐ {_inline(item[4:])}</li>')
                else:
                    items.append(f'<li>{_inline(item)}</li>')
                i += 1
            out += ['<ul>'] + items + ['</ul>']
            continue
        elif line.strip():
            out.append(f"<p>{_inline(line)}</p>")
        i += 1
    return '\n'.join(out)


def render_html(md: str, title: str) -> str:
    """Standalone HTML page (inline CSS, light/dark) for the Markdown report."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
  <title>Postmortem: {html.escape(title)}</title>
  <style>{_CSS}</style>
</head>
<body>
{markdown_to_html(md)}
</body>
</html>
"""
