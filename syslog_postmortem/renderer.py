"""
Render an AnalysisResult to Markdown or HTML.
"""
from datetime import datetime
from typing import Optional

from .analyzer import AnalysisResult, Event

VERSION = "1.0.0"

_SEV_ICON = {
    'CRITICAL': '⛔',
    'ERROR':    '🔴',
    'WARNING':  '⚠️',
    'INFO':     'ℹ️',
    'DEBUG':    '🔵',
}

_SEV_ORDER = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG']


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(dt: datetime) -> str:
    return dt.strftime('%H:%M:%S')


def _md_escape(s: str) -> str:
    return s.replace('|', '\\|').replace('`', "'")


def _duration(since: str, until: str) -> str:
    fmt = '%Y-%m-%d %H:%M'
    try:
        delta = datetime.strptime(until, fmt) - datetime.strptime(since, fmt)
        h, rem = divmod(int(delta.total_seconds()), 3600)
        m = rem // 60
        parts = []
        if h:
            parts.append(f"{h}h")
        if m:
            parts.append(f"{m}m")
        return ' '.join(parts) or '< 1m'
    except ValueError:
        return 'unknown'


def _overall_severity(result: AnalysisResult) -> str:
    if result.by_severity.get('CRITICAL'):
        return 'Critical'
    if result.by_severity.get('ERROR'):
        return 'High'
    if result.by_severity.get('WARNING'):
        return 'Medium'
    return 'Low'


# ── Markdown renderer ─────────────────────────────────────────────────────────

def render_markdown(result: AnalysisResult, title: str,
                    since: str, until: str,
                    services: Optional[list] = None) -> str:
    lines = []
    date_str = since.split()[0]
    duration = _duration(since, until)
    severity_label = _overall_severity(result)
    affected_str = ', '.join(f'`{s}`' for s in result.services_affected) or '_none detected_'

    # ── Header ─────────────────────────────────────────────────────────────────
    lines += [
        f"# Postmortem: {title}",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Date** | {date_str} |",
        f"| **Window** | {since} → {until} |",
        f"| **Duration** | {duration} |",
        f"| **Severity** | {severity_label} |",
        f"| **Status** | Draft |",
        f"| **Services affected** | {affected_str} |",
        "",
        "---",
        "",
    ]

    # ── Summary ────────────────────────────────────────────────────────────────
    lines += ["## Summary", ""]
    total_errors = len(result.by_severity.get('CRITICAL', [])) + \
                   len(result.by_severity.get('ERROR', []))
    total_events = len(result.timeline)

    summary_parts = [
        f"Analysis of **{result.total_raw} raw log entries** "
        f"({total_events} unique events after deduplication) "
        f"across **{len(result.by_service)} services**."
    ]
    if result.first_anomaly:
        summary_parts.append(
            f"First anomaly detected at **{_ts(result.first_anomaly.timestamp)}** "
            f"in **`{result.first_anomaly.service}`** "
            f"({result.first_anomaly.severity})."
        )
    if result.peak_window:
        summary_parts.append(
            f"Highest error density at **{result.peak_window.strftime('%H:%M')}**."
        )
    lines += [' '.join(summary_parts), "", "> *Auto-generated draft — review all sections before sharing.*", "", "---", ""]

    # ── Timeline ───────────────────────────────────────────────────────────────
    lines += ["## Timeline", ""]
    show = [e for e in result.timeline if e.severity in ('CRITICAL', 'ERROR', 'WARNING')][:50]
    if show:
        lines += [
            "| Time | Service | Severity | Event |",
            "|------|---------|----------|-------|",
        ]
        for ev in show:
            icon = _SEV_ICON.get(ev.severity, '')
            svc = f"`{ev.service}`"
            sev = f"{icon} {ev.severity}"
            msg = _md_escape(ev.message[:100])
            cnt = f" _(×{ev.count})_" if ev.count > 1 else ""
            lines.append(f"| {_ts(ev.timestamp)} | {svc} | {sev} | {msg}{cnt} |")
        if len([e for e in result.timeline if e.severity in ('CRITICAL', 'ERROR', 'WARNING')]) > 50:
            lines.append(f"\n_Table truncated to 50 entries. Full list in error sections below._")
    else:
        lines.append("_No warnings or errors found in the specified window._")
    lines += ["", "---", ""]

    # ── Errors by severity ─────────────────────────────────────────────────────
    lines += ["## Events by Severity", ""]
    for sev in _SEV_ORDER:
        evs = result.by_severity.get(sev, [])
        if not evs:
            continue
        icon = _SEV_ICON.get(sev, '')
        lines += [f"### {icon} {sev} ({len(evs)} event{'s' if len(evs) != 1 else ''})", ""]
        for ev in evs[:30]:
            cnt = f" _(×{ev.count})_" if ev.count > 1 else ""
            patterns = ""
            if ev.patterns:
                patterns = " `[" + ", ".join(p.label for p in ev.patterns) + "]`"
            lines.append(
                f"- `[{_ts(ev.timestamp)}]` **{ev.service}** — "
                f"{_md_escape(ev.message[:120])}{cnt}{patterns}"
            )
        if len(evs) > 30:
            lines.append(f"\n_...and {len(evs) - 30} more {sev} events._")
        lines.append("")
    lines += ["---", ""]

    # ── Pattern summary ────────────────────────────────────────────────────────
    if result.pattern_counts:
        lines += ["## Pattern Analysis", "",
                  "| Pattern | Occurrences | Affected services |",
                  "|---------|-------------|-------------------|"]
        from .patterns import PATTERNS
        pmap = {p.name: p for p in PATTERNS}
        for name, count in sorted(result.pattern_counts.items(), key=lambda x: -x[1]):
            pat = pmap.get(name)
            label = pat.label if pat else name
            svcs = sorted({
                e.service for e in result.timeline
                if any(p.name == name for p in e.patterns)
            })
            svc_str = ', '.join(f'`{s}`' for s in svcs[:5])
            if len(svcs) > 5:
                svc_str += f' +{len(svcs)-5} more'
            lines.append(f"| {label} | {count} | {svc_str} |")
        lines += ["", "---", ""]

    # ── Contributing factors ───────────────────────────────────────────────────
    lines += [
        "## Contributing Factors",
        "",
        "> *Auto-detected from log patterns — verify each before including in final report.*",
        "",
    ]
    for f in result.contributing_factors:
        lines.append(f"- {f}")
    lines += ["", "---", ""]

    # ── Impact ─────────────────────────────────────────────────────────────────
    lines += [
        "## Impact Assessment",
        "",
        "<!-- Fill in manually -->",
        "",
        f"- **Affected services:** {affected_str}",
        "- **Affected users:** ",
        "- **Data loss:** ",
        "- **Downtime:** ",
        "- **Revenue impact:** ",
        "",
        "---",
        "",
    ]

    # ── Root cause ─────────────────────────────────────────────────────────────
    lines += [
        "## Root Cause Analysis",
        "",
        "<!-- Fill in manually after investigation -->",
        "",
        "### What happened?",
        "",
        "### Why did it happen?",
        "",
        "### Why wasn't it caught earlier?",
        "",
        "---",
        "",
    ]

    # ── Action items ───────────────────────────────────────────────────────────
    lines += ["## Action Items", ""]
    if result.action_items:
        lines.append("_Generated from detected patterns — assign owner and priority._")
        lines.append("")
        for item in result.action_items:
            lines.append(f"- [ ] {item}")
    else:
        lines.append("- [ ] ")
    lines += ["", "---", ""]

    # ── Lessons learned ────────────────────────────────────────────────────────
    lines += [
        "## Lessons Learned",
        "",
        "<!-- Fill in manually -->",
        "",
        "---",
        "",
        f"*Generated by [syslog-postmortem](https://github.com/serber-info/syslog-postmortem) "
        f"v{VERSION} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
    ]

    return '\n'.join(lines)


# ── HTML renderer ─────────────────────────────────────────────────────────────

def render_html(md: str, title: str) -> str:
    """Wrap Markdown in a minimal HTML shell with inline CSS."""
    css = """
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
           max-width: 960px; margin: 40px auto; padding: 0 20px; color: #24292e; }
    h1 { border-bottom: 2px solid #e1e4e8; padding-bottom: 12px; }
    h2 { border-bottom: 1px solid #e1e4e8; padding-bottom: 8px; margin-top: 32px; }
    table { border-collapse: collapse; width: 100%; margin: 16px 0; }
    th { background: #f6f8fa; text-align: left; }
    th, td { border: 1px solid #e1e4e8; padding: 8px 12px; font-size: 14px; }
    tr:nth-child(even) { background: #f6f8fa; }
    code { background: #f6f8fa; border-radius: 3px; padding: 2px 5px; font-size: 90%; }
    blockquote { border-left: 4px solid #e1e4e8; margin: 0; padding: 8px 16px; color: #6a737d; }
    pre { background: #f6f8fa; padding: 16px; border-radius: 6px; overflow-x: auto; }
    li { margin: 4px 0; }
    """
    # Minimal Markdown → HTML (just enough for our output)
    import re as _re
    html = md
    html = _re.sub(r'^# (.+)$', r'<h1>\1</h1>', html, flags=_re.M)
    html = _re.sub(r'^## (.+)$', r'<h2>\1</h2>', html, flags=_re.M)
    html = _re.sub(r'^### (.+)$', r'<h3>\1</h3>', html, flags=_re.M)
    html = _re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
    html = _re.sub(r'`(.+?)`', r'<code>\1</code>', html)
    html = _re.sub(r'^- \[ \] (.+)$', r'<li>☐ \1</li>', html, flags=_re.M)
    html = _re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=_re.M)
    html = _re.sub(r'^---$', r'<hr>', html, flags=_re.M)
    html = html.replace('\n', '<br>\n')

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>{css}</style>
</head>
<body>
{html}
</body>
</html>
"""
