#!/usr/bin/env python3
import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path
from shellcolorize import Color

from .collector import collect_all
from .analyzer import analyze
from .renderer import render_markdown, render_html

VERSION = "1.0.0"


def _header() -> None:
    title = 'syslog-postmortem'
    w = len(title) + 6
    print()
    print(f"  {Color.CYAN}╔{'═' * w}╗{Color.RESET}")
    print(f"  {Color.CYAN}║{Color.RESET}  {Color.BOLD}{Color.CYAN}{title}{Color.RESET}  {Color.CYAN}║{Color.RESET}")
    print(f"  {Color.CYAN}╚{'═' * w}╝{Color.RESET}")
    print()


def _step(msg: str) -> None:
    print(f"  {Color.CYAN}▶{Color.RESET}  {msg}")


def _ok(msg: str) -> None:
    print(f"  {Color.GREEN}✔{Color.RESET}  {msg}")


def _warn(msg: str) -> None:
    print(f"  {Color.YELLOW}⚠{Color.RESET}  {msg}")


def _err(msg: str) -> None:
    print(f"  {Color.RED}✖{Color.RESET}  {msg}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='postmortem',
        description='Generate a structured postmortem draft from system logs.',
    )
    parser.add_argument('--from', dest='since', required=True,
                        metavar='DATETIME',
                        help='Start of incident window, e.g. "2026-05-10 14:00"')
    parser.add_argument('--to', dest='until', required=True,
                        metavar='DATETIME',
                        help='End of incident window, e.g. "2026-05-10 16:00"')
    parser.add_argument('--title', default=None,
                        help='Postmortem title (default: auto-generated)')
    parser.add_argument('--services', default=None,
                        help='Comma-separated list of services to focus on, e.g. nginx,postgresql')
    parser.add_argument('--output', '-o', default=None,
                        help='Output file path (default: postmortem_YYYYMMDD_HHMM.md)')
    parser.add_argument('--format', choices=['markdown', 'html'], default='markdown',
                        help='Output format (default: markdown)')
    parser.add_argument('--no-files', action='store_true',
                        help='Skip /var/log file parsing, use journalctl only')
    parser.add_argument('--priorities', default='0..4',
                        help='journalctl priority filter (default: 0..4 = emerg..warning)')
    parser.add_argument('-v', '--version', action='version', version=f'postmortem {VERSION}')
    args = parser.parse_args()

    # ── Validate timestamps ────────────────────────────────────────────────────
    fmt = '%Y-%m-%d %H:%M'
    try:
        since_dt = datetime.strptime(args.since, fmt)
        until_dt = datetime.strptime(args.until, fmt)
    except ValueError:
        _err('Dates must be in format "YYYY-MM-DD HH:MM"')
        sys.exit(1)

    if until_dt <= since_dt:
        _err('--to must be after --from')
        sys.exit(1)

    if (until_dt - since_dt) > timedelta(hours=72):
        _warn('Window is > 72 hours — this may produce a very large report')

    # ── Setup ──────────────────────────────────────────────────────────────────
    _header()

    services = [s.strip() for s in args.services.split(',')] if args.services else None
    title = args.title or f"Incident {since_dt.strftime('%Y-%m-%d')}"

    ext = 'html' if args.format == 'html' else 'md'
    output_path = args.output or f"postmortem_{since_dt.strftime('%Y%m%d_%H%M')}.{ext}"

    print(f"  {Color.DIM}Window  : {args.since} → {args.until}{Color.RESET}")
    print(f"  {Color.DIM}Services: {', '.join(services) if services else 'all'}{Color.RESET}")
    print(f"  {Color.DIM}Output  : {output_path}{Color.RESET}")
    print()

    # ── Collect ────────────────────────────────────────────────────────────────
    _step('Collecting logs...')
    raw = collect_all(
        since=args.since,
        until=args.until,
        units=services,
        include_files=not args.no_files,
        priorities=args.priorities,
    )

    if not raw:
        _warn('No log entries found in the specified window.')
        _warn('Check that journalctl is available and the time window is correct.')
        sys.exit(0)

    _ok(f"Collected {len(raw)} raw entries")

    # ── Analyse ────────────────────────────────────────────────────────────────
    _step('Analysing patterns...')
    result = analyze(raw, services_filter=services)
    _ok(f"Found {len(result.timeline)} unique events across "
        f"{len(result.by_service)} services")

    sev_summary = ', '.join(
        f"{sev}: {len(result.by_severity[sev])}"
        for sev in ['CRITICAL', 'ERROR', 'WARNING']
        if result.by_severity.get(sev)
    )
    if sev_summary:
        print(f"  {Color.DIM}  → {sev_summary}{Color.RESET}")

    if result.contributing_factors:
        _ok(f"Detected {len(result.contributing_factors)} contributing factor(s)")

    # ── Render ─────────────────────────────────────────────────────────────────
    _step(f'Generating {args.format} postmortem...')
    md = render_markdown(result, title, args.since, args.until, services)

    if args.format == 'html':
        output = render_html(md, title)
    else:
        output = md

    Path(output_path).write_text(output, encoding='utf-8')
    _ok(f"Postmortem saved to {Color.BOLD}{output_path}{Color.RESET}")

    # ── Quick summary ──────────────────────────────────────────────────────────
    print()
    if result.first_anomaly:
        print(f"  {Color.DIM}First anomaly : "
              f"{result.first_anomaly.timestamp.strftime('%H:%M:%S')} — "
              f"{result.first_anomaly.service}{Color.RESET}")
    if result.services_affected:
        print(f"  {Color.DIM}Affected      : {', '.join(result.services_affected)}{Color.RESET}")
    if result.action_items:
        print(f"  {Color.DIM}Action items  : {len(result.action_items)} generated{Color.RESET}")
    print()


if __name__ == '__main__':
    main()
