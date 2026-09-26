#!/usr/bin/env python3
"""
postmortem — generate a structured postmortem draft from system logs.
"""
import argparse
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from shellcolorize import Color

from . import __version__
from .analyzer import analyze
from .collector import collect_all
from .renderer import render_html, render_markdown

_FORMATS = ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M')
_DURATION_RE = re.compile(r'^(\d+)\s*([smhd])$')


# Status messages go to stderr so `-o -` can stream the report on stdout.
def _say(msg: str = '') -> None: print(msg, file=sys.stderr)
def _step(msg: str) -> None: _say(f"  {Color.CYAN}▶{Color.RESET}  {msg}")
def _ok(msg: str) -> None: _say(f"  {Color.GREEN}✔{Color.RESET}  {msg}")
def _warn(msg: str) -> None: _say(f"  {Color.YELLOW}⚠{Color.RESET}  {msg}")
def _err(msg: str) -> None: _say(f"  {Color.RED}✖{Color.RESET}  {msg}")


def _header() -> None:
    title = 'syslog-postmortem'
    w = len(title) + 4
    _say()
    _say(f"  {Color.CYAN}╔{'═' * w}╗{Color.RESET}")
    _say(f"  {Color.CYAN}║{Color.RESET}  {Color.BOLD}{Color.CYAN}{title}{Color.RESET}  {Color.CYAN}║{Color.RESET}")
    _say(f"  {Color.CYAN}╚{'═' * w}╝{Color.RESET}")
    _say()


def parse_datetime(text: str) -> datetime:
    for fmt in _FORMATS:
        try:
            return datetime.strptime(text.strip(), fmt)
        except ValueError:
            continue
    raise ValueError(f'invalid date "{text}" — use "YYYY-MM-DD HH:MM[:SS]"')


def parse_duration(text: str) -> timedelta:
    m = _DURATION_RE.match(text.strip().lower())
    if not m:
        raise ValueError(f'invalid duration "{text}" — use e.g. 30m, 2h, 1d')
    unit = {'s': 'seconds', 'm': 'minutes', 'h': 'hours', 'd': 'days'}[m.group(2)]
    return timedelta(**{unit: int(m.group(1))})


def resolve_window(since: Optional[str], until: Optional[str], last: Optional[str],
                   now: Optional[datetime] = None) -> tuple:
    """(since, until) from --from/--to or --last. Raises ValueError with a user-facing message."""
    now = now or datetime.now().replace(microsecond=0)
    if last:
        if since:
            raise ValueError('use either --last or --from/--to, not both')
        end = parse_datetime(until) if until else now
        return end - parse_duration(last), end
    if not since:
        raise ValueError('--from (or --last) is required')
    start = parse_datetime(since)
    end = parse_datetime(until) if until else now
    if end <= start:
        raise ValueError('--to must be after --from')
    return start, end


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='postmortem',
        description='Generate a structured postmortem draft from system logs.',
        epilog='examples:  postmortem --last 2h   ·   postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00" --services nginx,postgresql',
    )
    p.add_argument('--from', dest='since', metavar='DATETIME',
                   help='Start of the incident window, e.g. "2026-05-10 14:00"')
    p.add_argument('--to', dest='until', metavar='DATETIME',
                   help='End of the incident window (default: now)')
    p.add_argument('--last', metavar='DURATION',
                   help='Window ending now (or at --to): 30m, 2h, 1d')
    p.add_argument('--title', help='Postmortem title (default: "Incident YYYY-MM-DD")')
    p.add_argument('--services', help='Comma-separated services to focus on, e.g. nginx,postgresql')
    p.add_argument('--output', '-o',
                   help='Output file (default: postmortem_YYYYMMDD_HHMM.md/.html; "-" for stdout)')
    p.add_argument('--format', choices=['markdown', 'html'], default='markdown',
                   help='Output format (default: markdown)')
    p.add_argument('--no-files', action='store_true', help='Skip /var/log files, use journalctl only')
    p.add_argument('--priorities', default='0..4',
                   help='journalctl priority filter (default: 0..4 = emerg..warning)')
    p.add_argument('-v', '--version', action='version', version=f'postmortem {__version__}')
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    Color.auto(sys.stderr)

    try:
        since, until = resolve_window(args.since, args.until, args.last)
    except ValueError as e:
        _err(str(e))
        sys.exit(2)
    if until - since > timedelta(hours=72):
        _warn('Window is longer than 72 hours — the report may be very large')

    _header()
    services = [s.strip() for s in args.services.split(',') if s.strip()] if args.services else None
    title = args.title or f"Incident {since.strftime('%Y-%m-%d')}"
    ext = 'html' if args.format == 'html' else 'md'
    output = args.output or f"postmortem_{since.strftime('%Y%m%d_%H%M')}.{ext}"

    _say(f"  {Color.DIM}Window  : {since} → {until}{Color.RESET}")
    _say(f"  {Color.DIM}Services: {', '.join(services) if services else 'all'}{Color.RESET}")
    _say(f"  {Color.DIM}Output  : {'stdout' if output == '-' else output}{Color.RESET}")
    _say()

    _step('Collecting logs...')
    collected = collect_all(since, until, units=services, include_files=not args.no_files,
                            priorities=args.priorities)
    for w in collected.warnings:
        _warn(w)
    if not collected.entries:
        _warn('No log entries found in the specified window.')
        sys.exit(0)
    _ok(f"Collected {len(collected.entries):,} raw entries")

    _step('Analysing patterns...')
    result = analyze(collected.entries, services_filter=services)
    _ok(f"Found {len(result.timeline):,} unique events across {len(result.by_service)} services")
    sev_summary = ', '.join(f"{sev}: {len(result.by_severity[sev])}"
                            for sev in ('CRITICAL', 'ERROR', 'WARNING') if result.by_severity.get(sev))
    if sev_summary:
        _say(f"  {Color.DIM}  → {sev_summary}{Color.RESET}")

    _step(f'Generating {args.format} postmortem...')
    md = render_markdown(result, title, since, until, services)
    text = render_html(md, title) if args.format == 'html' else md

    if output == '-':
        sys.stdout.write(text)
    else:
        try:
            Path(output).write_text(text, encoding='utf-8')
        except OSError as e:
            _err(f'Cannot write {output}: {e.strerror}')
            sys.exit(2)
        _ok(f"Postmortem saved to {Color.BOLD}{output}{Color.RESET}")

    _say()
    if result.first_anomaly:
        _say(f"  {Color.DIM}First anomaly : {result.first_anomaly.timestamp.strftime('%H:%M:%S')} — "
             f"{result.first_anomaly.service}{Color.RESET}")
    if result.services_affected:
        _say(f"  {Color.DIM}Affected      : {', '.join(result.services_affected)}{Color.RESET}")
    if result.action_items:
        _say(f"  {Color.DIM}Action items  : {len(result.action_items)} generated{Color.RESET}")
    _say()


if __name__ == '__main__':
    main()
