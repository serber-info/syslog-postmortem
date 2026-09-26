"""
Log collection from journalctl (primary) and /var/log files (supplement).
"""
import json
import os
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RawEntry:
    timestamp: datetime
    service: str
    priority: int       # syslog priority 0-7 (0=emerg, 7=debug)
    message: str
    source: str         # 'journald' | 'syslog' | 'auth' | 'kernel'
    hostname: str = ''
    pid: Optional[int] = None


@dataclass
class CollectionResult:
    entries: List[RawEntry]
    warnings: List[str]

# ── Priority helpers ──────────────────────────────────────────────────────────

PRIORITY_MAP = {
    0: 'CRITICAL', 1: 'CRITICAL', 2: 'CRITICAL',
    3: 'ERROR',
    4: 'WARNING',
    5: 'INFO', 6: 'INFO', 7: 'DEBUG',
}

_PRIORITY_NAMES = {'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3, 'warning': 4,
                   'notice': 5, 'info': 6, 'debug': 7}


def priority_to_severity(p: int) -> str:
    return PRIORITY_MAP.get(p, 'INFO')


def max_priority(spec: str) -> int:
    """Highest (least severe) syslog priority allowed by a journalctl spec: '0..4' → 4, 'err' → 3."""
    last = spec.split('..')[-1].strip().lower()
    if last.isdigit():
        return int(last)
    return _PRIORITY_NAMES.get(last, 4)


# Plain-text log files carry no priority: infer it from the wording.
_KEYWORD_PRIORITY = [
    (re.compile(r'\b(panic|emerg(ency)?|fatal|critical|crit|oom|out of memory|kernel bug|oops)\b', re.I), 2),
    (re.compile(r'\b(err(or)?s?|fail(ed|ure|s)?|refused|denied|segfault|abort(ed)?|unable|cannot)\b', re.I), 3),
    (re.compile(r'\b(warn(ing)?s?|timed? ?out|retry(ing)?|deprecated|invalid user)\b', re.I), 4),
]


def infer_priority(message: str) -> int:
    for regex, prio in _KEYWORD_PRIORITY:
        if regex.search(message):
            return prio
    return 6

# ── journalctl ────────────────────────────────────────────────────────────────

def _journal_readable() -> bool:
    """Root and members of adm/systemd-journal/wheel can read the whole system journal."""
    if os.geteuid() == 0:
        return True
    try:
        import grp
        names = {grp.getgrgid(g).gr_name for g in os.getgroups()}
    except (ImportError, KeyError):
        return False
    return bool(names & {'adm', 'systemd-journal', 'wheel'})


def collect_journalctl(since: datetime, until: datetime, units: Optional[List[str]] = None,
                       priorities: str = '0..4', timeout: int = 120) -> Tuple[List[RawEntry], List[str]]:
    """Entries from the systemd journal. Returns (entries, warnings)."""
    warnings: List[str] = []
    cmd = ['journalctl', '--since', since.strftime('%Y-%m-%d %H:%M:%S'),
           '--until', until.strftime('%Y-%m-%d %H:%M:%S'),
           '--output', 'json', '--no-pager', '--quiet', '--priority', priorities]
    for u in units or []:
        cmd += ['-u', u if '.' in u or '*' in u else f'{u}*']

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        return [], ['journalctl not found — only /var/log files were analysed']
    except subprocess.TimeoutExpired:
        return [], [f'journalctl did not finish within {timeout}s — try a shorter window or --services']

    if not _journal_readable():
        warnings.append('Not root and not in the adm/systemd-journal group: '
                        'only your own journal entries are visible (run with sudo)')

    entries = []
    for line in result.stdout.splitlines():
        try:
            obj = json.loads(line)
            ts = datetime.fromtimestamp(int(obj['__REALTIME_TIMESTAMP']) / 1_000_000)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError):
            continue

        # systemd (PID 1) logs about other units with UNIT=…; attribute those messages to that unit.
        service = (obj.get('UNIT') or obj.get('USER_UNIT') or obj.get('_SYSTEMD_UNIT')
                   or obj.get('SYSLOG_IDENTIFIER') or obj.get('_COMM') or 'unknown')
        service = service.removesuffix('.service')
        if obj.get('_TRANSPORT') == 'kernel':
            service = 'kernel'

        message = obj.get('MESSAGE', '')
        if isinstance(message, list):   # binary payloads come as byte arrays
            message = bytes(b for b in message if isinstance(b, int) and 0 <= b < 256).decode('utf-8', 'replace')

        try:
            priority = int(obj.get('PRIORITY', 6))
        except (TypeError, ValueError):
            priority = 6
        pid = obj.get('_PID')

        entries.append(RawEntry(
            timestamp=ts, service=service, priority=priority, message=str(message).strip(),
            source='journald', hostname=obj.get('_HOSTNAME', ''),
            pid=int(pid) if str(pid).isdigit() else None,
        ))
    return entries, warnings

# ── /var/log file parsers ─────────────────────────────────────────────────────

# Traditional syslog: "May 10 14:03:22 host service[pid]: message"
_SYSLOG_RE = re.compile(r'^(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.*)')

# RFC 3339 syslog (rsyslog high-precision): "2026-05-10T14:03:22.123456+02:00 host service[pid]: msg"
_ISO_SYSLOG_RE = re.compile(r'^(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s*(.*)')


def _parse_syslog_ts(ts_str: str, since: datetime, until: datetime) -> Optional[datetime]:
    """Syslog timestamps have no year: pick the year that falls inside or closest to the window."""
    ts_str = ' '.join(ts_str.split())
    candidates = []
    for year in sorted({since.year, until.year}):
        try:   # parse with an explicit year (also valid for Feb 29 in leap years)
            candidates.append(datetime.strptime(f'{year} {ts_str}', '%Y %b %d %H:%M:%S'))
        except ValueError:
            continue
    if not candidates:
        return None
    return min(candidates, key=lambda c: 0 if since <= c <= until else min(abs((c - since).total_seconds()),
                                                                          abs((c - until).total_seconds())))


def _parse_iso_ts(ts_str: str) -> Optional[datetime]:
    """RFC 3339 timestamp → naive local time (offsets are converted, not dropped)."""
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


def collect_logfile(path: str, since: datetime, until: datetime, source_label: str = 'syslog',
                    max_prio: int = 4) -> List[RawEntry]:
    """Parse a /var/log-style file and return entries in [since, until] at or above max_prio."""
    p = Path(path)
    if not p.is_file():
        return []
    entries = []
    try:
        with open(p, 'r', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')
                m = _SYSLOG_RE.match(line)
                if m:
                    ts = _parse_syslog_ts(m.group(1), since, until)
                else:
                    m = _ISO_SYSLOG_RE.match(line)
                    ts = _parse_iso_ts(m.group(1)) if m else None
                if ts is None or not (since <= ts <= until):
                    continue
                message = m.group(5).strip()
                priority = infer_priority(message)
                if priority > max_prio:
                    continue
                entries.append(RawEntry(
                    timestamp=ts, service=m.group(3), priority=priority, message=message,
                    source=source_label, hostname=m.group(2),
                    pid=int(m.group(4)) if m.group(4) else None,
                ))
    except OSError:
        pass
    return entries


LOG_FILES = [
    ('/var/log/syslog',   'syslog'),
    ('/var/log/messages', 'syslog'),
    ('/var/log/auth.log', 'auth'),
    ('/var/log/secure',   'auth'),
    ('/var/log/kern.log', 'kernel'),
]

# ── Main collection entry point ───────────────────────────────────────────────

def collect_all(since: datetime, until: datetime, units: Optional[List[str]] = None,
                include_files: bool = True, priorities: str = '0..4') -> CollectionResult:
    """
    Collect from journalctl and optionally from /var/log files (plus their '.1' rotation).
    File lines already present in the journal are skipped. Returns entries sorted by time.
    """
    entries, warnings = collect_journalctl(since, until, units, priorities)

    if include_files:
        seen = {(e.timestamp.replace(microsecond=0), e.message) for e in entries}
        unreadable = []
        prio = max_priority(priorities)
        for path, label in LOG_FILES:
            for candidate in (path, f'{path}.1'):
                if Path(candidate).is_file() and not os.access(candidate, os.R_OK):
                    unreadable.append(candidate)
                    continue
                for entry in collect_logfile(candidate, since, until, label, prio):
                    key = (entry.timestamp.replace(microsecond=0), entry.message)
                    if key not in seen:
                        seen.add(key)
                        entries.append(entry)
        if unreadable:
            warnings.append(f"Cannot read {', '.join(unreadable)} (run with sudo)")

    return CollectionResult(entries=sorted(entries, key=lambda e: e.timestamp), warnings=warnings)
