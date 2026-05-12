"""
Log collection from journalctl (primary) and /var/log files (fallback/supplement).
"""
import json
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class RawEntry:
    timestamp: datetime
    service: str
    priority: int       # syslog priority 0-7 (0=emerg, 7=debug)
    message: str
    source: str         # 'journald' | 'syslog' | 'auth' | 'dmesg'
    hostname: str = ''
    pid: Optional[int] = None


# ── Priority helpers ──────────────────────────────────────────────────────────

PRIORITY_MAP = {
    0: 'CRITICAL', 1: 'CRITICAL', 2: 'CRITICAL',
    3: 'ERROR',
    4: 'WARNING',
    5: 'INFO', 6: 'INFO', 7: 'DEBUG',
}


def priority_to_severity(p: int) -> str:
    return PRIORITY_MAP.get(p, 'INFO')


# ── journalctl ────────────────────────────────────────────────────────────────

def collect_journalctl(since: str, until: str,
                       units: List[str] = None,
                       priorities: str = '0..4') -> List[RawEntry]:
    """
    Collect entries from systemd journal.
    `priorities` controls syslog priority filter (default: emerg..warning).
    Returns an empty list if journalctl is unavailable.
    """
    cmd = [
        'journalctl',
        '--since', since,
        '--until', until,
        '--output', 'json',
        '--no-pager',
        '--priority', priorities,
    ]
    if units:
        for u in units:
            cmd += ['-u', u]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    entries = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue

        ts_us = int(obj.get('__REALTIME_TIMESTAMP', 0))
        if not ts_us:
            continue

        ts = datetime.fromtimestamp(ts_us / 1_000_000)
        service = (obj.get('_SYSTEMD_UNIT') or
                   obj.get('SYSLOG_IDENTIFIER') or
                   obj.get('_COMM') or 'unknown')
        service = service.removesuffix('.service')

        priority = int(obj.get('PRIORITY', 6))
        message = obj.get('MESSAGE', '')
        if isinstance(message, list):
            message = ' '.join(str(b) for b in message)

        pid_raw = obj.get('_PID')
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None

        entries.append(RawEntry(
            timestamp=ts,
            service=service,
            priority=priority,
            message=str(message).strip(),
            source='journald',
            hostname=obj.get('_HOSTNAME', ''),
            pid=pid,
        ))

    return entries


# ── /var/log file parsers ─────────────────────────────────────────────────────

# Standard syslog line: "May 10 14:03:22 host service[pid]: message"
_SYSLOG_RE = re.compile(
    r'^(\w{3}\s+\d+\s[\d:]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
)

# ISO timestamp variant: "2026-05-10T14:03:22.123456+00:00 host service: msg"
_ISO_SYSLOG_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2}T[\d:.+]+)\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s+(.*)'
)


def _parse_syslog_ts(ts_str: str, year: int) -> Optional[datetime]:
    ts_str = ts_str.strip()
    for fmt in ('%b %d %H:%M:%S', '%b  %d %H:%M:%S'):
        try:
            dt = datetime.strptime(ts_str, fmt).replace(year=year)
            return dt
        except ValueError:
            continue
    return None


def _parse_iso_ts(ts_str: str) -> Optional[datetime]:
    ts_str = re.sub(r'([+-]\d{2}:\d{2})$', '', ts_str)
    for fmt in ('%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(ts_str, fmt)
        except ValueError:
            continue
    return None


def collect_logfile(path: str, since: datetime, until: datetime,
                    source_label: str = 'syslog',
                    default_priority: int = 3) -> List[RawEntry]:
    """Parse a /var/log-style file and return entries in [since, until]."""
    p = Path(path)
    if not p.exists() or not p.is_file():
        return []

    entries = []
    year = since.year

    try:
        with open(p, 'r', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n')
                ts = None
                service = source_label
                message = line
                pid = None
                hostname = ''

                m = _SYSLOG_RE.match(line)
                if m:
                    ts = _parse_syslog_ts(m.group(1), year)
                    hostname = m.group(2)
                    service = m.group(3)
                    pid = int(m.group(4)) if m.group(4) else None
                    message = m.group(5)
                else:
                    m = _ISO_SYSLOG_RE.match(line)
                    if m:
                        ts = _parse_iso_ts(m.group(1))
                        hostname = m.group(2)
                        service = m.group(3)
                        pid = int(m.group(4)) if m.group(4) else None
                        message = m.group(5)

                if ts is None or not (since <= ts <= until):
                    continue

                entries.append(RawEntry(
                    timestamp=ts,
                    service=service,
                    priority=default_priority,
                    message=message.strip(),
                    source=source_label,
                    hostname=hostname,
                    pid=pid,
                ))
    except PermissionError:
        pass

    return entries


# ── Main collection entry point ───────────────────────────────────────────────

def collect_all(since: str, until: str,
                units: List[str] = None,
                include_files: bool = True,
                priorities: str = '0..4') -> List[RawEntry]:
    """
    Collect from journalctl and optionally from /var/log files.
    Returns a merged, time-sorted list of RawEntry.
    """
    since_dt = datetime.strptime(since, '%Y-%m-%d %H:%M')
    until_dt = datetime.strptime(until, '%Y-%m-%d %H:%M')

    entries = collect_journalctl(since, until, units, priorities)

    if include_files:
        log_files = [
            ('/var/log/syslog',    'syslog',   4),
            ('/var/log/messages',  'syslog',   4),
            ('/var/log/auth.log',  'auth',     4),
            ('/var/log/secure',    'auth',     4),
            ('/var/log/kern.log',  'kernel',   3),
            ('/var/log/dmesg',     'kernel',   3),
        ]
        seen_msgs: set = {e.message for e in entries}
        for path, label, prio in log_files:
            for entry in collect_logfile(path, since_dt, until_dt, label, prio):
                if entry.message not in seen_msgs:
                    entries.append(entry)
                    seen_msgs.add(entry.message)

    return sorted(entries, key=lambda e: e.timestamp)
