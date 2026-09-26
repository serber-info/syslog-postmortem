from datetime import datetime

import pytest

from syslog_postmortem import collector
from syslog_postmortem.collector import collect_logfile, infer_priority, max_priority


@pytest.mark.parametrize("msg, prio", [
    ("Kernel panic - not syncing", 2),
    ("Out of memory: Killed process 1234 (java)", 2),
    ("connect() failed (111: Connection refused)", 3),
    ("Failed password for invalid user admin from 10.0.0.5", 3),
    ("Invalid user test from 10.0.0.5 port 22", 4),
    ("upstream timed out while reading response", 4),
    ("Started Daily apt download activities.", 6),
])
def test_infer_priority(msg, prio):
    assert infer_priority(msg) == prio


@pytest.mark.parametrize("spec, expected", [("0..4", 4), ("err", 3), ("0..crit", 2), ("6", 6)])
def test_max_priority(spec, expected):
    assert max_priority(spec) == expected


def test_collect_logfile_filters_window_and_priority(tmp_path):
    log = tmp_path / "syslog"
    log.write_text(
        "May 10 13:59:59 web nginx[10]: connect() failed (111: Connection refused)\n"   # before window
        "May 10 14:03:22 web postgres[20]: FATAL: could not connect to database\n"
        "May 10 14:03:23 web CRON[30]: (root) CMD (run-parts /etc/cron.hourly)\n"      # info → dropped
        "2026-05-10T14:05:00.123456+00:00 web sshd[40]: Failed password for root\n"
        "garbage line without timestamp\n"
    )
    since, until = datetime(2026, 5, 10, 14, 0), datetime(2026, 5, 10, 18, 0)
    entries = collect_logfile(str(log), since, until, "syslog", max_prio=4)
    assert [(e.service, e.priority, e.pid) for e in entries[:1]] == [("postgres", 2, 20)]
    assert len(entries) in (1, 2)   # the ISO line depends on the local timezone
    for e in entries:
        assert since <= e.timestamp <= until


def test_syslog_year_rollover(tmp_path):
    log = tmp_path / "syslog"
    log.write_text("Dec 31 23:59:30 h app[1]: error one\nJan  1 00:00:10 h app[1]: error two\n")
    entries = collect_logfile(str(log), datetime(2025, 12, 31, 23, 0), datetime(2026, 1, 1, 1, 0))
    assert [e.timestamp.year for e in entries] == [2025, 2026]


def test_iso_offsets_are_converted():
    ts = collector._parse_iso_ts("2026-05-10T14:03:22+00:00")
    expected = datetime(2026, 5, 10, 14, 3, 22).replace(tzinfo=__import__("datetime").timezone.utc)
    assert ts == expected.astimezone().replace(tzinfo=None)


def test_journal_entries_attributed_to_unit(monkeypatch):
    out = "\n".join([
        '{"__REALTIME_TIMESTAMP":"1778421802000000","_SYSTEMD_UNIT":"init.scope","UNIT":"nginx.service",'
        '"PRIORITY":"3","MESSAGE":"Failed to start nginx.service."}',
        '{"__REALTIME_TIMESTAMP":"1778421803000000","_TRANSPORT":"kernel","SYSLOG_IDENTIFIER":"kernel",'
        '"PRIORITY":"2","MESSAGE":[79,79,77]}',
        'not json',
    ])

    class R:
        stdout = out
    monkeypatch.setattr(collector.subprocess, "run", lambda *a, **k: R())
    monkeypatch.setattr(collector, "_journal_readable", lambda: True)
    entries, warnings = collector.collect_journalctl(datetime(2026, 1, 1), datetime(2026, 12, 31))
    assert [(e.service, e.priority, e.message) for e in entries] == [
        ("nginx", 3, "Failed to start nginx.service."), ("kernel", 2, "OOM")]
    assert warnings == []


def test_missing_journalctl_is_a_warning(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError
    monkeypatch.setattr(collector.subprocess, "run", boom)
    entries, warnings = collector.collect_journalctl(datetime(2026, 1, 1), datetime(2026, 1, 2))
    assert entries == [] and "journalctl not found" in warnings[0]
