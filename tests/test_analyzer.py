from datetime import datetime, timedelta

from syslog_postmortem.analyzer import analyze, service_matches
from syslog_postmortem.collector import RawEntry
from syslog_postmortem.patterns import match_patterns

T0 = datetime(2026, 5, 10, 14, 0, 0)


def entry(sec, service, prio, msg):
    return RawEntry(timestamp=T0 + timedelta(seconds=sec), service=service, priority=prio,
                    message=msg, source="journald")


def test_patterns():
    assert [p.name for p in match_patterns("load average: 0.15, 0.10, 0.05")] == []
    assert "high_load" in [p.name for p in match_patterns("load average: 14.02, 9.1, 4.0")]
    assert "kernel_oops" in [p.name for p in match_patterns("BUG: unable to handle page fault")]
    assert "oom" in [p.name for p in match_patterns("Out of memory: Killed process 42 (java)")]


def test_service_matches_templates():
    assert service_matches("postgresql@14-main", ["postgresql"])
    assert service_matches("nginx", ["nginx"])
    assert not service_matches("nginx-exporter-extra", ["redis"])


def test_repeated_messages_are_grouped():
    raw = [entry(i * 120, "backup", 3, "Failed to start backup.") for i in range(10)]
    raw.append(entry(5000, "backup", 3, "Failed to start backup."))   # gap > 5 min: new group
    result = analyze(raw)
    assert [e.count for e in result.timeline] == [10, 1]
    assert result.timeline[0].last_timestamp == T0 + timedelta(seconds=9 * 120)


def test_cascade_detection_one_line_per_pair():
    raw = [entry(0, "postgresql", 2, "could not connect to database: out of memory"),
           entry(1, "postgresql", 2, "PANIC: out of memory again"),
           entry(20, "nginx", 3, "upstream connect error"),
           entry(25, "nginx", 3, "upstream connect error or disconnect")]
    result = analyze(raw)
    cascades = [f for f in result.contributing_factors if "Cascading" in f]
    assert len(cascades) == 1 and "`nginx` errors began **20s**" in cascades[0]


def test_auth_burst_and_actions():
    raw = [entry(i, "sshd", 6, f"Failed password for invalid user u{i} from 10.0.0.9") for i in range(6)]
    result = analyze(raw)
    assert any("Auth anomaly" in f for f in result.contributing_factors)
    assert result.action_items


def test_services_filter():
    raw = [entry(0, "nginx", 3, "boom"), entry(1, "redis", 3, "boom")]
    assert set(analyze(raw, services_filter=["NGINX"]).by_service) == {"nginx"}


def test_severity_upgraded_by_pattern():
    result = analyze([entry(0, "kernel", 6, "Out of memory: Killed process 42")])
    assert result.timeline[0].severity == "CRITICAL"


def test_messages_differing_only_by_port_are_grouped_but_not_by_ip():
    raw = [entry(i, "sshd", 4, f"Failed password for admin from 203.0.113.7 port {40000 + i}") for i in range(5)]
    raw.append(entry(10, "sshd", 4, "Failed password for admin from 198.51.100.9 port 40100"))
    result = analyze(raw)
    assert [e.count for e in result.timeline] == [5, 1]


def test_restart_loop_counts_occurrences():
    raw = [entry(i * 20, "postgresql", 4, "start request repeated too quickly") for i in range(4)]
    factors = analyze(raw).contributing_factors
    assert any("restart-loop detection **4 time(s)**" in f for f in factors)
