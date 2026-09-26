# syslog-postmortem

[![CI](https://github.com/serber-info/syslog-postmortem/actions/workflows/ci.yml/badge.svg)](https://github.com/serber-info/syslog-postmortem/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/syslog-postmortem.svg)](https://badge.fury.io/py/syslog-postmortem)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Generate a **structured postmortem draft** from system logs in seconds — no more reconstructing incident
timelines by hand at 3 a.m.

Reads `journalctl` plus `/var/log/syslog`, `messages`, `auth.log`, `secure` and `kern.log`, correlates
events, detects known failure patterns and writes a ready-to-edit Markdown or HTML postmortem.

---

## ✨ What it does

Given a time window (and optionally a list of services), `postmortem`:

1. **Collects** entries from `journalctl` (primary) and `/var/log` files, including their `.1` rotation
2. **Attributes** systemd messages to the unit they are about (not to PID 1)
3. **Groups** repeated messages — `Failed to start backup (×166, until 10:55)` instead of 166 lines
4. **Detects patterns** — OOM kills, disk full, kernel oops, crashes, restart loops, connection errors,
   timeouts, auth bursts, TLS and database errors, high load
5. **Builds a timeline**, keeping the most severe events when there are too many
6. **Finds contributing factors** — cascading failures between services, restart loops, error bursts
7. **Suggests action items** and leaves Impact / Root cause / Lessons learned sections ready to fill in

---

## 📥 Installation

```bash
pip install syslog-postmortem
```

Run it with `sudo` (or as a member of the `adm` / `systemd-journal` group) to read the whole system journal.

---

## 🛠 Usage

```bash
postmortem --last 2h                                   # incident in progress: the last two hours
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00"
```

```bash
# Focus on specific services (postgresql also matches postgresql@14-main)
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00" \
           --services nginx,postgresql,redis \
           --title "Database outage" \
           --output incident-2026-05-10.md

# Standalone HTML page (light/dark theme, safe to open: log content is escaped)
postmortem --last 1d --format html --output report.html

# Print to stdout, e.g. to paste into a ticket
postmortem --last 30m -o - | xclip -selection clipboard
```

---

## 📋 Options

| Option | Description |
|--------|-------------|
| `--from DATETIME` | Start of the window: `"YYYY-MM-DD HH:MM[:SS]"` |
| `--to DATETIME` | End of the window (default: now) |
| `--last DURATION` | Window ending now (or at `--to`): `30m`, `2h`, `1d` |
| `--title TEXT` | Postmortem title (default: `Incident YYYY-MM-DD`) |
| `--services LIST` | Comma-separated services to focus on |
| `-o`, `--output FILE` | Output path (default: `postmortem_YYYYMMDD_HHMM.md`); `-` for stdout |
| `--format` | `markdown` (default) or `html` |
| `--no-files` | Skip `/var/log` files, use journalctl only |
| `--priorities` | journalctl priority filter (default: `0..4` = emerg…warning) |

---

## 📄 Example

This draft was generated from a simulated incident: PostgreSQL is OOM-killed, nginx starts failing,
and someone tries to brute-force SSH at the same time.

```markdown
# Postmortem: Database outage

| | |
|---|---|
| **Date** | 2026-05-10 |
| **Window** | 2026-05-10 14:00 → 2026-05-10 16:00 |
| **Duration** | 2h |
| **Severity** | Critical |
| **Status** | Draft |
| **Services analysed** | all |
| **Services affected** | `kernel`, `nginx`, `postgresql` |

---

## Summary

Analysis of **58 raw log entries** (5 unique events after deduplication) across **4 services**. First anomaly detected at **14:03:22** in `kernel` (CRITICAL). Highest error density at **14:03**.

> *Auto-generated draft — review all sections before sharing.*

---

## Timeline

| Time | Service | Severity | Event |
|------|---------|----------|-------|
| 14:03:22 | `kernel` | ⛔ CRITICAL | Out of memory: Killed process 2211 (postgres) total-vm:8123456kB |
| 14:03:24 | `postgresql` | ⛔ CRITICAL | server process (PID 2211) was terminated by signal 9: Killed |
| 14:03:45 | `nginx` | 🔴 ERROR | connect() failed (111: Connection refused) while connecting to upstream _(×40, until 14:05:42)_ |
| 14:04:22 | `postgresql` | ⚠️ WARNING | start request repeated too quickly, automatic restart _(×4, until 14:05:22)_ |
| 14:08:22 | `sshd` | ⚠️ WARNING | Failed password for invalid user admin from 203.0.113.7 port 40000 _(×12, until 14:08:33)_ |

## Contributing Factors

> *Auto-detected from log patterns — verify each before including in final report.*

- **Service instability**: `postgresql` triggered restart-loop detection **4 time(s)**
- **Memory pressure**: OOM killer fired **1 time(s)** during the window
- **Auth anomaly**: Burst of **12 authentication failure(s)** detected — possible brute-force attempt
- **Cascading failure**: `nginx` errors began **23s** after the first `kernel` critical event (14:03:22)
- **Cascading failure**: `nginx` errors began **21s** after the first `postgresql` critical event (14:03:24)
- **Error burst**: **42 errors** in the 5-minute window starting 14:00

## Action Items

_Generated from detected patterns — assign owner and priority._

- [ ] Investigate memory usage; consider adding swap or increasing RAM
- [ ] Verify the downstream service is running and listening on the expected port
- [ ] Service is crash-looping; check dependencies and configuration
- [ ] Review SSH access logs; consider IP blocking if burst detected

…
```

---

## 🔍 Detected patterns

| Pattern | Triggers |
|---------|----------|
| OOM Killer | `out of memory`, `oom-kill`, `killed process` |
| Disk Full | `no space left on device`, `disk full` |
| Kernel Error | `BUG:`, `Oops`, `call trace`, `segfault at`, `general protection`, `kernel panic` |
| Service Failed | `failed to start`, `entered failed state` |
| Process Crash | `segmentation fault`, `core dumped`, `aborted` |
| Connection Refused | `connection refused`, `upstream connect error` |
| Timeout | `timed out`, `ETIMEDOUT`, `request timeout` |
| Auth Failure | `Failed password`, `authentication failure`, `invalid user` |
| Service Restart Loop | `start request repeated too quickly`, `automatic restart` |
| SSL/TLS Error | `certificate expired`, `TLS handshake failed`, `certificate verify failed` |
| Database Error | `could not connect to database`, `max connections reached`, `deadlock` |
| High Load | load average of 10 or more, `cpu throttled` |

---

## 🧪 Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

See [CHANGELOG.md](CHANGELOG.md) for release notes.

---

## 📝 License

MIT — see [LICENSE](LICENSE).

## 🌐 Connect

[![GitHub](https://img.shields.io/badge/GitHub-@serber--info-181717?style=flat-square&logo=github)](https://github.com/serber-info)
