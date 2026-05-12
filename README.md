# syslog-postmortem

[![PyPI version](https://badge.fury.io/py/syslog-postmortem.svg)](https://badge.fury.io/py/syslog-postmortem)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Generate a **structured postmortem draft** from system logs in seconds — no more reconstructing incident timelines by hand.

Pulls from `journalctl`, `/var/log/syslog`, `/var/log/auth.log` and `/var/log/dmesg`, correlates events, detects patterns, and produces a ready-to-edit Markdown or HTML postmortem.

---

## ✨ What it does

Given a time window and optional service list, `syslog-postmortem`:

1. **Collects** entries from `journalctl` (primary) and `/var/log` files (supplement)
2. **Deduplicates** repeated messages and counts occurrences
3. **Detects patterns** — OOM kills, service crashes, auth bursts, disk exhaustion, cascading failures, connection errors
4. **Builds a timeline** sorted chronologically with severity icons
5. **Identifies contributing factors** automatically (restart loops, cascade chains, error bursts)
6. **Generates action items** from pattern hints
7. **Outputs** a complete Markdown postmortem ready to edit and share

---

## 📥 Installation

```bash
pip install syslog-postmortem
```

---

## 🛠 Usage

```bash
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00"
```

```bash
# Focus on specific services
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00" \
           --services nginx,postgresql,redis \
           --title "Database outage" \
           --output incident-2026-05-10.md

# HTML output
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00" \
           --format html --output report.html

# journalctl only (skip /var/log files)
postmortem --from "2026-05-10 14:00" --to "2026-05-10 16:00" --no-files
```

---

## 📋 Options

| Option | Description |
|--------|-------------|
| `--from DATETIME` | Start of incident window **required** |
| `--to DATETIME` | End of incident window **required** |
| `--title TEXT` | Postmortem title (default: `Incident YYYY-MM-DD`) |
| `--services LIST` | Comma-separated services to focus on |
| `--output FILE` | Output path (default: `postmortem_YYYYMMDD_HHMM.md`) |
| `--format` | `markdown` (default) or `html` |
| `--no-files` | Skip `/var/log` parsing, use journalctl only |
| `--priorities` | journalctl priority filter (default: `0..4`) |

---

## 📄 Output structure

```markdown
# Postmortem: Database outage

| | |
|---|---|
| **Date** | 2026-05-10 |
| **Window** | 2026-05-10 14:00 → 2026-05-10 16:00 |
| **Duration** | 2h 0m |
| **Severity** | Critical |

## Summary
Analysis of 1,243 raw log entries (89 unique events after deduplication)...
First anomaly detected at **14:03:22** in **postgresql** (CRITICAL).

## Timeline
| Time | Service | Severity | Event |
|------|---------|----------|-------|
| 14:03:22 | `postgresql` | ⛔ CRITICAL | could not connect to server |
| 14:03:45 | `nginx` | 🔴 ERROR | upstream connect error |

## Contributing Factors
- **Service instability**: `postgresql` triggered restart-loop detection 4 time(s)
- **Cascading failure**: `nginx` errors began 23s after first `postgresql` critical event

## Action Items
- [ ] Investigate postgresql restart cause; check dependencies and configuration
- [ ] Verify the downstream service is running and listening on the expected port
```

---

## 🔍 Detected patterns

| Pattern | Triggers |
|---------|----------|
| OOM Killer | `out of memory`, `oom_kill`, `killed process` |
| Disk Full | `no space left on device`, `disk full` |
| Kernel Error | `kernel: BUG`, `segfault`, `general protection` |
| Service Failed | `failed to start`, `unit entered failed state` |
| Process Crash | `segmentation fault`, `core dump`, `aborted` |
| Connection Refused | `connection refused`, `upstream connect error` |
| Timeout | `timed out`, `ETIMEDOUT`, `request timeout` |
| Auth Failure | `Failed password`, `authentication failure`, `invalid user` |
| SSL/TLS Error | `certificate expired`, `TLS handshake failed` |
| Database Error | `could not connect to database`, `max connections reached` |
| High Load | `load average` spike, `cpu throttled` |

---

## 📝 License

MIT — see [LICENSE](LICENSE).

## 🌐 Connect

[![GitHub](https://img.shields.io/badge/GitHub-@serber--info-181717?style=flat-square&logo=github)](https://github.com/serber-info)
