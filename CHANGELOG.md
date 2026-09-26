# Changelog

## 1.1.0

### Security
- **HTML reports were vulnerable to script injection.** Log messages were inserted without escaping, and
  some are attacker-controlled (an SSH login attempt with a crafted user name lands in auth.log). All log
  content is now escaped in both Markdown and HTML, and the HTML page ships a Content-Security-Policy.

### Fixed
- Every line of `/var/log/syslog`/`auth.log` in the window was reported as a WARNING (and `kern.log` lines
  as ERROR), flooding the report. File lines now get a priority from their content and honour `--priorities`.
- `/var/log/dmesg` was listed but never parsed (it has no wall-clock timestamps); the kernel log comes from
  the journal and `kern.log`.
- Messages logged by systemd about a unit were attributed to `init.scope`; they now show the real unit.
- "High load" matched any load average (`load average: 0.15` was an alert).
- The kernel oops pattern never matched journald messages (it expected a `kernel:` prefix).
- `--services postgresql` missed template units such as `postgresql@14-main`.
- Syslog lines around New Year got the wrong year; RFC 3339 timestamps with a UTC offset were read as local time.
- Cascading failures were reported once per event instead of once per pair of services.
- The HTML output did not render tables, lists or quotes.
- Uses an explicit year when parsing syslog dates (Python 3.15 changes year-less `strptime`).

### Added
- `--last 30m|2h|1d`, optional `--to` (defaults to now) and seconds in timestamps.
- `-o -` writes the report to stdout; progress messages go to stderr.
- Repeated messages are grouped with their count and the time of the last repetition.
- Rotated logs (`syslog.1`, `auth.log.1`…) are read as well.
- Warnings when the journal or log files are not fully readable.
- Light/dark theme in the HTML report; the timeline keeps the most severe events when truncated.
- `python -m syslog_postmortem`, test suite and GitHub Actions CI.

### Changed
- License metadata unified (MIT). Requires Python 3.9+.

## 1.0.0

- Initial release: automated postmortem generator from system logs.
