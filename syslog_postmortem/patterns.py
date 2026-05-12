"""
Known error patterns with severity labels and action hints.
Each pattern is matched against log message text.
"""
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: str       # CRITICAL | ERROR | WARNING
    label: str          # human-readable category
    action_hint: str    # suggested action item


PATTERNS = [
    Pattern(
        name='oom',
        regex=re.compile(r'out of memory|oom.kill|killed process|oom_reaper', re.I),
        severity='CRITICAL',
        label='OOM Killer',
        action_hint='Investigate memory usage; consider adding swap or increasing RAM',
    ),
    Pattern(
        name='disk_full',
        regex=re.compile(r'no space left on device|disk full|filesystem.*full|write.*failed.*enospc', re.I),
        severity='CRITICAL',
        label='Disk Full',
        action_hint='Free disk space immediately; review log rotation and data retention',
    ),
    Pattern(
        name='kernel_oops',
        regex=re.compile(r'kernel: bug|kernel: oops|kernel: warning.*call trace|segfault|general protection', re.I),
        severity='CRITICAL',
        label='Kernel Error',
        action_hint='Review kernel logs; consider rebooting if system is unstable',
    ),
    Pattern(
        name='service_failed',
        regex=re.compile(r'\bfailed\b.*start|start.*\bfailed\b|unit.*entered failed|activating.*failed', re.I),
        severity='ERROR',
        label='Service Failed',
        action_hint='Check service logs with journalctl -u <service>; review service configuration',
    ),
    Pattern(
        name='service_crash',
        regex=re.compile(r'segmentation fault|core dump|crashed|dumped core|aborted', re.I),
        severity='ERROR',
        label='Process Crash',
        action_hint='Collect core dump; review application error logs',
    ),
    Pattern(
        name='connection_refused',
        regex=re.compile(r'connection refused|econnrefused|connect.*failed|upstream.*connect.*error', re.I),
        severity='ERROR',
        label='Connection Refused',
        action_hint='Verify the downstream service is running and listening on the expected port',
    ),
    Pattern(
        name='timeout',
        regex=re.compile(r'\btimed? out\b|etimedout|operation timed out|request timeout|read timeout', re.I),
        severity='WARNING',
        label='Timeout',
        action_hint='Check network latency and service response times; review timeout thresholds',
    ),
    Pattern(
        name='auth_failure',
        regex=re.compile(r'failed password|authentication failure|invalid user|permission denied.*ssh|pam.*auth.*fail', re.I),
        severity='WARNING',
        label='Auth Failure',
        action_hint='Review SSH access logs; consider IP blocking if burst detected',
    ),
    Pattern(
        name='service_restart',
        regex=re.compile(r'start request repeated too quickly|restarting.*unit|automatic.*restart', re.I),
        severity='WARNING',
        label='Service Restart Loop',
        action_hint='Service is crash-looping; check dependencies and configuration',
    ),
    Pattern(
        name='ssl_cert',
        regex=re.compile(r'certificate.*expir|ssl.*error|tls.*handshake.*fail|certificate verify failed', re.I),
        severity='ERROR',
        label='SSL/TLS Error',
        action_hint='Renew the certificate; check certificate chain and validity',
    ),
    Pattern(
        name='db_error',
        regex=re.compile(r'could not connect.*database|database.*unavailable|max.*connection.*reached|deadlock', re.I),
        severity='ERROR',
        label='Database Error',
        action_hint='Check database service status, connection pool settings, and max connections',
    ),
    Pattern(
        name='high_load',
        regex=re.compile(r'load average.*\b([5-9]\d|\d{2,})\b|cpu.*throttl|system.*overload', re.I),
        severity='WARNING',
        label='High System Load',
        action_hint='Identify CPU-intensive processes; consider horizontal scaling',
    ),
]


def match_patterns(message: str) -> list:
    """Return list of matching Patterns for a log message."""
    return [p for p in PATTERNS if p.regex.search(message)]
