"""
Pattern analysis, deduplication, cascade detection and contributing factor generation.
"""
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from .collector import RawEntry, priority_to_severity
from .patterns import match_patterns, Pattern


# ── Normalised event ──────────────────────────────────────────────────────────

@dataclass
class Event:
    timestamp: datetime
    service: str
    severity: str           # CRITICAL | ERROR | WARNING | INFO
    message: str
    source: str
    patterns: List[Pattern] = field(default_factory=list)
    count: int = 1                              # after deduplication
    last_timestamp: Optional[datetime] = None   # last repetition when count > 1


# ── Analysis result ───────────────────────────────────────────────────────────

@dataclass
class AnalysisResult:
    events: List[Event]
    timeline: List[Event]                           # deduplicated, sorted
    by_severity: Dict[str, List[Event]]
    by_service: Dict[str, List[Event]]
    pattern_counts: Dict[str, int]                  # pattern_name → count
    contributing_factors: List[str]
    action_items: List[str]
    first_anomaly: Optional[Event]
    peak_window: Optional[datetime]                 # minute with most errors
    services_affected: List[str]
    total_raw: int


# ── Helpers ───────────────────────────────────────────────────────────────────

# Standalone integers (PIDs, ports, counters) — but not IPv4 octets, versions or times.
_VOLATILE_NUMBER = re.compile(r'(?<![\d.:])\d+(?![\d.:])')


def _deduplicate(events: List[Event], window_seconds: int = 300) -> List[Event]:
    """
    Merge identical messages from the same service while they keep repeating
    (each repetition less than `window_seconds` after the previous one).
    Keeps the first occurrence with a count and the time of the last repetition.
    """
    result: List[Event] = []
    groups: Dict[tuple, Event] = {}

    for ev in events:
        key = (ev.service, _VOLATILE_NUMBER.sub('#', ev.message[:200]))
        group = groups.get(key)
        if group is not None:
            last = group.last_timestamp or group.timestamp
            if (ev.timestamp - last).total_seconds() <= window_seconds:
                group.count += 1
                group.last_timestamp = ev.timestamp
                continue
        groups[key] = ev
        result.append(ev)

    return result


def _peak_minute(events: List[Event]) -> Optional[datetime]:
    buckets: Counter = Counter()
    for ev in events:
        if ev.severity in ('CRITICAL', 'ERROR', 'WARNING'):
            buckets[ev.timestamp.replace(second=0, microsecond=0)] += 1
    return buckets.most_common(1)[0][0] if buckets else None


def _detect_cascades(events: List[Event], window_seconds: int = 120) -> List[str]:
    """
    Detect cascading failures: service A has a critical event, service B starts
    failing shortly after. One line per (A, B) pair, using A's first critical event.
    """
    cascades = []
    seen_pairs = set()
    criticals = [e for e in events if e.severity == 'CRITICAL']
    errors = [e for e in events if e.severity == 'ERROR']

    for trigger in criticals:
        for follow in errors:
            pair = (trigger.service, follow.service)
            if follow.service == trigger.service or pair in seen_pairs:
                continue
            delta = (follow.timestamp - trigger.timestamp).total_seconds()
            if 0 < delta <= window_seconds:
                seen_pairs.add(pair)
                cascades.append(
                    f"**Cascading failure**: `{follow.service}` errors began "
                    f"**{int(delta)}s** after the first `{trigger.service}` critical event "
                    f"({trigger.timestamp.strftime('%H:%M:%S')})"
                )
    return cascades


_SEV_RANK = {'CRITICAL': 0, 'ERROR': 1, 'WARNING': 2, 'INFO': 3, 'DEBUG': 4}


def service_matches(service: str, wanted: List[str]) -> bool:
    """'postgresql' matches 'postgresql', 'postgresql@14-main' and 'postgresql.service'."""
    s = service.lower()
    return any(s == w or s.startswith((w + '@', w + '.', w + '-')) for w in wanted)


# ── Main analyser ─────────────────────────────────────────────────────────────

def analyze(raw: List[RawEntry], services_filter: List[str] = None) -> AnalysisResult:
    total_raw = len(raw)

    # 1. Normalise RawEntry → Event and run pattern matching
    events: List[Event] = []
    wanted = [s.lower() for s in services_filter or []]
    for r in raw:
        if wanted and not service_matches(r.service, wanted):
            continue
        severity = priority_to_severity(r.priority)
        matched = match_patterns(r.message)
        # Upgrade severity when a known pattern is more serious than the log priority
        for p in matched:
            if _SEV_RANK.get(p.severity, 4) < _SEV_RANK.get(severity, 4):
                severity = p.severity
        events.append(Event(
            timestamp=r.timestamp,
            service=r.service,
            severity=severity,
            message=r.message,
            source=r.source,
            patterns=matched,
        ))

    # 2. Deduplicate
    timeline = _deduplicate(events)

    # 3. Group by severity and service
    by_severity: Dict[str, List[Event]] = defaultdict(list)
    by_service:  Dict[str, List[Event]] = defaultdict(list)
    for ev in timeline:
        by_severity[ev.severity].append(ev)
        by_service[ev.service].append(ev)

    # 4. Pattern counts
    pattern_counts: Counter = Counter()
    for ev in timeline:
        for p in ev.patterns:
            pattern_counts[p.name] += ev.count

    # 5. First anomaly (first CRITICAL or ERROR)
    first_anomaly = next(
        (e for e in timeline if e.severity in ('CRITICAL', 'ERROR')), None
    )

    # 6. Peak minute
    peak_window = _peak_minute(timeline)

    # 7. Services affected (those with at least one ERROR+)
    services_affected = sorted({
        e.service for e in timeline
        if e.severity in ('CRITICAL', 'ERROR')
    })

    # 8. Contributing factors
    factors: List[str] = []

    # Restart loops
    restart_counts: Counter = Counter()
    for e in timeline:
        if any(p.name == 'service_restart' for p in e.patterns):
            restart_counts[e.service] += e.count
    for svc, cnt in restart_counts.most_common():
        factors.append(
            f"**Service instability**: `{svc}` triggered restart-loop detection **{cnt} time(s)**"
        )

    # OOM events
    oom_count = pattern_counts.get('oom', 0)
    if oom_count:
        factors.append(
            f"**Memory pressure**: OOM killer fired **{oom_count} time(s)** during the window"
        )

    # Disk full
    if pattern_counts.get('disk_full', 0):
        factors.append("**Disk exhaustion**: 'No space left on device' events detected")

    # Auth failure burst (>5 in window)
    auth_count = sum(
        e.count for e in timeline
        if any(p.name == 'auth_failure' for p in e.patterns)
    )
    if auth_count >= 5:
        factors.append(
            f"**Auth anomaly**: Burst of **{auth_count} authentication failure(s)** detected"
            " — possible brute-force attempt"
        )

    # Cascading failures
    factors.extend(_detect_cascades(timeline))

    # High error density (>30 error events in any 5-minute window)
    buckets: Counter = Counter()
    for ev in timeline:
        if ev.severity in ('CRITICAL', 'ERROR'):
            slot = ev.timestamp.replace(second=0, microsecond=0)
            slot = slot.replace(minute=(slot.minute // 5) * 5)
            buckets[slot] += ev.count
    dense = [(t, c) for t, c in buckets.items() if c >= 30]
    for t, c in sorted(dense):
        factors.append(
            f"**Error burst**: **{c} errors** in the 5-minute window starting "
            f"{t.strftime('%H:%M')}"
        )

    if not factors:
        factors.append("No specific contributing factors auto-detected — manual analysis required")

    # 9. Action items (deduplicated from pattern hints)
    seen_hints: set = set()
    action_items: List[str] = []
    for ev in timeline:
        for p in ev.patterns:
            if p.action_hint not in seen_hints:
                seen_hints.add(p.action_hint)
                action_items.append(p.action_hint)

    return AnalysisResult(
        events=events,
        timeline=timeline,
        by_severity=dict(by_severity),
        by_service=dict(by_service),
        pattern_counts=dict(pattern_counts),
        contributing_factors=factors,
        action_items=action_items,
        first_anomaly=first_anomaly,
        peak_window=peak_window,
        services_affected=services_affected,
        total_raw=total_raw,
    )
