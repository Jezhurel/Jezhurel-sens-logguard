"""Deterministic, review-only detections for validated login events."""

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Optional


BURST_THRESHOLD = 3
BURST_WINDOW = timedelta(minutes=5)


@dataclass(frozen=True)
class _FailedLogin:
    """A failed event with the fields required for burst analysis."""

    timestamp: datetime
    username: str
    source_ip: str
    record_number: int


@dataclass(frozen=True)
class _AlertCandidate:
    """Internal alert data used to sort and de-duplicate deterministic output."""

    detected_at: datetime
    username: Optional[str]
    source_ip: Optional[str]
    evidence_count: int
    evidence_records: tuple[int, ...]


def detect_failed_login_bursts(
    records: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return review-only alerts for three failed logins within five minutes.

    A burst may share a username or a source IP. If a matching window contains
    multiple usernames or multiple IPs, the non-common field is ``None`` so an
    alert never claims one value represented all of the evidence.

    This detector does not contact a service, block an account, or treat an
    alert as proof of malicious activity.
    """
    failures = _failed_login_events(records)
    candidates = _burst_candidates(failures, group_by="username")
    candidates.extend(_burst_candidates(failures, group_by="source_ip"))

    unique_candidates = {
        (
            candidate.detected_at,
            candidate.username,
            candidate.source_ip,
            candidate.evidence_count,
            candidate.evidence_records,
        ): candidate
        for candidate in candidates
    }

    ordered_candidates = sorted(
        unique_candidates.values(),
        key=lambda candidate: (
            candidate.detected_at,
            candidate.username or "",
            candidate.source_ip or "",
            candidate.evidence_records,
        ),
    )

    return [
        {
            "category": "failed_login_burst",
            "severity": "high",
            "username": candidate.username,
            "source_ip": candidate.source_ip,
            "evidence_count": candidate.evidence_count,
            "requires_human_review": True,
        }
        for candidate in ordered_candidates
    ]


def _failed_login_events(
    records: Iterable[Mapping[str, Any]],
) -> list[_FailedLogin]:
    failures: list[_FailedLogin] = []

    for record_number, record in enumerate(records, start=1):
        if not isinstance(record, Mapping):
            raise ValueError(f"Record {record_number} must be a mapping")

        success = record.get("success")

        if not isinstance(success, bool):
            raise ValueError(
                f"Record {record_number} field 'success' must be a boolean"
            )

        if success:
            continue

        failures.append(
            _FailedLogin(
                timestamp=_timestamp(record, record_number),
                username=_text_field(record, "username", record_number),
                source_ip=_text_field(record, "ip", record_number),
                record_number=record_number,
            )
        )

    return failures


def _burst_candidates(
    failures: Iterable[_FailedLogin],
    *,
    group_by: str,
) -> list[_AlertCandidate]:
    groups: dict[str, list[_FailedLogin]] = defaultdict(list)

    for failure in failures:
        key = failure.username if group_by == "username" else failure.source_ip
        groups[key].append(failure)

    candidates: list[_AlertCandidate] = []

    for key in sorted(groups):
        candidate = _first_burst_in_group(groups[key])

        if candidate is not None:
            candidates.append(candidate)

    return candidates


def _first_burst_in_group(
    failures: Iterable[_FailedLogin],
) -> Optional[_AlertCandidate]:
    window: Deque[_FailedLogin] = deque()

    for failure in sorted(
        failures,
        key=lambda event: (event.timestamp, event.record_number),
    ):
        window.append(failure)

        while failure.timestamp - window[0].timestamp > BURST_WINDOW:
            window.popleft()

        if len(window) >= BURST_THRESHOLD:
            evidence = tuple(window)
            usernames = {event.username for event in evidence}
            source_ips = {event.source_ip for event in evidence}

            return _AlertCandidate(
                detected_at=failure.timestamp,
                username=(
                    next(iter(usernames)) if len(usernames) == 1 else None
                ),
                source_ip=(
                    next(iter(source_ips)) if len(source_ips) == 1 else None
                ),
                evidence_count=len(evidence),
                evidence_records=tuple(
                    event.record_number for event in evidence
                ),
            )

    return None


def _timestamp(record: Mapping[str, Any], record_number: int) -> datetime:
    timestamp = _text_field(record, "timestamp", record_number)
    normalized = (
        f"{timestamp[:-1]}+00:00" if timestamp.endswith("Z") else timestamp
    )

    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as error:
        raise ValueError(
            f"Record {record_number} has an invalid timestamp"
        ) from error

    if parsed.tzinfo is None:
        raise ValueError(
            f"Record {record_number} timestamp must include a timezone"
        )

    return parsed.astimezone(timezone.utc)


def _text_field(
    record: Mapping[str, Any],
    field_name: str,
    record_number: int,
) -> str:
    value = record.get(field_name)

    if not isinstance(value, str) or not value:
        raise ValueError(
            f"Record {record_number} field '{field_name}' must be text"
        )

    return value
