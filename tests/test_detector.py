from typing import Any

from logguard.detector import detect_failed_login_bursts


def login_event(
    timestamp: str,
    username: str,
    success: bool,
    source_ip: str,
) -> dict[str, Any]:
    return {
        "timestamp": timestamp,
        "username": username,
        "success": success,
        "ip": source_ip,
        "device": "synthetic-test-device",
    }


def test_detects_failed_logins_for_the_same_username_and_ip() -> None:
    records = [
        login_event("2026-08-13T10:00:00Z", "michael", False, "192.0.2.10"),
        login_event("2026-08-13T10:01:00Z", "michael", False, "192.0.2.10"),
        login_event("2026-08-13T10:03:00Z", "michael", False, "192.0.2.10"),
    ]

    assert detect_failed_login_bursts(records) == [
        {
            "category": "failed_login_burst",
            "severity": "high",
            "username": "michael",
            "source_ip": "192.0.2.10",
            "evidence_count": 3,
            "requires_human_review": True,
        }
    ]


def test_detects_username_and_source_ip_bursts_without_misattribution() -> None:
    records = [
        login_event("2026-08-13T10:00:00Z", "michael", False, "192.0.2.10"),
        login_event("2026-08-13T10:01:00Z", "michael", False, "192.0.2.11"),
        login_event("2026-08-13T10:02:00Z", "michael", False, "192.0.2.12"),
        login_event("2026-08-13T10:10:00Z", "alex", False, "192.0.2.20"),
        login_event("2026-08-13T10:11:00Z", "bea", False, "192.0.2.20"),
        login_event("2026-08-13T10:12:00Z", "cam", False, "192.0.2.20"),
    ]

    assert detect_failed_login_bursts(records) == [
        {
            "category": "failed_login_burst",
            "severity": "high",
            "username": "michael",
            "source_ip": None,
            "evidence_count": 3,
            "requires_human_review": True,
        },
        {
            "category": "failed_login_burst",
            "severity": "high",
            "username": None,
            "source_ip": "192.0.2.20",
            "evidence_count": 3,
            "requires_human_review": True,
        },
    ]


def test_ignores_successes_and_failures_outside_the_window() -> None:
    records = [
        login_event("2026-08-13T10:00:00Z", "michael", False, "192.0.2.10"),
        login_event("2026-08-13T10:01:00Z", "michael", True, "192.0.2.10"),
        login_event("2026-08-13T10:06:00Z", "michael", False, "192.0.2.10"),
        login_event("2026-08-13T10:12:00Z", "michael", False, "192.0.2.10"),
    ]

    assert detect_failed_login_bursts(records) == []
