from pathlib import Path

import pytest

from logguard.parser import load_login_events


PROJECT_ROOT = Path(__file__).parent.parent


def test_loads_three_valid_records() -> None:
    log_file = PROJECT_ROOT / "sample_data" / "login_events.jsonl"

    records = load_login_events(log_file)

    assert len(records) == 3
    assert records[0]["username"] == "michael"
    assert records[0]["success"] is False


def test_invalid_json_reports_line_number(tmp_path: Path) -> None:
    log_file = tmp_path / "invalid.jsonl"
    log_file.write_text(
        '{"timestamp":"2026-07-26T08:00:00Z",'
        '"username":"michael","success":true,'
        '"ip":"192.0.2.10","device":"macbook"}\n'
        'this is not valid JSON\n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="line 2"):
        load_login_events(log_file)


def test_missing_fields_are_rejected(tmp_path: Path) -> None:
    log_file = tmp_path / "missing-fields.jsonl"
    log_file.write_text(
        '{"timestamp":"2026-07-26T08:00:00Z",'
        '"username":"michael"}\n',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Missing required field.*line 1",
    ):
        load_login_events(log_file)
