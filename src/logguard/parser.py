import json
from pathlib import Path
from typing import Any, Union


REQUIRED_FIELDS = {
    "timestamp",
    "username",
    "success",
    "ip",
    "device",
}


def load_login_events(path: Union[str, Path]) -> list[dict[str, Any]]:
    """Load JSONL login events and require the expected fields.

    Blank lines are ignored. Invalid JSON and missing fields raise ValueError
    with the line number so the operator can locate the bad source record.
    """
    file_path = Path(path)
    records: list[dict[str, Any]] = []

    with file_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            cleaned_line = line.strip()

            if not cleaned_line:
                continue

            try:
                record = json.loads(cleaned_line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {error.msg}"
                ) from error

            if not isinstance(record, dict):
                raise ValueError(
                    f"Line {line_number} must contain a JSON object"
                )

            missing_fields = REQUIRED_FIELDS.difference(record.keys())

            if missing_fields:
                missing_names = ", ".join(sorted(missing_fields))
                raise ValueError(
                    f"Missing required field(s) on line "
                    f"{line_number}: {missing_names}"
                )

            records.append(record)

    return records
