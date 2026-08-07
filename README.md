# SenS LogGuard

SenS LogGuard is a beginner-friendly, defensive Python project for learning how
security tools safely ingest login events. Its current milestone reads a local
JSON Lines (`.jsonl`) file, validates the shape of each record, and returns
clear errors that identify the bad line.

The repository currently contains a parser, not a complete intrusion-detection
system. It does not connect to devices, scan networks, block users, or send
alerts.

## Why this project exists

Security detections are only as trustworthy as the data they receive. A
malformed or incomplete event can crash later analysis or produce misleading
results. This first milestone creates a small, deterministic input boundary
before any detection rules are added.

Potential users include cybersecurity students, defenders prototyping local log
analysis, and developers learning how to validate machine-generated records.
Only synthetic or explicitly authorized data should be used.

## Current architecture

```text
Local JSONL file
      |
      v
load_login_events()
  - reads one line at a time
  - decodes JSON
  - requires a JSON object
  - checks five required fields
      |
      +---- valid ----> list of Python dictionaries
      |
      +---- invalid --> ValueError with the source line number
```

Each nonblank line must be one JSON object with these fields:

| Field | Intended meaning |
| --- | --- |
| `timestamp` | When the login occurred |
| `username` | Account involved |
| `success` | Whether authentication succeeded |
| `ip` | Source IP address |
| `device` | Source or reported device |

Example synthetic record:

```json
{"timestamp":"2026-07-26T08:00:00Z","username":"michael","success":false,"ip":"192.0.2.10","device":"macbook"}
```

## Security and trust boundaries

- Input is an untrusted local text file. Parsing JSON does not make its contents
  truthful or safe for operational decisions.
- Processing stays on the local machine; this milestone makes no network calls.
- The parser reads data but does not modify the source file.
- A malformed record stops processing at the first detected error. Callers must
  handle `ValueError` and must not silently discard it.
- The sample uses documentation-only IP space and synthetic identities. Do not
  commit real login logs, credentials, tokens, customer data, or device secrets.
- No automated enforcement action is allowed at this stage.

## Repository structure

```text
sens-logguard/
├── docs/json-type-boundary.md       # Guided parser trust-boundary lesson
├── sample_data/login_events.jsonl  # Synthetic example events
├── src/logguard/parser.py          # JSONL loading and structural validation
├── tests/test_parser.py            # Parser acceptance tests
├── .gitignore                      # Excludes local/generated files
├── pyproject.toml                  # Package and pytest configuration
└── README.md                       # Scope, setup, use, and limitations
```

## Setup

Python 3.9 or newer is required. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install pytest
```

The virtual environment keeps this project's tools separate from the rest of
the computer. It is excluded from Git by `.gitignore`.

## Run the tests

```bash
python -m pytest -q
```

`python -m pytest` runs pytest with the active Python interpreter. `-q` selects
concise output. The current checkpoint is successful when all three existing
tests pass. The next learner exercise will raise that target to four.

## Use the parser

From Python with `src` available on the import path:

```python
from logguard.parser import load_login_events

try:
    events = load_login_events("sample_data/login_events.jsonl")
except (OSError, ValueError) as error:
    print(f"Could not load events: {error}")
else:
    print(f"Loaded {len(events)} events")
```

The function returns a list of dictionaries when all nonblank lines are valid.
It raises `ValueError` for invalid JSON, a non-object JSON value, or missing
required fields. Normal file errors such as a missing path remain `OSError`
subclasses so the caller can distinguish file access from data validation.

## Acceptance tests

The current suite proves that:

1. Three well-formed synthetic records load successfully.
2. Invalid JSON reports its exact line number.
3. A record missing required fields is rejected with its line number.

The suite does not yet prove field types, timestamp syntax, valid IP addresses,
duplicate handling, large-file behavior, or security detection accuracy.

## Troubleshooting

- **`No module named pytest`:** activate `.venv`, then install pytest with the
  setup command above.
- **`No module named logguard`:** run tests from the repository root so pytest
  can apply the `pythonpath = ["src"]` setting in `pyproject.toml`.
- **`Invalid JSON on line N`:** inspect that exact source line for missing
  quotes, commas, braces, or other JSON syntax problems.
- **`must contain a JSON object`:** the line is valid JSON but is an array,
  string, number, boolean, or null instead of an event object.
- **`Missing required field(s)`:** add the named fields at the producer or reject
  the source record; do not invent security data merely to pass validation.

## Limitations and risks

- Validation is structural only. Values can have the wrong type or meaning and
  still pass if all required keys exist.
- Loading all accepted records into memory is unsuitable for very large files.
- Processing stops at the first bad record and does not produce a complete error
  inventory.
- No schema version is recorded, so future field changes will require careful
  compatibility decisions.
- There is no failed-login detector yet; this milestone cannot identify attacks.
- Real authentication logs contain sensitive personal and infrastructure data.
  Minimize collection, restrict access, define retention, and redact before
  sharing or committing anything.

## Learning gate and roadmap

Before adding the first detector, add a test named
`test_json_array_is_rejected`. It should write `[]` as one JSONL line and prove
that the parser raises `ValueError` containing `must contain a JSON object`.
This matters because `[]` is valid JSON, but it is not a login-event object.

Work through [the JSON type-boundary lesson](docs/json-type-boundary.md) before
writing the test. It explains the three validation layers and gives you a
prediction table to complete without revealing the exercise's final code.

After that fourth parser test passes, the next milestone can implement a
deterministic rule for three or more failed logins from the same username or IP
within five minutes. Detection output must remain reviewable and must never
trigger an automatic blocking action.
