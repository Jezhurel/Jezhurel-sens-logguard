# Learning Checkpoint: Valid JSON Is Not Always a Valid Event

This checkpoint teaches a security boundary that appears in log pipelines,
APIs, compliance evidence systems, and AI data workflows: successful parsing
does not prove that input has the structure or meaning the system expects.

Use only the synthetic values in this lesson.

## The three validation layers

### 1. Syntax validation

`json.loads()` answers one narrow question: **is this text legal JSON?**

JSON supports six top-level value types:

| JSON text | Python value | Legal JSON? |
| --- | --- | --- |
| `{"username": "michael"}` | `dict` | Yes |
| `[]` | `list` | Yes |
| `"michael"` | `str` | Yes |
| `42` | `int` | Yes |
| `true` | `bool` | Yes |
| `null` | `None` | Yes |

All six examples pass syntax validation. Only the first has the container type
expected for one login-event record.

### 2. Structural validation

The parser next asks:

1. Is the decoded value a Python dictionary?
2. Does it contain all five required field names?

This is why `[]` must be rejected. It is valid JSON, but a list has no event
fields such as `username`, `timestamp`, or `success`. Passing it downstream
would force every detector to handle unexpected shapes and could cause crashes
or skipped security events.

The current boundary is implemented by these two expressions:

```python
isinstance(record, dict)
REQUIRED_FIELDS.difference(record.keys())
```

The first checks the container type. The second calculates which required keys
are missing. Keeping both checks inside the parser gives later detectors a
simpler contract: accepted records are dictionaries containing the known keys.

### 3. Semantic validation

Even a structurally complete record can still be misleading:

```json
{"timestamp":"yesterday-ish","username":99,"success":"maybe","ip":"banana","device":null}
```

This object has every required key, so the current parser accepts it. Its values
do not have the intended types or formats. Future milestones may validate those
meanings, but the present exercise must not silently expand scope.

## Trust-boundary model

```text
Untrusted line
     |
     v
JSON syntax check -------- failure -> line-numbered error
     |
     v
Object type check -------- failure -> line-numbered error
     |
     v
Required-key check ------- failure -> line-numbered error
     |
     v
Structurally accepted record
     |
     v
Future semantic checks and detection rules
```

The parser does not prove that an event is true, trustworthy, harmless, or
complete enough for production decisions. It establishes only the documented
minimum structure.

## Prediction exercise

Without running the parser, complete the last two columns:

| Input | Decoded Python type | Accepted or rejected? | Expected reason |
| --- | --- | --- | --- |
| `[]` | `list` |  |  |
| `"login"` | `str` |  |  |
| `null` | `None` |  |  |
| `{}` | `dict` |  |  |
| Complete five-field object | `dict` |  |  |

Notice that `{}` crosses the object-type boundary but should fail at the next
layer because all required fields are absent.

## Your test assignment

Add one test named `test_json_array_is_rejected` to `tests/test_parser.py`.
The test must:

1. use pytest's `tmp_path` fixture;
2. write exactly one JSONL line containing `[]`;
3. call `load_login_events()`;
4. require a `ValueError`;
5. check that the message contains `must contain a JSON object`.

Do not change `parser.py` for this checkpoint. The behavior already exists; the
missing work is proving it with a regression test.

Run:

```bash
python -m pytest -q
```

Acceptance result: **four tests pass**. A passing test proves that the current
parser rejects this one array case. It does not yet prove all other non-object
JSON types, value semantics, detector accuracy, or production readiness.

## GRC and AI-governance connection

This coding boundary mirrors evidence assessment in GRC:

- **Syntax:** a document or record exists and can be opened.
- **Structure:** it contains the expected owner, date, scope, approval, and
  control fields.
- **Semantics:** its content is accurate, current, relevant, and supported.

For AI governance, a model card or risk assessment is not reliable merely
because the file exists or follows a template. An analyst must also evaluate
whether its claims are supported and whether the evidence covers the intended
system and risk.

## Explain it in your own words

Before the next milestone, answer:

> Why can `[]` be valid JSON while still being invalid as one login event, and
> what failure could occur if the parser allowed it into a detector?
