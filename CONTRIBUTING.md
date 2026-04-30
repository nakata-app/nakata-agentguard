# Contributing

## Setup

```bash
git clone https://github.com/nakata-app/agentguard
cd agentguard
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,serve]"
pip install httpx   # for server tests
```

## Running tests

```bash
make test          # all tests + coverage
pytest tests/ -v   # verbose
pytest tests/test_loop.py  # single module
```

## Running benchmarks

```bash
make bench
```

## Code style

`ruff` for lint + format. Run before committing:

```bash
make lint
make fmt
```

Or install the pre-commit hook:

```bash
pip install pre-commit
pre-commit install
```

## Adding a danger pattern

Edit `src/agentguard/detectors/danger.py`, add a tuple to `_PATTERNS`:

```python
(r"your_pattern_here", DangerCategory.DESTRUCTIVE, severity, "description"),
```

Severity scale:
- 10: immediate halt, no ambiguity (e.g. reverse shell, `rm -rf /`)
- 8-9: almost certainly dangerous
- 6-7: risky, warrants investigation
- 4-5: suspicious but often legitimate
- 1-3: informational

Add a test in `tests/test_danger.py`.

## Adding a loop detection mode

Add a `_detect_*` function in `src/agentguard/detectors/loop.py` and a variant
in `LoopType` enum in `models.py`. Wire it up in `LoopDetector.check()`.

## Pull requests

- Keep changes focused. One PR per concern.
- All tests must pass.
- New features need tests.
