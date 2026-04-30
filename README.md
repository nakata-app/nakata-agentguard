# agentguard

[![PyPI version](https://img.shields.io/pypi/v/nakata-agentguard.svg)](https://pypi.org/project/nakata-agentguard/)
[![Python versions](https://img.shields.io/pypi/pyversions/nakata-agentguard.svg)](https://pypi.org/project/nakata-agentguard/)
[![License: MIT](https://img.shields.io/pypi/l/nakata-agentguard.svg)](LICENSE)
[![CI](https://github.com/nakata-app/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/nakata-app/agentguard/actions/workflows/ci.yml)

**Lightweight agentic loop detector and safety monitor. Zero required dependencies.**

## The problem

LLM agents get stuck. A loop, a dangerous command, a runaway budget, and your agent keeps going. Existing guardrail frameworks are heavy, opinionated, and require you to rewrite your agent around them.

agentguard is different: one method call, drop-in anywhere, no LLM required.

## Quick start

```bash
pip install nakata-agentguard
```

```python
from agentguard import AgentGuard, Action

guard = AgentGuard()

# In your tool execution loop:
report = guard.record("bash", {"cmd": "git status"})
if report.action == Action.HALT:
    raise RuntimeError(report.reason)
```

That's it.

## What it catches

### Loop detection

Three modes, exact, pattern, stall:

```python
# Exact: same (tool, args) repeated N times
guard.record("bash", {"cmd": "git status"})
guard.record("bash", {"cmd": "git status"})
report = guard.record("bash", {"cmd": "git status"})
# report.action == Action.HALT
# report.reason == "loop detected ('bash:...' called 3x in last 10 calls)"

# Pattern: ABCABC sequence repeating
# Stall: same tool called N times with any args
```

### Dangerous pattern detection

30+ regex patterns across 5 categories, no LLM required:

| Category | Examples |
|---|---|
| DESTRUCTIVE | `rm -rf`, `DROP TABLE`, `TRUNCATE TABLE` |
| DATA_WIPE | `dd if=`, `mkfs`, `format c:` |
| PRIVILEGE_ESCALATION | `sudo`, `chmod 777`, `chown root` |
| EXFILTRATION | reverse shells, `curl -d`, SSH key access |
| CODE_INJECTION | `eval $()`, `shell=True`, `pickle.loads` |

```python
report = guard.record("bash", {"cmd": "rm -rf /"})
# report.action == Action.HALT
# report.dangers[0].category == DangerCategory.DESTRUCTIVE
# report.dangers[0].severity == 10
```

### Budget monitoring

```python
from agentguard import GuardConfig

guard = AgentGuard(GuardConfig(token_limit=100_000, cost_limit_usd=5.0))
report = guard.record("llm", {"prompt": "..."}, tokens=1500, cost_usd=0.002)
# report.budget.token_pct  → 0.015
# report.budget.is_warning → False (< 80%)
```

## Configuration

```python
from agentguard import AgentGuard, GuardConfig

guard = AgentGuard(GuardConfig(
    # Loop
    exact_threshold=3,       # N identical calls = loop
    stall_threshold=5,       # N same-tool calls = stall
    halt_on_loop=True,

    # Danger
    halt_on_severity=9,      # severity >= 9 → HALT
    warn_on_severity=6,      # severity >= 6 → WARN

    # Budget
    token_limit=50_000,
    cost_limit_usd=2.0,
))
```

## Metis integration

agentguard ships a `check` subcommand designed to run as a Metis PostToolUse hook.
It reads `METIS_TOOL_NAME` and `METIS_TOOL_ARGS` from the environment and either
passes through (exit 0) or blocks (exit 1).

Add to `~/.metis/hooks.toml`:

```toml
[[hooks]]
event      = "SessionStart"
command    = "agentguard serve --port 7420"
background = true

[[hooks]]
event   = "PostToolUse"
command = "agentguard check"
```

The daemon maintains session state across tool calls, enabling loop detection.
Without the daemon, `agentguard check` runs stateless (danger + budget only).

## HTTP daemon

```bash
pip install "nakata-agentguard[serve]"
agentguard serve --port 7420 --halt-severity 9 --token-limit 100000
```

```bash
# Record a tool call
curl -s -X POST http://localhost:7420/record \
  -H 'Content-Type: application/json' \
  -d '{"tool":"bash","args":{"cmd":"ls -la"}}'

# {"action":"continue","reason":"ok","total_calls":1,...}

# Status
curl http://localhost:7420/status

# Reset session
curl -X POST http://localhost:7420/reset
```

## nakata cluster

agentguard is part of the [nakata](https://github.com/nakata-app) AI reliability cluster:

- [halluguard](https://github.com/nakata-app/halluguard), reverse-RAG hallucination detector
- [adaptmem](https://github.com/nakata-app/AdaptMem), domain-adapted retrieval memory
- [claimcheck](https://github.com/nakata-app/claimcheck), end-to-end claim verification pipeline
- **agentguard**, agentic loop and safety monitor

## License

MIT
