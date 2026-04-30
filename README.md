# agentguard

[![PyPI version](https://img.shields.io/pypi/v/nakata-agentguard.svg)](https://pypi.org/project/nakata-agentguard/)
[![Python versions](https://img.shields.io/pypi/pyversions/nakata-agentguard.svg)](https://pypi.org/project/nakata-agentguard/)
[![License: MIT](https://img.shields.io/pypi/l/nakata-agentguard.svg)](LICENSE)
[![CI](https://github.com/nakata-app/nakata-agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/nakata-app/nakata-agentguard/actions/workflows/ci.yml)

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

## What it catches

### Loop detection (5 modes)

```python
from agentguard import AgentGuard, GuardConfig

guard = AgentGuard(GuardConfig(exact_threshold=3))

# Exact: same (tool, args) repeated N times
for _ in range(3):
    guard.record("bash", {"cmd": "git status"})
# report.action == Action.HALT, "loop detected ('bash:...' called 3x)"

# Also catches:
# Near-duplicate: args differ only in whitespace/numbers
# Error-loop: tool returning errors repeatedly
# Pattern: ABCABC repeating sequence
# Stall: same tool called N times with any args
```

### Dangerous pattern detection (110+ patterns)

No LLM required, pure regex across 9 categories:

| Category | Examples |
|---|---|
| DESTRUCTIVE | `rm -rf`, `DROP TABLE`, `docker system prune`, `terraform destroy` |
| DATA_WIPE | `dd if=`, `mkfs`, `> /dev/sda` |
| PRIVILEGE_ESCALATION | `sudo`, `chmod 777`, `docker run --privileged`, `nsenter` |
| EXFILTRATION | reverse shells, `curl -d`, `/dev/tcp/`, Metasploit payloads |
| CODE_INJECTION | `eval $()`, `shell=True`, `pickle.loads`, `curl \| bash`, SQL injection |
| SECRETS | SSH keys, AWS/GCloud creds, OpenAI keys, Stripe live keys, kubeconfig |
| NETWORK | `nmap`, `masscan`, `ettercap`, C2 frameworks, crypto miners |
| DESTRUCTIVE (cloud) | `aws s3 rm --recursive`, `gcloud ... delete`, `kubectl delete --all` |
| DESTRUCTIVE (git) | `git push --force`, `git reset --hard`, `git filter-branch` |

```python
report = guard.record("bash", {"cmd": "rm -rf /"})
# report.action    == Action.HALT
# report.dangers[0].category == DangerCategory.DESTRUCTIVE
# report.dangers[0].severity == 10
```

### Budget monitoring

```python
guard = AgentGuard(GuardConfig(token_limit=100_000, cost_limit_usd=5.0))
report = guard.record("llm", {"prompt": "..."}, tokens=1500, cost_usd=0.002)
# report.budget.token_pct   → 0.015
# report.budget.is_warning  → False (< 80%)
# report.budget.is_exceeded → False
```

### Output monitoring

Catches the "464MB cat" class of bugs, tool output that is too large, binary, or stuck in a repeated-line loop.

```python
guard = AgentGuard(GuardConfig(output_max_bytes=512_000, output_warn_bytes=100_000))
report = guard.record("bash", {"cmd": "cat bigfile"}, output="A" * 600_000)
# report.action == Action.HALT
```

### Rate limiting

```python
guard = AgentGuard(GuardConfig(rate_halt_cps=25.0, rate_warn_cps=10.0))
# 26 calls/second → Action.HALT
```

## Configuration

```python
from agentguard import AgentGuard, GuardConfig

guard = AgentGuard(GuardConfig(
    # Loop
    exact_threshold=3,
    stall_threshold=5,
    halt_on_loop=True,
    # Danger
    halt_on_severity=9,
    warn_on_severity=6,
    # Budget
    token_limit=50_000,
    cost_limit_usd=2.0,
    # Rate
    rate_halt_cps=25.0,
    rate_warn_cps=10.0,
    # Custom rules file (TOML or JSON)
    rules_file="agentguard.toml",
))
```

### Config file

Generate a starter config:

```bash
agentguard init                     # creates agentguard.toml
agentguard init --output my.toml    # custom path
```

```toml
# agentguard.toml
[guard]
halt_on_severity = 9
warn_on_severity = 6
token_limit      = 100000

[[patterns]]
pattern     = "my_internal_secret_func"
category    = "secrets"
severity    = 8
description = "internal secret function"

[[allowlist]]
tool    = "bash"
pattern = "ls\\s+-la"
reason  = "safe directory listing"
```

Load it:

```python
guard = AgentGuard(GuardConfig(rules_file="agentguard.toml"))
```

## Allowlist

Skip danger checks for known-safe patterns:

```python
from agentguard import AgentGuard, GuardConfig
from agentguard.allowlist import Allowlist

guard = AgentGuard(GuardConfig(
    allowlist=Allowlist.from_list([
        {"tool": "bash", "pattern": r"ls\s+-la", "reason": "safe listing"},
    ])
))
```

## CLI commands

```bash
# Start stateful daemon (enables loop detection across calls)
agentguard serve --port 7420 --halt-severity 9 --token-limit 100000
agentguard serve --webhook-url https://hooks.example.com/alert  # POST on halt/warn

# Check status / reset session
agentguard status
agentguard reset

# One-shot explain (diagnostic output)
agentguard explain bash '{"cmd": "rm -rf /"}'
agentguard explain bash '{"cmd": "sudo apt update"}'

# Analyse a saved session
agentguard audit session.json

# Generate config file
agentguard init

# Claude Code hooks (PreToolUse + PostToolUse)
agentguard hooks                    # print JSON
agentguard hooks --install          # write to ~/.claude/hooks.json
```

## Metis integration

agentguard's `check` command is designed as a Metis PostToolUse hook.

```bash
agentguard hooks --install   # one-time setup
```

Or add to `~/.metis/hooks.toml` manually:

```toml
[[hooks]]
event      = "SessionStart"
command    = "agentguard serve --port 7420"
background = true

[[hooks]]
event   = "PreToolUse"
command = "agentguard check"

[[hooks]]
event   = "PostToolUse"
command = "agentguard check"
```

The daemon maintains session state across calls, enabling loop detection. Without the daemon, `agentguard check` runs stateless (danger + budget only).

## HTTP daemon

```bash
pip install "nakata-agentguard[serve]"
agentguard serve --port 7420
```

```bash
# Record a tool call
curl -s -X POST http://localhost:7420/record \
  -H 'Content-Type: application/json' \
  -d '{"tool":"bash","args":{"cmd":"ls -la"}}'

# Status
curl http://localhost:7420/status

# Multi-session
curl http://localhost:7420/status?session=agent-1

# Prometheus metrics
curl http://localhost:7420/metrics

# Health
curl http://localhost:7420/health

# Reset
curl -X POST http://localhost:7420/reset
curl -X POST "http://localhost:7420/reset?session=all"
```

### Webhook

```bash
agentguard serve --webhook-url https://hooks.example.com/agentguard
```

The daemon POSTs `{"action":"halt","reason":"...","session":"default","ts":1234567890}` to the URL on every halt or warn event. Webhook failures never block the agent.

### Prometheus metrics

`GET /metrics` returns Prometheus text exposition:

```
agentguard_uptime_seconds 42.1
agentguard_active_sessions 3
agentguard_records_total 158
agentguard_tool_calls_total 158
agentguard_loop_events_total 2
agentguard_danger_events_total 4
agentguard_total_tokens 45200
agentguard_total_cost_usd 0.091
```

## Session snapshot

```python
# Save
guard.save("session.json")

# Load and audit
guard2 = AgentGuard.load("session.json")
print(guard2.stats())

# CLI audit
# agentguard audit session.json
```

## nakata cluster

agentguard is part of the [nakata](https://github.com/nakata-app) AI reliability cluster:

- [halluguard](https://github.com/nakata-app/halluguard), reverse-RAG hallucination detector
- [adaptmem](https://github.com/nakata-app/AdaptMem), domain-adapted retrieval memory
- [claimcheck](https://github.com/nakata-app/claimcheck), end-to-end claim verification pipeline
- **agentguard**, agentic loop and safety monitor

## License

MIT
