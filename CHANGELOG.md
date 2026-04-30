# Changelog

## [0.4.0] - 2026-04-30

### Added
- `agentguard init`, generate a commented `agentguard.toml` starter config in the current directory
- `agentguard hooks [--install]`, generate Claude Code PreToolUse/PostToolUse hooks JSON; `--install` writes to `~/.claude/hooks.json`
- `agentguard serve --webhook-url <url>`, POST `{action, reason, session, ts}` to a URL on every halt/warn event; failures never block the agent
- `GET /metrics`, Prometheus text exposition (uptime, active sessions, total records, loop/danger events, tokens, cost)
- `GET /health`, now includes `uptime_seconds`
- `python -m agentguard`, package now executable as a module via `__main__.py`
- `GuardConfig.from_file(path)`, load a TOML/JSON rules file directly into a `GuardConfig` instance
- GitHub Actions CI: lint (ruff) + test (pytest) on Python 3.10, 3.11, 3.12; auto-publish to PyPI on version tags
- 49 new tests covering Docker/K8s/git/cloud/supply-chain/crypto-mining patterns, CLI commands, webhook, metrics

### Fixed
- gcloud delete pattern now matches subresource commands (`gcloud compute instances delete`)
- `ruff E501` suppressed for danger.py (regex patterns are intentionally long)
- Import ordering in server.py and test files

## [0.3.0] - 2026-04-30

### Added
- `agentguard explain <tool> [args]`, rich one-shot diagnostic: colored action, per-danger severity, loop/output/allowlist context
- `RateMonitor` detector: halt/warn when calls/second exceeds threshold in a sliding window
- Custom rules file loader (`rules.py`): TOML/JSON files can add extra danger patterns and allowlist entries
- `GuardConfig.rules_file`, path to a rules file, loaded at `AgentGuard` init
- Danger patterns expanded from 63 to 110+:
  - Docker: `system prune`, `--privileged`, host root mount, `--pid=host`
  - Kubernetes: `kubectl delete --all`, namespace deletion, `helm uninstall`, `kubectl exec` shell
  - Git: `push --force`, `reset --hard`, `clean -df`, `filter-branch`
  - Cloud: `aws s3 rm --recursive`, `aws ec2 terminate-instances`, `terraform destroy`, `pulumi destroy`, `gcloud ... delete`, `az ... delete`
  - Supply chain: `curl | bash`, `wget | sh`, `pip install http://`
  - Crypto mining: xmrig, ccminer, stratum+tcp://
  - Secrets: OpenAI/Anthropic API keys, Stripe live keys, kubeconfig, Docker credentials, Vault, AWS Secrets Manager
  - Network: ettercap, aircrack-ng, ZMap, hping, C2 frameworks (Sliver, Cobalt Strike)
  - Injection: SQL UNION, statement terminator (`'; DROP`), xp_cmdshell, unsafe YAML, .NET reflection
  - Privilege: nsenter, unshare --user, CAP_SYS_ADMIN

## [0.2.0] - 2026-04-30

### Added
- Near-duplicate loop detection (args differ only in whitespace/numbers)
- Error-loop detection (tool returning errors repeatedly)
- Pattern loop detection (ABCABC repeating sequence)
- Stall detection (same tool, varying args)
- Output size monitor: configurable byte limits (halt/warn), binary detection, repeated-line detection
- Allowlist: exempt specific tool/arg patterns from danger checks
- Session stats: `guard.stats()` returns `SessionStats` with tool frequency, error rate, etc.
- `AgentReport.output_flags` and `AgentReport.allowlist_match` fields
- `AgentReport.to_dict()` for JSON serialisation
- Snapshot/restore: `guard.save()`, `AgentGuard.load()`, `guard.snapshot()`, `guard.restore()`
- Multi-session HTTP daemon: `?session=<id>` query param
- `/stats`, `/sessions` endpoints on daemon
- `agentguard audit <file>` CLI command for session analysis
- `agentguard status` / `agentguard reset` CLI commands with colored output
- Danger patterns expanded to 63, added SECRETS and NETWORK categories
- Metis integration: `examples/metis_setup.sh` for one-command hook wiring
- Benchmark suite in `benchmarks/`
- CONTRIBUTING.md, SECURITY.md, Makefile, pre-commit config

### Fixed
- Pattern loop detector was O(n²) in session length, now O(window²) with configurable cap
- Budget monitor was O(n) per call, now O(1) with running totals
- `args_hash` and `call_key` recomputed on every access, now `cached_property`
- Danger detector re-runs regexes for identical calls, now cached by call_key
- Combined: 1664x throughput improvement at 10,000 calls

### Performance
| calls | before | after |
|---|---|---|
| 100 | 0.19 ms/call | 0.10 ms/call |
| 1,000 | 0.16 ms/call | 0.046 ms/call |
| 10,000 | 65 ms/call | 0.039 ms/call |
| danger-heavy 1k | 0.10 ms/call | 0.0087 ms/call |

## [0.1.0] - 2026-04-30

### Added
- `AgentGuard` main class with `record()`, `report()`, `reset()` API
- `LoopDetector`: exact, pattern, and stall loop detection
- `DangerDetector`: 30+ regex patterns across 5 categories
- `BudgetMonitor`: token and cost limit tracking with warning thresholds
- `GuardConfig` dataclass for full configuration
- FastAPI HTTP daemon (`agentguard serve`) for stateful session monitoring
- `agentguard check` hook command for Metis PostToolUse integration
- Zero required dependencies (core is pure Python)
- 44 tests, 100% pass rate
