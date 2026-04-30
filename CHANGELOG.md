# Changelog

## [Unreleased]

### Added
- Near-duplicate loop detection (args differ only in whitespace/numbers)
- Error-loop detection (tool returning errors repeatedly)
- Output size monitor: catches the "464MB cat" class of bugs
  - Configurable byte limits (halt/warn), binary detection, repeated line detection
- Allowlist: exempt specific tool/arg patterns from danger checks
- Session stats: `guard.stats()` returns `SessionStats` with tool frequency, error rate, etc.
- `AgentReport.output_flags` and `AgentReport.allowlist_match` fields
- `AgentReport.to_dict()` for JSON serialisation
- Snapshot/restore: `guard.save()`, `AgentGuard.load()`, `guard.snapshot()`, `guard.restore()`
- Multi-session HTTP daemon: `?session=<id>` query param
- `/stats`, `/sessions` endpoints on daemon
- `agentguard audit <file>` CLI command for session analysis
- `agentguard status` / `agentguard reset` CLI commands with colored output
- Danger patterns expanded: 60+ patterns, added SECRETS and NETWORK categories
- Metis integration: `examples/metis_setup.sh` for one-command hook wiring
- `Allowlist.from_list()` for config-file-driven allowlists
- Benchmark suite in `benchmarks/`
- CONTRIBUTING.md, SECURITY.md, Makefile, pre-commit config

### Fixed
- Pattern loop detector was O(n²) in session length, now O(window²) with configurable window cap
- Budget monitor was O(n) per call, now O(1) with running totals
- `args_hash` and `call_key` recomputed on every access, now `cached_property`
- Danger detector re-runs regexes for identical calls, now cached by call_key
- Combined: 1664x throughput improvement at 10,000 calls

### Performance
| calls | before | after |
|-------|--------|-------|
| 100 | 0.19ms/call | 0.10ms/call |
| 1,000 | 0.16ms/call | 0.046ms/call |
| 10,000 | 65ms/call | 0.039ms/call |
| danger-heavy 1k | 0.10ms/call | 0.0087ms/call |

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
