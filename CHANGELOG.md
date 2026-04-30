# Changelog

## [0.1.0] - 2026-04-30

### Added
- `AgentGuard` main class with `record()`, `report()`, `reset()` API
- `LoopDetector`: exact, pattern, and stall loop detection
- `DangerDetector`: 30+ regex patterns across 5 categories (destructive, data_wipe, privilege_escalation, exfiltration, code_injection)
- `BudgetMonitor`: token and cost limit tracking with warning thresholds
- `GuardConfig` dataclass for full configuration
- FastAPI HTTP daemon (`agentguard serve`) for stateful session monitoring
- `agentguard check` hook command for Metis PostToolUse integration
- Zero required dependencies (core is pure Python)
- 44 tests, 100% pass rate
