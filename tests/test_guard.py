import pytest
from agentguard import Action, AgentGuard, GuardConfig


class TestNormalBehaviour:
    def test_single_safe_call_continues(self):
        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "ls -la"})
        assert report.action == Action.CONTINUE
        assert report.total_calls == 1

    def test_reset_clears_history(self):
        guard = AgentGuard()
        for _ in range(3):
            guard.record("bash", {"cmd": "ls"})
        guard.reset()
        assert guard.report().total_calls == 0


class TestLoopDetection:
    def test_exact_loop_halts(self):
        guard = AgentGuard(GuardConfig(exact_threshold=3, halt_on_loop=True))
        reports = [guard.record("bash", {"cmd": "ls"}) for _ in range(3)]
        assert reports[-1].action == Action.HALT
        assert reports[-1].loop is not None

    def test_loop_disabled_no_halt(self):
        guard = AgentGuard(GuardConfig(exact_threshold=3, halt_on_loop=False, rate_halt_cps=9999, rate_warn_cps=9999))
        reports = [guard.record("bash", {"cmd": "ls"}) for _ in range(5)]
        assert all(r.action == Action.CONTINUE for r in reports)

    def test_is_looping_property(self):
        guard = AgentGuard(GuardConfig(exact_threshold=3))
        for _ in range(2):
            guard.record("bash", {"cmd": "ls"})
        assert not guard.is_looping()
        guard.record("bash", {"cmd": "ls"})
        assert guard.is_looping()


class TestDangerDetection:
    def test_rm_rf_halts(self):
        guard = AgentGuard(GuardConfig(halt_on_severity=9))
        report = guard.record("bash", {"cmd": "rm -rf /"})
        assert report.action == Action.HALT
        assert len(report.dangers) > 0

    def test_sudo_warns(self):
        guard = AgentGuard(GuardConfig(warn_on_severity=6, halt_on_severity=9))
        report = guard.record("bash", {"cmd": "sudo apt update"})
        assert report.action == Action.WARN

    def test_has_danger_property(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "ls"})
        assert not guard.has_danger()

    def test_safe_call_no_danger(self):
        guard = AgentGuard()
        report = guard.record("read", {"path": "/tmp/file.txt"})
        assert report.action == Action.CONTINUE
        assert report.dangers == []


class TestBudget:
    def test_over_token_limit_halts(self):
        guard = AgentGuard(GuardConfig(token_limit=100))
        guard.record("bash", {"cmd": "ls"}, tokens=60)
        report = guard.record("bash", {"cmd": "pwd"}, tokens=50)
        assert report.action == Action.HALT
        assert report.budget.is_exceeded

    def test_budget_warning_at_80pct(self):
        guard = AgentGuard(GuardConfig(token_limit=100))
        report = guard.record("bash", {"cmd": "ls"}, tokens=82)
        assert report.action == Action.WARN
        assert report.budget.is_warning

    def test_is_over_budget_property(self):
        guard = AgentGuard(GuardConfig(token_limit=50))
        guard.record("bash", {"cmd": "ls"}, tokens=60)
        assert guard.is_over_budget()

    def test_cost_limit(self):
        guard = AgentGuard(GuardConfig(cost_limit_usd=1.0))
        guard.record("bash", {"cmd": "ls"}, cost_usd=0.60)
        report = guard.record("bash", {"cmd": "pwd"}, cost_usd=0.50)
        assert report.budget.is_exceeded

    def test_no_budget_always_ok(self):
        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "ls"}, tokens=999_999, cost_usd=999.0)
        # No limits configured — budget status never exceeded
        assert not report.budget.is_exceeded


class TestCombined:
    def test_danger_takes_priority_over_loop_warn(self):
        guard = AgentGuard(GuardConfig(
            halt_on_severity=9,
            halt_on_loop=False,
            exact_threshold=2,
        ))
        guard.record("bash", {"cmd": "ls"})
        # Second call: same (loop) + dangerous
        report = guard.record("bash", {"cmd": "rm -rf /"})
        assert report.action == Action.HALT

    def test_report_without_calls(self):
        guard = AgentGuard()
        report = guard.report()
        assert report.action == Action.CONTINUE
        assert report.total_calls == 0

    def test_reason_populated_on_halt(self):
        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "rm -rf /"})
        assert report.action == Action.HALT
        assert len(report.reason) > 0
        assert "destructive" in report.reason.lower() or "dangerous" in report.reason.lower() or "rm" in report.reason.lower()
