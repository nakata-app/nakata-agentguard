"""Tests for output monitor and allowlist."""
import pytest
from agentguard import AgentGuard, Allowlist, GuardConfig, Action
from agentguard.detectors.output import OutputMonitor, OutputIssue


class TestOutputMonitor:
    def test_no_output_clean(self):
        m = OutputMonitor()
        assert m.check(None) == []
        assert m.check("") == []

    def test_small_output_clean(self):
        m = OutputMonitor()
        assert m.check("hello world\n") == []

    def test_large_output_flagged(self):
        m = OutputMonitor(max_bytes=100)
        big = "x" * 200
        flags = m.check(big)
        assert flags
        assert any(f.issue == OutputIssue.TOO_LARGE for f in flags)
        assert max(f.severity for f in flags) >= 8

    def test_warn_range_flagged(self):
        m = OutputMonitor(max_bytes=1000, warn_bytes=100)
        medium = "x" * 200
        flags = m.check(medium)
        assert flags
        assert any(f.issue == OutputIssue.TOO_LARGE for f in flags)
        top_sev = max(f.severity for f in flags)
        assert top_sev < 8  # warn, not halt

    def test_binary_flagged(self):
        m = OutputMonitor()
        binary = "".join(chr(i) for i in range(0, 512))
        flags = m.check(binary)
        assert any(f.issue == OutputIssue.BINARY for f in flags)

    def test_repeated_lines_flagged(self):
        m = OutputMonitor(check_repeated_lines=True)
        repeated = ("same line\n" * 25)
        flags = m.check(repeated)
        assert any(f.issue == OutputIssue.REPEATED_LINE for f in flags)

    def test_normal_log_no_repeated_flag(self):
        m = OutputMonitor()
        log = "\n".join(f"2026-01-01 line {i}" for i in range(30))
        flags = m.check(log)
        assert not any(f.issue == OutputIssue.REPEATED_LINE for f in flags)


class TestOutputInGuard:
    def test_huge_output_halts(self):
        guard = AgentGuard(GuardConfig(
            output_max_bytes=100,
            halt_on_output_size=True,
        ))
        big_output = "x" * 200
        report = guard.record("bash", {"cmd": "cat bigfile"}, output=big_output)
        assert report.action == Action.HALT
        assert report.output_flags

    def test_medium_output_warns(self):
        guard = AgentGuard(GuardConfig(
            output_max_bytes=1000,
            output_warn_bytes=100,
        ))
        medium = "x" * 200
        report = guard.record("bash", {"cmd": "cat file"}, output=medium)
        assert report.action == Action.WARN

    def test_normal_output_continues(self):
        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "ls"}, output="file.txt\nREADME.md\n")
        assert report.output_flags == []


class TestAllowlist:
    def test_allowlisted_danger_skipped(self):
        al = Allowlist()
        al.add(pattern=r"rm -rf /tmp/build", tool="bash", reason="CI cleanup")
        guard = AgentGuard(GuardConfig(allowlist=al))
        report = guard.record("bash", {"cmd": "rm -rf /tmp/build/output"})
        # Allowlisted — should not halt on danger
        assert report.action == Action.CONTINUE
        assert report.allowlist_match is not None
        assert report.dangers == []

    def test_non_allowlisted_danger_still_halts(self):
        al = Allowlist()
        al.add(pattern=r"rm -rf /tmp/build", tool="bash")
        guard = AgentGuard(GuardConfig(allowlist=al))
        report = guard.record("bash", {"cmd": "rm -rf /home/user"})
        assert report.action == Action.HALT

    def test_allowlist_tool_filter(self):
        al = Allowlist()
        al.add(pattern=r"rm -rf", tool="bash")   # only bash
        guard = AgentGuard(GuardConfig(allowlist=al))
        # Different tool — allowlist doesn't apply
        report = guard.record("shell", {"cmd": "rm -rf /tmp"})
        assert report.action == Action.HALT

    def test_allowlist_no_tool_matches_all(self):
        al = Allowlist()
        al.add(pattern=r"rm -rf /tmp/", tool=None)  # any tool
        guard = AgentGuard(GuardConfig(allowlist=al))
        for tool in ("bash", "shell", "exec"):
            g = AgentGuard(GuardConfig(allowlist=al))
            r = g.record(tool, {"cmd": "rm -rf /tmp/test"})
            assert r.action == Action.CONTINUE

    def test_from_list(self):
        al = Allowlist.from_list([
            {"pattern": r"rm -rf /tmp", "tool": "bash", "reason": "safe cleanup"},
        ])
        assert len(al) == 1
        assert al.is_allowed("bash", {"cmd": "rm -rf /tmp/stuff"})
        assert not al.is_allowed("bash", {"cmd": "rm -rf /home"})
