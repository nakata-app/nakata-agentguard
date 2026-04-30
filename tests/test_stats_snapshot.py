"""Tests for session stats, snapshot, and restore."""
import json
import tempfile
from pathlib import Path

import pytest
from agentguard import AgentGuard, GuardConfig


class TestStats:
    def test_empty_stats(self):
        guard = AgentGuard()
        s = guard.stats()
        assert s.total_calls == 0
        assert s.error_count == 0
        assert s.error_rate == 0.0
        assert s.loop_events == 0
        assert s.danger_events == 0

    def test_tool_frequency(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "ls"})
        guard.record("bash", {"cmd": "pwd"})
        guard.record("read", {"path": "a.txt"})
        s = guard.stats()
        assert s.tool_frequency["bash"] == 2
        assert s.tool_frequency["read"] == 1
        assert set(s.unique_tools) == {"bash", "read"}

    def test_error_rate(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "a"}, output="error: fail")
        guard.record("bash", {"cmd": "b"}, output="ok")
        guard.record("bash", {"cmd": "c"}, output="error: fail")
        s = guard.stats()
        assert s.error_count == 2
        assert abs(s.error_rate - 2 / 3) < 0.01

    def test_token_accumulation(self):
        guard = AgentGuard()
        guard.record("llm", {}, tokens=100, cost_usd=0.01)
        guard.record("llm", {}, tokens=200, cost_usd=0.02)
        s = guard.stats()
        assert s.total_tokens == 300
        assert abs(s.total_cost_usd - 0.03) < 0.0001

    def test_loop_event_counted(self):
        guard = AgentGuard(GuardConfig(exact_threshold=3))
        for _ in range(3):
            guard.record("bash", {"cmd": "ls"})
        s = guard.stats()
        assert s.loop_events >= 1

    def test_danger_event_counted(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "rm -rf /"})
        s = guard.stats()
        assert s.danger_events >= 1


class TestSnapshot:
    def test_snapshot_roundtrip(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "ls"}, output="file.txt", tokens=10)
        guard.record("read", {"path": "a.txt"}, tokens=5)

        snap = guard.snapshot()
        guard2 = AgentGuard()
        guard2.restore(snap)

        assert len(guard2.calls) == 2
        assert guard2.calls[0].tool == "bash"
        assert guard2.calls[1].tool == "read"
        assert guard2.calls[0].tokens == 10

    def test_save_load_file(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "pwd"}, tokens=50, cost_usd=0.005)

        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "session.json")
            guard.save(path)

            guard2 = AgentGuard.load(path)
            assert len(guard2.calls) == 1
            assert guard2.calls[0].tool == "bash"
            assert guard2.calls[0].tokens == 50

    def test_snapshot_is_json_serialisable(self):
        guard = AgentGuard()
        guard.record("bash", {"cmd": "ls"})
        snap = guard.snapshot()
        # Must not raise
        serialised = json.dumps(snap)
        restored = json.loads(serialised)
        assert len(restored["calls"]) == 1

    def test_restore_preserves_event_counts(self):
        guard = AgentGuard(GuardConfig(exact_threshold=3))
        for _ in range(3):
            guard.record("bash", {"cmd": "ls"})
        snap = guard.snapshot()

        guard2 = AgentGuard()
        guard2.restore(snap)
        assert guard2._loop_events == guard._loop_events
