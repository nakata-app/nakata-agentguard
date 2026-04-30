"""Tests for near-duplicate and error-loop detection."""
import pytest
from agentguard.detectors.loop import LoopDetector
from agentguard.models import LoopType, ToolCall


def bash(cmd: str, output: str | None = None) -> ToolCall:
    return ToolCall(tool="bash", args={"cmd": cmd}, output=output)


class TestNearDup:
    def test_number_variant_detected(self):
        d = LoopDetector(near_dup_threshold=4, near_dup_window=6)
        calls = [
            bash("grep -n 1 file.txt"),
            bash("grep -n 2 file.txt"),
            bash("grep -n 3 file.txt"),
            bash("grep -n 4 file.txt"),
        ]
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.NEAR_DUP

    def test_whitespace_variant_detected(self):
        d = LoopDetector(near_dup_threshold=4, near_dup_window=6)
        calls = [
            bash("ls   -la"),
            bash("ls -la"),
            bash("ls  -la"),
            bash("ls -la "),
        ]
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.NEAR_DUP

    def test_truly_different_args_no_trigger(self):
        d = LoopDetector(near_dup_threshold=4)
        calls = [
            bash("ls -la"),
            bash("git status"),
            bash("cat README.md"),
            bash("pwd"),
        ]
        assert d.check(calls) is None


class TestErrorLoop:
    def test_repeated_errors_detected(self):
        # Use different cmds so exact loop doesn't fire first
        d = LoopDetector(error_loop_threshold=3, error_loop_window=6)
        calls = [
            bash("cat missing1.txt", output="error: file not found"),
            bash("cat missing2.txt", output="error: permission denied"),
            bash("cat missing3.txt", output="error: no such file"),
        ]
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.ERROR_LOOP
        assert result.repeat_count == 3

    def test_mixed_errors_and_success_no_trigger(self):
        d = LoopDetector(error_loop_threshold=3, error_loop_window=6)
        calls = [
            bash("cat a.txt", output="error: not found"),
            bash("cat b.txt", output="hello world"),
            bash("cat c.txt", output="error: not found"),
        ]
        result = d.check(calls)
        # Only 2 errors in window — below threshold of 3
        assert result is None or result.loop_type != LoopType.ERROR_LOOP

    def test_error_loop_below_threshold(self):
        d = LoopDetector(error_loop_threshold=4, error_loop_window=6)
        calls = [bash("cmd", output="error: fail")] * 3
        result = d.check(calls)
        # exact loop fires first (same call_key 3x, exact_threshold=3)
        assert result is not None
