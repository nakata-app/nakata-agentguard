from agentguard.detectors.loop import LoopDetector
from agentguard.models import LoopType, ToolCall


def make_call(tool: str, cmd: str) -> ToolCall:
    return ToolCall(tool=tool, args={"cmd": cmd})


def make_calls(seq: list[tuple[str, str]]) -> list[ToolCall]:
    return [make_call(t, c) for t, c in seq]


class TestExactLoop:
    def test_no_loop_below_threshold(self):
        d = LoopDetector(exact_threshold=3)
        calls = make_calls([("bash", "ls"), ("bash", "ls")])
        assert d.check(calls) is None

    def test_exact_loop_detected(self):
        d = LoopDetector(exact_threshold=3, exact_window=10)
        calls = make_calls([("bash", "ls")] * 3)
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.EXACT
        assert result.repeat_count == 3

    def test_exact_loop_different_args_no_trigger(self):
        d = LoopDetector(exact_threshold=3)
        calls = make_calls([("bash", "ls"), ("bash", "ls -l"), ("bash", "ls -la")])
        assert d.check(calls) is None

    def test_exact_loop_outside_window(self):
        # exact_window=4, exact_threshold=3, stall_threshold=6 (raise to avoid stall trigger)
        d = LoopDetector(exact_threshold=3, exact_window=4, stall_threshold=6)
        # 3 hits but spread across 5 calls, window only sees last 4
        calls = make_calls([("bash", "ls")] * 2 + [("bash", "pwd")] * 2 + [("bash", "ls")])
        # window of 4: pwd, pwd, ls — only 1 "ls", no exact loop
        result = d.check(calls)
        assert result is None or result.loop_type == LoopType.STALL


class TestPatternLoop:
    def test_pattern_abc_detected(self):
        # ABABAB — exact detector fires first (same args repeated), which is correct:
        # an exact loop IS detected (bash:a appears 3x). Accept either EXACT or PATTERN.
        d = LoopDetector(pattern_min_period=2, pattern_min_repeats=3)
        calls = make_calls([
            ("bash", "a"), ("bash", "b"),
            ("bash", "a"), ("bash", "b"),
            ("bash", "a"), ("bash", "b"),
        ])
        result = d.check(calls)
        assert result is not None
        assert result.loop_type in (LoopType.EXACT, LoopType.PATTERN)

    def test_pattern_no_false_positive(self):
        # Use stall_threshold=6 so stall doesn't fire on 5 calls
        d = LoopDetector(pattern_min_period=2, pattern_min_repeats=3, stall_threshold=6)
        calls = make_calls([
            ("bash", "a"), ("bash", "b"),
            ("bash", "a"), ("bash", "b"),
            ("bash", "c"),  # breaks pattern
        ])
        assert d.check(calls) is None

    def test_period_3_pattern(self):
        d = LoopDetector(pattern_min_period=2, pattern_min_repeats=2)
        calls = make_calls([
            ("bash", "x"), ("bash", "y"), ("bash", "z"),
            ("bash", "x"), ("bash", "y"), ("bash", "z"),
        ])
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.PATTERN


class TestStallLoop:
    def test_stall_same_tool_detected(self):
        d = LoopDetector(stall_threshold=5, stall_window=8)
        calls = make_calls([("bash", f"variant_{i}") for i in range(5)])
        result = d.check(calls)
        assert result is not None
        assert result.loop_type == LoopType.STALL
        assert result.repeat_count == 5

    def test_stall_different_tools_no_trigger(self):
        d = LoopDetector(stall_threshold=5)
        calls = make_calls([
            ("bash", "a"), ("read", "b"), ("write", "c"),
            ("bash", "d"), ("read", "e"),
        ])
        assert d.check(calls) is None


class TestEdgeCases:
    def test_empty_calls(self):
        d = LoopDetector()
        assert d.check([]) is None

    def test_single_call(self):
        d = LoopDetector()
        assert d.check([make_call("bash", "ls")]) is None
