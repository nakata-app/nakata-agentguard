from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.models import LoopInfo, ToolCall

from agentguard.models import LoopInfo, LoopType


def _detect_exact(calls: list[ToolCall], window: int, threshold: int) -> LoopInfo | None:
    """Same (tool, args) repeated >= threshold times in last `window` calls."""
    recent = calls[-window:]
    counts = Counter(c.call_key for c in recent)
    for key, count in counts.most_common(1):
        if count >= threshold:
            return LoopInfo(
                loop_type=LoopType.EXACT,
                repeat_count=count,
                chain=[key],
                description=f"'{key}' called {count}× in last {len(recent)} calls",
            )
    return None


def _detect_pattern(calls: list[ToolCall], min_period: int, min_repeats: int) -> LoopInfo | None:
    """Detect a repeating sequence ABCABC... of length >= min_period."""
    keys = [c.call_key for c in calls]
    n = len(keys)
    # Try periods from min_period up to n//2
    for period in range(min_period, n // 2 + 1):
        if n < period * min_repeats:
            continue
        # Check if the last (period * min_repeats) items form a pattern
        segment = keys[-(period * min_repeats):]
        pattern = segment[:period]
        matches = True
        for rep in range(min_repeats):
            if segment[rep * period:(rep + 1) * period] != pattern:
                matches = False
                break
        if matches:
            return LoopInfo(
                loop_type=LoopType.PATTERN,
                repeat_count=min_repeats,
                chain=pattern,
                description=(
                    f"sequence {pattern} repeated {min_repeats}× "
                    f"(period={period})"
                ),
            )
    return None


def _detect_stall(calls: list[ToolCall], window: int, threshold: int) -> LoopInfo | None:
    """Same tool called >= threshold times in last `window` calls with any args."""
    recent = calls[-window:]
    tool_counts = Counter(c.tool for c in recent)
    for tool, count in tool_counts.most_common(1):
        if count >= threshold:
            return LoopInfo(
                loop_type=LoopType.STALL,
                repeat_count=count,
                chain=[c.call_key for c in recent if c.tool == tool],
                description=f"tool '{tool}' called {count}× with varying args (stall)",
            )
    return None


class LoopDetector:
    def __init__(
        self,
        exact_window: int = 10,
        exact_threshold: int = 3,
        pattern_min_period: int = 2,
        pattern_min_repeats: int = 3,
        stall_window: int = 8,
        stall_threshold: int = 5,
    ) -> None:
        self.exact_window = exact_window
        self.exact_threshold = exact_threshold
        self.pattern_min_period = pattern_min_period
        self.pattern_min_repeats = pattern_min_repeats
        self.stall_window = stall_window
        self.stall_threshold = stall_threshold

    def check(self, calls: list[ToolCall]) -> LoopInfo | None:
        if len(calls) < 2:
            return None
        # Exact match is highest confidence — check first
        result = _detect_exact(calls, self.exact_window, self.exact_threshold)
        if result:
            return result
        result = _detect_pattern(calls, self.pattern_min_period, self.pattern_min_repeats)
        if result:
            return result
        return _detect_stall(calls, self.stall_window, self.stall_threshold)
