from __future__ import annotations

import re
from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agentguard.models import LoopInfo, ToolCall

from agentguard.models import LoopInfo, LoopType

# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_NUM = re.compile(r"\b\d+\b")


def _normalise_arg(value: str) -> str:
    """Strip whitespace variations and digit differences for near-dup detection."""
    v = _WS.sub(" ", value.strip().lower())
    v = _NUM.sub("N", v)
    return v


def _near_key(call) -> str:  # type: ignore[no-untyped-def]
    """Normalised call key for near-duplicate matching."""
    parts = [call.tool]
    for v in call.args.values():
        if isinstance(v, str):
            parts.append(_normalise_arg(v))
    return ":".join(parts)


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

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
                description=f"'{key}' called {count}x in last {len(recent)} calls",
            )
    return None


def _detect_near_dup(calls: list[ToolCall], window: int, threshold: int) -> LoopInfo | None:
    """Near-duplicate calls: same tool, args that differ only in whitespace/numbers."""
    recent = calls[-window:]
    counts = Counter(_near_key(c) for c in recent)
    for key, count in counts.most_common(1):
        if count >= threshold:
            tool = key.split(":")[0]
            return LoopInfo(
                loop_type=LoopType.NEAR_DUP,
                repeat_count=count,
                chain=[key],
                description=(
                    f"near-duplicate '{tool}' calls {count}x in last {len(recent)} "
                    f"calls (args differ only in whitespace/numbers)"
                ),
            )
    return None


def _detect_error_loop(calls: list[ToolCall], window: int, threshold: int) -> LoopInfo | None:
    """Agent receiving errors repeatedly — trying the same failing thing."""
    recent = calls[-window:]
    errors = [c for c in recent if c.output and c.output.startswith("error:")]
    if len(errors) < threshold:
        return None
    tools = Counter(c.tool for c in errors)
    top_tool, count = tools.most_common(1)[0]
    if count >= threshold:
        return LoopInfo(
            loop_type=LoopType.ERROR_LOOP,
            repeat_count=count,
            chain=[c.call_key for c in errors if c.tool == top_tool],
            description=(
                f"tool '{top_tool}' returned errors {count}x in last {len(recent)} "
                f"calls — agent is stuck on a failing operation"
            ),
        )
    return None


def _detect_pattern(
    calls: list[ToolCall],
    min_period: int,
    min_repeats: int,
    window: int = 30,
) -> LoopInfo | None:
    """Detect a repeating sequence ABCABC... of length >= min_period.

    Only scans the last `window` calls to keep complexity O(window²) not O(n²).
    """
    # Cap to window so this stays O(window^2) regardless of session length
    keys = [c.call_key for c in calls[-window:]]
    n = len(keys)
    max_period = min(n // min_repeats, window // 2)
    for period in range(min_period, max_period + 1):
        if n < period * min_repeats:
            continue
        segment = keys[-(period * min_repeats):]
        pattern = segment[:period]
        matches = all(
            segment[rep * period:(rep + 1) * period] == pattern
            for rep in range(min_repeats)
        )
        if matches:
            return LoopInfo(
                loop_type=LoopType.PATTERN,
                repeat_count=min_repeats,
                chain=pattern,
                description=f"sequence {pattern} repeated {min_repeats}x (period={period})",
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
                description=f"tool '{tool}' called {count}x with varying args (stall)",
            )
    return None


# ---------------------------------------------------------------------------
# Public detector
# ---------------------------------------------------------------------------

class LoopDetector:
    def __init__(
        self,
        exact_window: int = 10,
        exact_threshold: int = 3,
        near_dup_window: int = 8,
        near_dup_threshold: int = 4,
        error_loop_window: int = 6,
        error_loop_threshold: int = 3,
        pattern_min_period: int = 2,
        pattern_min_repeats: int = 3,
        stall_window: int = 8,
        stall_threshold: int = 5,
    ) -> None:
        self.exact_window = exact_window
        self.exact_threshold = exact_threshold
        self.near_dup_window = near_dup_window
        self.near_dup_threshold = near_dup_threshold
        self.error_loop_window = error_loop_window
        self.error_loop_threshold = error_loop_threshold
        self.pattern_min_period = pattern_min_period
        self.pattern_min_repeats = pattern_min_repeats
        self.stall_window = stall_window
        self.stall_threshold = stall_threshold

    def check(self, calls: list[ToolCall]) -> LoopInfo | None:
        if len(calls) < 2:
            return None
        # Priority: exact > near-dup > error-loop > pattern > stall
        return (
            _detect_exact(calls, self.exact_window, self.exact_threshold)
            or _detect_near_dup(calls, self.near_dup_window, self.near_dup_threshold)
            or _detect_error_loop(calls, self.error_loop_window, self.error_loop_threshold)
            or _detect_pattern(calls, self.pattern_min_period, self.pattern_min_repeats)
            or _detect_stall(calls, self.stall_window, self.stall_threshold)
        )
