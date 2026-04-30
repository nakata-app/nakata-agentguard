"""
Rate-limit detector: catches agents calling tools too fast.

An agent hammering the same tool 20+ times per second is almost
certainly stuck or malfunctioning, not doing useful work.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from agentguard.models import ToolCall


@dataclass
class RateFlag:
    calls_per_second: float
    window_seconds: float
    call_count: int
    description: str
    severity: int   # 1-10


class RateMonitor:
    def __init__(
        self,
        window_seconds: float = 5.0,
        warn_cps: float = 10.0,    # calls per second → warn
        halt_cps: float = 25.0,    # calls per second → halt
    ) -> None:
        self.window_seconds = window_seconds
        self.warn_cps = warn_cps
        self.halt_cps = halt_cps

    def check(self, calls: list[ToolCall]) -> RateFlag | None:
        if len(calls) < 3:
            return None
        now = time.time()
        cutoff = now - self.window_seconds
        recent = [c for c in calls if c.timestamp >= cutoff]
        if len(recent) < 3:
            return None
        duration = max(recent[-1].timestamp - recent[0].timestamp, 0.001)
        cps = len(recent) / duration

        if cps >= self.halt_cps:
            return RateFlag(
                calls_per_second=cps,
                window_seconds=self.window_seconds,
                call_count=len(recent),
                description=(
                    f"{cps:.0f} calls/sec in last {self.window_seconds}s "
                    f"(halt threshold: {self.halt_cps})"
                ),
                severity=8,
            )
        if cps >= self.warn_cps:
            return RateFlag(
                calls_per_second=cps,
                window_seconds=self.window_seconds,
                call_count=len(recent),
                description=(
                    f"{cps:.0f} calls/sec in last {self.window_seconds}s "
                    f"(warn threshold: {self.warn_cps})"
                ),
                severity=5,
            )
        return None
