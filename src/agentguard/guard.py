from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agentguard.detectors import BudgetMonitor, DangerDetector, LoopDetector
from agentguard.models import Action, AgentReport, DangerCategory, ToolCall


@dataclass
class GuardConfig:
    # Loop detector
    exact_window: int = 10
    exact_threshold: int = 3
    pattern_min_period: int = 2
    pattern_min_repeats: int = 3
    stall_window: int = 8
    stall_threshold: int = 5
    # Danger detector
    danger_min_severity: int = 1
    halt_on_severity: int = 9        # severity >= this → HALT
    warn_on_severity: int = 6        # severity >= this → WARN
    # Budget
    token_limit: int | None = None
    cost_limit_usd: float | None = None
    # Behaviour
    halt_on_loop: bool = True
    warn_on_danger: bool = True


class AgentGuard:
    """
    Drop-in agent safety monitor.

    Usage::

        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "ls -la"}, output="...")
        if report.action == Action.HALT:
            raise RuntimeError(report.reason)
    """

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self._calls: list[ToolCall] = []
        self._loop = LoopDetector(
            exact_window=self.config.exact_window,
            exact_threshold=self.config.exact_threshold,
            pattern_min_period=self.config.pattern_min_period,
            pattern_min_repeats=self.config.pattern_min_repeats,
            stall_window=self.config.stall_window,
            stall_threshold=self.config.stall_threshold,
        )
        self._danger = DangerDetector(min_severity=self.config.danger_min_severity)
        self._budget = BudgetMonitor(
            token_limit=self.config.token_limit,
            cost_limit_usd=self.config.cost_limit_usd,
        )

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        output: str | None = None,
        tokens: int = 0,
        cost_usd: float = 0.0,
    ) -> AgentReport:
        call = ToolCall(tool=tool, args=args, output=output, tokens=tokens, cost_usd=cost_usd)
        self._calls.append(call)
        return self._evaluate(call)

    def _evaluate(self, latest: ToolCall) -> AgentReport:
        loop_info = self._loop.check(self._calls)
        dangers = self._danger.check(latest.tool, latest.args)
        budget = self._budget.status(self._calls)

        action = Action.CONTINUE
        reasons: list[str] = []

        # Budget check first — hard limit
        if budget.is_exceeded:
            action = Action.HALT
            reasons.append(
                f"budget exceeded: {budget.total_tokens} tokens / "
                f"${budget.total_cost_usd:.4f}"
            )

        # Loop check
        if loop_info and self.config.halt_on_loop:
            action = Action.HALT
            reasons.append(f"loop detected ({loop_info.description})")

        # Danger check
        if dangers:
            max_sev = max(d.severity for d in dangers)
            if max_sev >= self.config.halt_on_severity:
                action = Action.HALT
                reasons.append(
                    f"dangerous pattern [{dangers[0].category.value}]: "
                    f"{dangers[0].description} (severity {dangers[0].severity})"
                )
            elif max_sev >= self.config.warn_on_severity and action == Action.CONTINUE:
                action = Action.WARN
                reasons.append(
                    f"risky pattern [{dangers[0].category.value}]: "
                    f"{dangers[0].description} (severity {dangers[0].severity})"
                )

        # Budget warning
        if budget.is_warning and action == Action.CONTINUE:
            action = Action.WARN
            pct = max(
                (budget.token_pct or 0),
                (budget.cost_pct or 0),
            )
            reasons.append(f"budget warning: {pct:.0%} consumed")

        reason = "; ".join(reasons) if reasons else "ok"

        return AgentReport(
            action=action,
            loop=loop_info,
            dangers=dangers,
            budget=budget,
            total_calls=len(self._calls),
            reason=reason,
        )

    def report(self) -> AgentReport:
        """Return current status without recording a new call."""
        if not self._calls:
            budget = self._budget.status([])
            from agentguard.models import BudgetStatus
            return AgentReport(
                action=Action.CONTINUE,
                loop=None,
                dangers=[],
                budget=budget,
                total_calls=0,
                reason="no calls recorded",
            )
        return self._evaluate(self._calls[-1])

    def is_looping(self) -> bool:
        return self._loop.check(self._calls) is not None

    def is_over_budget(self) -> bool:
        return self._budget.status(self._calls).is_exceeded

    def has_danger(self) -> bool:
        if not self._calls:
            return False
        return bool(self._danger.check(self._calls[-1].tool, self._calls[-1].args))

    def reset(self) -> None:
        self._calls.clear()

    @property
    def calls(self) -> list[ToolCall]:
        return list(self._calls)
