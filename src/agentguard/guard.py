from __future__ import annotations

import json
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from agentguard.allowlist import Allowlist
from agentguard.detectors import BudgetMonitor, DangerDetector, LoopDetector
from agentguard.detectors.output import OutputFlag, OutputMonitor
from agentguard.detectors.rate import RateMonitor
from agentguard.models import Action, AgentReport, SessionStats, ToolCall


@dataclass
class GuardConfig:
    # ── Loop detector ──────────────────────────────────────────────────────
    exact_window: int = 10
    exact_threshold: int = 3
    near_dup_window: int = 8
    near_dup_threshold: int = 4
    error_loop_window: int = 6
    error_loop_threshold: int = 3
    pattern_min_period: int = 2
    pattern_min_repeats: int = 3
    stall_window: int = 8
    stall_threshold: int = 5
    # ── Danger detector ────────────────────────────────────────────────────
    danger_min_severity: int = 1
    halt_on_severity: int = 9
    warn_on_severity: int = 6
    # ── Budget ─────────────────────────────────────────────────────────────
    token_limit: int | None = None
    cost_limit_usd: float | None = None
    # ── Output monitor ─────────────────────────────────────────────────────
    output_max_bytes: int = 512_000      # 512 KB → halt
    output_warn_bytes: int = 100_000     # 100 KB → warn
    output_check_binary: bool = True
    output_check_repeated: bool = True
    output_check_truncated: bool = True
    # ── Behaviour ──────────────────────────────────────────────────────────
    halt_on_loop: bool = True
    warn_on_danger: bool = True
    halt_on_output_size: bool = True
    # ── Allowlist ──────────────────────────────────────────────────────────
    allowlist: Allowlist = field(default_factory=Allowlist)
    # ── Rate monitor ───────────────────────────────────────────────────────
    rate_window_seconds: float = 5.0
    rate_warn_cps: float = 10.0
    rate_halt_cps: float = 25.0
    halt_on_rate: bool = True
    # ── Custom rules ───────────────────────────────────────────────────────
    rules_file: str | None = None   # path to .toml or .json rules file


class AgentGuard:
    """
    Drop-in agent safety monitor.

    Usage::

        guard = AgentGuard()
        report = guard.record("bash", {"cmd": "ls -la"}, output="file1.txt")
        if report.action == Action.HALT:
            raise RuntimeError(report.reason)
    """

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self._calls: list[ToolCall] = []
        self._loop_events: int = 0
        self._danger_events: int = 0
        self._output_events: int = 0
        self._session_start: float = time.time()
        self._danger_cache: dict[str, list] = {}   # call_key → flags
        # Load custom rules file if specified
        _extra_patterns = None
        if self.config.rules_file:
            from agentguard.rules import load_rules_file
            loaded = load_rules_file(self.config.rules_file)
            _extra_patterns = loaded["patterns"] or None
            # Merge allowlist from rules file
            for entry in loaded["allowlist"]._entries:
                self.config.allowlist._entries.append(entry)
        self._loop = LoopDetector(
            exact_window=self.config.exact_window,
            exact_threshold=self.config.exact_threshold,
            near_dup_window=self.config.near_dup_window,
            near_dup_threshold=self.config.near_dup_threshold,
            error_loop_window=self.config.error_loop_window,
            error_loop_threshold=self.config.error_loop_threshold,
            pattern_min_period=self.config.pattern_min_period,
            pattern_min_repeats=self.config.pattern_min_repeats,
            stall_window=self.config.stall_window,
            stall_threshold=self.config.stall_threshold,
        )
        self._danger = DangerDetector(
            min_severity=self.config.danger_min_severity,
            extra_patterns=_extra_patterns,
        )
        self._budget = BudgetMonitor(
            token_limit=self.config.token_limit,
            cost_limit_usd=self.config.cost_limit_usd,
        )
        self._rate = RateMonitor(
            window_seconds=self.config.rate_window_seconds,
            warn_cps=self.config.rate_warn_cps,
            halt_cps=self.config.rate_halt_cps,
        )
        self._output_monitor = OutputMonitor(
            max_bytes=self.config.output_max_bytes,
            warn_bytes=self.config.output_warn_bytes,
            check_binary=self.config.output_check_binary,
            check_repeated_lines=self.config.output_check_repeated,
            check_truncated=self.config.output_check_truncated,
        )

    # ── Public API ─────────────────────────────────────────────────────────

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
        self._budget.add(tokens, cost_usd)
        report = self._evaluate(call)
        if report.loop:
            self._loop_events += 1
        if report.dangers:
            self._danger_events += 1
        if report.output_flags:
            self._output_events += 1
        return report

    def _evaluate(self, latest: ToolCall) -> AgentReport:
        loop_info = self._loop.check(self._calls)
        budget = self._budget.status()
        output_flags = self._output_monitor.check(latest.output)
        rate_flag = self._rate.check(self._calls)

        # Danger check — skip if allowlisted
        if self.config.allowlist.is_allowed(latest.tool, latest.args):
            dangers = []
            allowlist_reason = self.config.allowlist.matching_reason(latest.tool, latest.args)
        else:
            cache_key = latest.call_key
            if cache_key not in self._danger_cache:
                self._danger_cache[cache_key] = self._danger.check(latest.tool, latest.args)
            dangers = self._danger_cache[cache_key]
            allowlist_reason = None

        action = Action.CONTINUE
        reasons: list[str] = []

        # Budget exceeded → halt
        if budget.is_exceeded:
            action = Action.HALT
            reasons.append(
                f"budget exceeded: {budget.total_tokens} tokens / "
                f"${budget.total_cost_usd:.4f}"
            )

        # Loop → halt
        if loop_info and self.config.halt_on_loop:
            action = Action.HALT
            reasons.append(f"loop detected ({loop_info.description})")

        # Danger → halt or warn
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

        # Output size → halt or warn
        if output_flags:
            max_out_sev = max(f.severity for f in output_flags)
            if max_out_sev >= 8 and self.config.halt_on_output_size:
                if action == Action.CONTINUE:
                    action = Action.HALT
                reasons.append(f"output issue: {output_flags[0].description}")
            elif max_out_sev >= 5 and action == Action.CONTINUE:
                action = Action.WARN
                reasons.append(f"output warning: {output_flags[0].description}")

        # Rate limit
        if rate_flag:
            if rate_flag.severity >= 8 and self.config.halt_on_rate:
                action = Action.HALT
                reasons.append(f"rate limit: {rate_flag.description}")
            elif rate_flag.severity >= 5 and action == Action.CONTINUE:
                action = Action.WARN
                reasons.append(f"rate warning: {rate_flag.description}")

        # Budget warning
        if budget.is_warning and action == Action.CONTINUE:
            action = Action.WARN
            pct = max(budget.token_pct or 0, budget.cost_pct or 0)
            reasons.append(f"budget warning: {pct:.0%} consumed")

        return AgentReport(
            action=action,
            loop=loop_info,
            dangers=dangers,
            output_flags=output_flags,
            rate_flag=rate_flag,
            budget=budget,
            total_calls=len(self._calls),
            reason="; ".join(reasons) if reasons else "ok",
            allowlist_match=allowlist_reason,
        )

    def report(self) -> AgentReport:
        if not self._calls:
            budget = self._budget.status()
            return AgentReport(
                action=Action.CONTINUE,
                loop=None,
                dangers=[],
                output_flags=[],
                rate_flag=None,
                budget=budget,
                total_calls=0,
                reason="no calls recorded",
                allowlist_match=None,
            )
        return self._evaluate(self._calls[-1])

    def stats(self) -> SessionStats:
        tool_freq = dict(Counter(c.tool for c in self._calls))
        errors = [c for c in self._calls if c.output and c.output.startswith("error:")]
        duration = time.time() - self._session_start
        budget = self._budget.status()
        return SessionStats(
            total_calls=len(self._calls),
            unique_tools=list(tool_freq.keys()),
            tool_frequency=tool_freq,
            error_count=len(errors),
            error_rate=len(errors) / len(self._calls) if self._calls else 0.0,
            total_tokens=budget.total_tokens,
            total_cost_usd=budget.total_cost_usd,
            duration_seconds=duration,
            loop_events=self._loop_events,
            danger_events=self._danger_events,
        )

    # ── Convenience booleans ───────────────────────────────────────────────

    def is_looping(self) -> bool:
        return self._loop.check(self._calls) is not None

    def is_over_budget(self) -> bool:
        return self._budget.status().is_exceeded

    def has_danger(self) -> bool:
        if not self._calls:
            return False
        return bool(self._danger.check(self._calls[-1].tool, self._calls[-1].args))

    # ── Snapshot / restore ─────────────────────────────────────────────────

    def snapshot(self) -> dict[str, Any]:
        return {
            "calls": [c.to_dict() for c in self._calls],
            "loop_events": self._loop_events,
            "danger_events": self._danger_events,
            "output_events": self._output_events,
            "session_start": self._session_start,
        }

    def restore(self, data: dict[str, Any]) -> None:
        self._calls = [ToolCall.from_dict(d) for d in data.get("calls", [])]
        self._loop_events = data.get("loop_events", 0)
        self._danger_events = data.get("danger_events", 0)
        self._output_events = data.get("output_events", 0)
        self._session_start = data.get("session_start", time.time())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f, indent=2)

    @classmethod
    def load(cls, path: str, config: GuardConfig | None = None) -> AgentGuard:
        guard = cls(config)
        with open(path, encoding="utf-8") as f:
            guard.restore(json.load(f))
        return guard

    def reset(self) -> None:
        self._calls.clear()
        self._loop_events = 0
        self._danger_events = 0
        self._output_events = 0
        self._session_start = time.time()
        self._budget.reset()
        self._danger_cache.clear()

    @property
    def calls(self) -> list[ToolCall]:
        return list(self._calls)
