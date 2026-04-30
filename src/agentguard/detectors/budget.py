from __future__ import annotations

from agentguard.models import BudgetStatus


class BudgetMonitor:
    """Tracks token and cost totals with O(1) per-call update."""

    def __init__(
        self,
        token_limit: int | None = None,
        cost_limit_usd: float | None = None,
    ) -> None:
        self.token_limit = token_limit
        self.cost_limit_usd = cost_limit_usd
        self._total_tokens: int = 0
        self._total_cost: float = 0.0

    def add(self, tokens: int, cost_usd: float) -> None:
        self._total_tokens += tokens
        self._total_cost += cost_usd

    def status(self) -> BudgetStatus:
        token_pct = (
            self._total_tokens / self.token_limit
            if self.token_limit else None
        )
        cost_pct = (
            self._total_cost / self.cost_limit_usd
            if self.cost_limit_usd else None
        )
        return BudgetStatus(
            total_tokens=self._total_tokens,
            total_cost_usd=self._total_cost,
            token_limit=self.token_limit,
            cost_limit_usd=self.cost_limit_usd,
            token_pct=token_pct,
            cost_pct=cost_pct,
        )

    def reset(self) -> None:
        self._total_tokens = 0
        self._total_cost = 0.0
