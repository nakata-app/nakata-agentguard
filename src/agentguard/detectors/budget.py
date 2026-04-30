from __future__ import annotations

from agentguard.models import BudgetStatus, ToolCall


class BudgetMonitor:
    def __init__(
        self,
        token_limit: int | None = None,
        cost_limit_usd: float | None = None,
    ) -> None:
        self.token_limit = token_limit
        self.cost_limit_usd = cost_limit_usd

    def status(self, calls: list[ToolCall]) -> BudgetStatus:
        total_tokens = sum(c.tokens for c in calls)
        total_cost = sum(c.cost_usd for c in calls)

        token_pct = (total_tokens / self.token_limit) if self.token_limit else None
        cost_pct = (total_cost / self.cost_limit_usd) if self.cost_limit_usd else None

        return BudgetStatus(
            total_tokens=total_tokens,
            total_cost_usd=total_cost,
            token_limit=self.token_limit,
            cost_limit_usd=self.cost_limit_usd,
            token_pct=token_pct,
            cost_pct=cost_pct,
        )
