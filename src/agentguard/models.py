from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import Any


class Action(str, Enum):
    CONTINUE = "continue"
    WARN = "warn"
    HALT = "halt"


class LoopType(str, Enum):
    EXACT = "exact"          # identical (tool, args) seen N times
    NEAR_DUP = "near_dup"    # same tool, args differ only in whitespace/numbers
    ERROR_LOOP = "error_loop"  # tool returning errors repeatedly
    PATTERN = "pattern"      # ABCABC sequence repeating
    STALL = "stall"          # same tool, varied args


class DangerCategory(str, Enum):
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CODE_INJECTION = "code_injection"
    DATA_WIPE = "data_wipe"
    NETWORK = "network"
    SECRETS = "secrets"


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    output: str | None = None
    timestamp: float = field(default_factory=time.time)
    tokens: int = 0
    cost_usd: float = 0.0

    @cached_property
    def args_hash(self) -> str:
        canonical = json.dumps(self.args, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @cached_property
    def call_key(self) -> str:
        return f"{self.tool}:{self.args_hash}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "args": self.args,
            "output": self.output,
            "timestamp": self.timestamp,
            "tokens": self.tokens,
            "cost_usd": self.cost_usd,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolCall:
        return cls(
            tool=d["tool"],
            args=d.get("args", {}),
            output=d.get("output"),
            timestamp=d.get("timestamp", time.time()),
            tokens=d.get("tokens", 0),
            cost_usd=d.get("cost_usd", 0.0),
        )


@dataclass
class DangerFlag:
    category: DangerCategory
    severity: int          # 1-10
    matched_pattern: str
    tool: str
    args_snippet: str
    description: str


@dataclass
class LoopInfo:
    loop_type: LoopType
    repeat_count: int
    chain: list[str]
    description: str


@dataclass
class BudgetStatus:
    total_tokens: int
    total_cost_usd: float
    token_limit: int | None
    cost_limit_usd: float | None
    token_pct: float | None
    cost_pct: float | None

    @property
    def is_exceeded(self) -> bool:
        if self.token_limit and self.total_tokens >= self.token_limit:
            return True
        if self.cost_limit_usd and self.total_cost_usd >= self.cost_limit_usd:
            return True
        return False

    @property
    def is_warning(self) -> bool:
        if self.token_pct and self.token_pct >= 0.80:
            return True
        if self.cost_pct and self.cost_pct >= 0.80:
            return True
        return False


@dataclass
class SessionStats:
    """Aggregate analytics for a guard session."""
    total_calls: int
    unique_tools: list[str]
    tool_frequency: dict[str, int]
    error_count: int
    error_rate: float            # 0.0-1.0
    total_tokens: int
    total_cost_usd: float
    duration_seconds: float
    loop_events: int
    danger_events: int


@dataclass
class AgentReport:
    action: Action
    loop: LoopInfo | None
    dangers: list[DangerFlag]
    budget: BudgetStatus
    total_calls: int
    reason: str
    output_flags: list = field(default_factory=list)   # list[OutputFlag]
    rate_flag: Any = None                               # RateFlag | None
    allowlist_match: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "loop": {
                "loop_type": self.loop.loop_type.value,
                "repeat_count": self.loop.repeat_count,
                "chain": self.loop.chain,
                "description": self.loop.description,
            } if self.loop else None,
            "dangers": [
                {
                    "category": d.category.value,
                    "severity": d.severity,
                    "tool": d.tool,
                    "description": d.description,
                    "args_snippet": d.args_snippet,
                }
                for d in self.dangers
            ],
            "budget": {
                "total_tokens": self.budget.total_tokens,
                "total_cost_usd": self.budget.total_cost_usd,
                "token_pct": self.budget.token_pct,
                "cost_pct": self.budget.cost_pct,
                "is_exceeded": self.budget.is_exceeded,
                "is_warning": self.budget.is_warning,
            },
            "total_calls": self.total_calls,
            "reason": self.reason,
        }
