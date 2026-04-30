from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Action(str, Enum):
    CONTINUE = "continue"
    WARN = "warn"
    HALT = "halt"


class LoopType(str, Enum):
    EXACT = "exact"       # identical (tool, args) seen N times
    PATTERN = "pattern"   # ABCABC sequence repeating
    STALL = "stall"       # same tool, marginally different args


class DangerCategory(str, Enum):
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CODE_INJECTION = "code_injection"
    DATA_WIPE = "data_wipe"


@dataclass
class ToolCall:
    tool: str
    args: dict[str, Any]
    output: str | None = None
    timestamp: float = field(default_factory=time.time)
    tokens: int = 0
    cost_usd: float = 0.0

    @property
    def args_hash(self) -> str:
        """Deterministic hash of args (sorted keys, normalised)."""
        canonical = json.dumps(self.args, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    @property
    def call_key(self) -> str:
        return f"{self.tool}:{self.args_hash}"


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
    chain: list[str]       # call_keys involved
    description: str


@dataclass
class BudgetStatus:
    total_tokens: int
    total_cost_usd: float
    token_limit: int | None
    cost_limit_usd: float | None
    token_pct: float | None   # 0.0-1.0, None if no limit
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
class AgentReport:
    action: Action
    loop: LoopInfo | None
    dangers: list[DangerFlag]
    budget: BudgetStatus
    total_calls: int
    reason: str            # human-readable summary for Metis hook output
