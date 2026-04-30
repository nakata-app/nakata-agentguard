"""
nakata-agentguard: lightweight agentic loop detector and safety monitor.

Quick start::

    from agentguard import AgentGuard, Action

    guard = AgentGuard()
    report = guard.record("bash", {"cmd": "ls -la"})
    if report.action == Action.HALT:
        raise RuntimeError(report.reason)
"""

from agentguard.allowlist import Allowlist
from agentguard.guard import AgentGuard, GuardConfig
from agentguard.models import (
    Action,
    AgentReport,
    BudgetStatus,
    DangerCategory,
    DangerFlag,
    LoopInfo,
    LoopType,
    SessionStats,
    ToolCall,
)

__version__ = "0.2.0"
__all__ = [
    "AgentGuard",
    "GuardConfig",
    "Allowlist",
    "Action",
    "AgentReport",
    "BudgetStatus",
    "DangerCategory",
    "DangerFlag",
    "LoopInfo",
    "LoopType",
    "SessionStats",
    "ToolCall",
]
