"""
nakata-agentguard: lightweight agentic loop & safety monitor.

Quick start::

    from agentguard import AgentGuard, Action

    guard = AgentGuard()
    report = guard.record("bash", {"cmd": "ls -la"})
    if report.action == Action.HALT:
        raise RuntimeError(report.reason)
"""

from agentguard.guard import AgentGuard, GuardConfig
from agentguard.models import (
    Action,
    AgentReport,
    BudgetStatus,
    DangerCategory,
    DangerFlag,
    LoopInfo,
    LoopType,
    ToolCall,
)

__version__ = "0.1.0"
__all__ = [
    "AgentGuard",
    "GuardConfig",
    "Action",
    "AgentReport",
    "BudgetStatus",
    "DangerCategory",
    "DangerFlag",
    "LoopInfo",
    "LoopType",
    "ToolCall",
]
