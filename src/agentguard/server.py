"""
FastAPI daemon for Metis hook integration.

Metis PostToolUse hook calls POST /record with tool name + args.
Server returns {action, reason} so the hook can block on HALT.

Start:
    agentguard serve [--port 7420] [--halt-severity 9] [--token-limit N]

Metis hook config (~/.metis/hooks.toml or project):
    [[hooks]]
    event = "PostToolUse"
    command = "agentguard-hook"   # ships with this package

Or manually via curl:
    curl -s -X POST http://localhost:7420/record \
      -H 'Content-Type: application/json' \
      -d '{"tool":"bash","args":{"cmd":"rm -rf /"}}'
"""

from __future__ import annotations

import json
import os
from typing import Any

try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from agentguard.guard import AgentGuard, GuardConfig
from agentguard.models import Action

_guard: AgentGuard | None = None


def _get_guard() -> AgentGuard:
    global _guard
    if _guard is None:
        _guard = AgentGuard()
    return _guard


def create_app(config: GuardConfig | None = None) -> Any:
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install nakata-agentguard[serve]")

    global _guard
    _guard = AgentGuard(config)

    app = FastAPI(title="agentguard", version="0.1.0")

    class RecordRequest(BaseModel):
        tool: str
        args: dict[str, Any] = {}
        output: str | None = None
        tokens: int = 0
        cost_usd: float = 0.0

    class StatusResponse(BaseModel):
        action: str
        reason: str
        total_calls: int
        loop_detected: bool
        danger_count: int
        budget_exceeded: bool

    @app.post("/record", response_model=StatusResponse)
    def record(req: RecordRequest):
        report = _get_guard().record(
            tool=req.tool,
            args=req.args,
            output=req.output,
            tokens=req.tokens,
            cost_usd=req.cost_usd,
        )
        return StatusResponse(
            action=report.action.value,
            reason=report.reason,
            total_calls=report.total_calls,
            loop_detected=report.loop is not None,
            danger_count=len(report.dangers),
            budget_exceeded=report.budget.is_exceeded,
        )

    @app.post("/reset")
    def reset():
        _get_guard().reset()
        return {"status": "ok"}

    @app.get("/status", response_model=StatusResponse)
    def status():
        report = _get_guard().report()
        return StatusResponse(
            action=report.action.value,
            reason=report.reason,
            total_calls=report.total_calls,
            loop_detected=report.loop is not None,
            danger_count=len(report.dangers),
            budget_exceeded=report.budget.is_exceeded,
        )

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


def serve(
    host: str = "127.0.0.1",
    port: int = 7420,
    config: GuardConfig | None = None,
    log_level: str = "warning",
) -> None:
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install nakata-agentguard[serve]")
    app = create_app(config)
    uvicorn.run(app, host=host, port=port, log_level=log_level)
