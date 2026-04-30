"""
FastAPI daemon for stateful Metis hook integration.

Multiple named sessions supported — pass ?session=<id> to isolate parallel runs.
Default session is "default".

Start:
    agentguard serve [--port 7420] [--halt-severity 9] [--token-limit N]
"""

from __future__ import annotations

from typing import Any

try:
    from fastapi import FastAPI, Query
    from pydantic import BaseModel
    import uvicorn
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from agentguard.guard import AgentGuard, GuardConfig


# ── Session registry ────────────────────────────────────────────────────────

_sessions: dict[str, AgentGuard] = {}
_default_config: GuardConfig = GuardConfig()


def _get_session(session_id: str) -> AgentGuard:
    if session_id not in _sessions:
        _sessions[session_id] = AgentGuard(_default_config)
    return _sessions[session_id]


# ── Pydantic models (module-level to avoid TestClient schema issues) ─────────

if _FASTAPI_AVAILABLE:
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
        loop_type: str | None
        danger_count: int
        max_danger_severity: int
        budget_exceeded: bool
        budget_warning: bool
        total_tokens: int
        total_cost_usd: float


def _to_status(guard: AgentGuard) -> Any:
    report = guard.report()
    return StatusResponse(
        action=report.action.value,
        reason=report.reason,
        total_calls=report.total_calls,
        loop_detected=report.loop is not None,
        loop_type=report.loop.loop_type.value if report.loop else None,
        danger_count=len(report.dangers),
        max_danger_severity=max((d.severity for d in report.dangers), default=0),
        budget_exceeded=report.budget.is_exceeded,
        budget_warning=report.budget.is_warning,
        total_tokens=report.budget.total_tokens,
        total_cost_usd=report.budget.total_cost_usd,
    )


# ── App factory ────────────────────────────────────────────────────────────

def create_app(config: GuardConfig | None = None) -> Any:
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install nakata-agentguard[serve]")

    global _default_config
    _default_config = config or GuardConfig()
    _sessions.clear()

    app = FastAPI(
        title="agentguard",
        version="0.1.0",
        description="Agentic loop and safety monitor daemon",
    )

    @app.post("/record", response_model=StatusResponse)
    def record(
        body: RecordRequest,
        session: str = Query(default="default"),
    ):
        guard = _get_session(session)
        guard.record(
            tool=body.tool,
            args=body.args,
            output=body.output,
            tokens=body.tokens,
            cost_usd=body.cost_usd,
        )
        return _to_status(guard)

    @app.post("/reset")
    def reset(session: str = Query(default="default")):
        if session == "all":
            _sessions.clear()
            return {"status": "ok", "sessions_cleared": "all"}
        if session in _sessions:
            _sessions[session].reset()
        return {"status": "ok", "session": session}

    @app.get("/status", response_model=StatusResponse)
    def status(session: str = Query(default="default")):
        return _to_status(_get_session(session))

    @app.get("/stats")
    def stats(session: str = Query(default="default")):
        s = _get_session(session).stats()
        return {
            "total_calls": s.total_calls,
            "unique_tools": s.unique_tools,
            "tool_frequency": s.tool_frequency,
            "error_count": s.error_count,
            "error_rate": s.error_rate,
            "total_tokens": s.total_tokens,
            "total_cost_usd": s.total_cost_usd,
            "duration_seconds": s.duration_seconds,
            "loop_events": s.loop_events,
            "danger_events": s.danger_events,
        }

    @app.get("/sessions")
    def list_sessions():
        return {"sessions": list(_sessions.keys())}

    @app.get("/health")
    def health():
        return {"status": "ok", "sessions": len(_sessions)}

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
