"""
FastAPI daemon for stateful Metis hook integration.

Multiple named sessions supported — pass ?session=<id> to isolate parallel runs.
Default session is "default".

Start:
    agentguard serve [--port 7420] [--halt-severity 9] [--token-limit N]
"""

from __future__ import annotations

import json
import time
import urllib.request
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
_webhook_url: str | None = None
_server_start: float = time.time()
_total_records: int = 0


def _get_session(session_id: str) -> AgentGuard:
    if session_id not in _sessions:
        _sessions[session_id] = AgentGuard(_default_config)
    return _sessions[session_id]


def _fire_webhook(action: str, reason: str, session: str) -> None:
    if not _webhook_url:
        return
    payload = json.dumps({
        "action": action,
        "reason": reason,
        "session": session,
        "ts": time.time(),
    }).encode()
    req = urllib.request.Request(
        _webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # never block the agent on webhook failure


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

def create_app(config: GuardConfig | None = None, webhook_url: str | None = None) -> Any:
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install nakata-agentguard[serve]")

    global _default_config, _webhook_url, _server_start, _total_records
    _default_config = config or GuardConfig()
    _webhook_url = webhook_url
    _server_start = time.time()
    _total_records = 0
    _sessions.clear()

    app = FastAPI(
        title="agentguard",
        version="0.3.0",
        description="Agentic loop and safety monitor daemon",
    )

    @app.post("/record", response_model=StatusResponse)
    def record(
        body: RecordRequest,
        session: str = Query(default="default"),
    ):
        global _total_records
        guard = _get_session(session)
        guard.record(
            tool=body.tool,
            args=body.args,
            output=body.output,
            tokens=body.tokens,
            cost_usd=body.cost_usd,
        )
        _total_records += 1
        st = _to_status(guard)
        if st.action in ("halt", "warn"):
            _fire_webhook(st.action, st.reason, session)
        return st

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
        return {"status": "ok", "sessions": len(_sessions), "uptime_seconds": round(time.time() - _server_start, 1)}

    @app.get("/metrics")
    def metrics():
        """Prometheus-compatible text exposition."""
        lines: list[str] = []
        uptime = time.time() - _server_start

        def g(name: str, value: float, help_text: str = "") -> None:
            if help_text:
                lines.append(f"# HELP agentguard_{name} {help_text}")
            lines.append(f"# TYPE agentguard_{name} gauge")
            lines.append(f"agentguard_{name} {value}")

        def c(name: str, value: float, help_text: str = "") -> None:
            if help_text:
                lines.append(f"# HELP agentguard_{name} {help_text}")
            lines.append(f"# TYPE agentguard_{name} counter")
            lines.append(f"agentguard_{name}_total {value}")

        g("uptime_seconds", round(uptime, 1), "Daemon uptime in seconds")
        g("active_sessions", len(_sessions), "Number of active sessions")
        c("records", _total_records, "Total tool calls recorded across all sessions")

        total_calls = total_loops = total_dangers = total_tokens = total_cost = 0.0
        for guard in _sessions.values():
            s = guard.stats()
            total_calls += s.total_calls
            total_loops += s.loop_events
            total_dangers += s.danger_events
            total_tokens += s.total_tokens
            total_cost += s.total_cost_usd

        c("tool_calls", total_calls, "Total tool calls across all sessions")
        c("loop_events", total_loops, "Total loop detections across all sessions")
        c("danger_events", total_dangers, "Total danger detections across all sessions")
        g("total_tokens", total_tokens, "Cumulative tokens used across all sessions")
        g("total_cost_usd", round(total_cost, 6), "Cumulative cost USD across all sessions")

        return "\n".join(lines) + "\n"

    return app


def serve(
    host: str = "127.0.0.1",
    port: int = 7420,
    config: GuardConfig | None = None,
    webhook_url: str | None = None,
    log_level: str = "warning",
) -> None:
    if not _FASTAPI_AVAILABLE:
        raise ImportError("FastAPI not installed. Run: pip install nakata-agentguard[serve]")
    app = create_app(config, webhook_url=webhook_url)
    uvicorn.run(app, host=host, port=port, log_level=log_level)
