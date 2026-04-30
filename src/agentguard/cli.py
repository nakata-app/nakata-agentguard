"""
CLI entry points:

  agentguard serve      start the FastAPI daemon
  agentguard check      one-shot check (reads from Metis env vars)
  agentguard status     query a running daemon
  agentguard reset      reset session on a running daemon
  agentguard audit <file>  analyse a saved session snapshot
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any


# ── Helpers ────────────────────────────────────────────────────────────────

def _post_to_daemon(url: str, payload: dict[str, Any], timeout: float = 2.0) -> dict[str, Any] | None:
    import urllib.request
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _get_from_daemon(url: str, timeout: float = 2.0) -> dict[str, Any] | None:
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _color(text: str, code: str) -> str:
    """ANSI colour if stdout is a tty."""
    if sys.stderr.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


HALT_COLOR = "31;1"   # bold red
WARN_COLOR = "33;1"   # bold yellow
OK_COLOR   = "32"     # green


# ── Commands ───────────────────────────────────────────────────────────────

def cmd_serve(args: argparse.Namespace) -> None:
    from agentguard.guard import GuardConfig
    from agentguard.server import serve

    config = GuardConfig(
        halt_on_severity=args.halt_severity,
        warn_on_severity=args.warn_severity,
        token_limit=args.token_limit,
        cost_limit_usd=args.cost_limit,
        exact_threshold=args.exact_threshold,
        stall_threshold=args.stall_threshold,
    )
    print(f"[agentguard] daemon starting on {args.host}:{args.port}", flush=True)
    serve(host=args.host, port=args.port, config=config)


def cmd_check(args: argparse.Namespace) -> None:
    """
    One-shot check — reads Metis env vars.

    PreToolUse:  METIS_TOOL_NAME + METIS_TOOL_ARGS
    PostToolUse: METIS_TOOL_NAME + METIS_TOOL_RESULT

    Exit codes:
      0  → continue
      1  → warn (printed to stderr, Metis blocks if configured)
      2  → halt (Metis blocks the turn)
    """
    tool = os.environ.get("METIS_TOOL_NAME", "")
    if not tool:
        sys.exit(0)

    raw_args = os.environ.get("METIS_TOOL_ARGS", "")
    raw_result = os.environ.get("METIS_TOOL_RESULT", "")

    try:
        parsed_args: dict[str, Any] = json.loads(raw_args) if raw_args else {}
    except json.JSONDecodeError:
        parsed_args = {"raw": raw_args}

    daemon_url = os.environ.get("AGENTGUARD_URL", "http://127.0.0.1:7420")
    result = _post_to_daemon(
        f"{daemon_url}/record",
        {
            "tool": tool,
            "args": parsed_args,
            "output": raw_result or None,
        },
    )

    if result is None:
        # Daemon not running — stateless in-process check
        from agentguard.guard import AgentGuard, GuardConfig
        guard = AgentGuard(GuardConfig(
            halt_on_severity=args.halt_severity,
            warn_on_severity=args.warn_severity,
        ))
        report = guard.record(tool, parsed_args, output=raw_result or None)
        action = report.action.value
        reason = report.reason
    else:
        action = result.get("action", "continue")
        reason = result.get("reason", "")

    if action == "halt":
        print(_color(f"[agentguard] HALT: {reason}", HALT_COLOR), file=sys.stderr)
        sys.exit(2)
    elif action == "warn":
        print(_color(f"[agentguard] WARN: {reason}", WARN_COLOR), file=sys.stderr)
        sys.exit(1)
    else:
        sys.exit(0)


def cmd_status(args: argparse.Namespace) -> None:
    result = _get_from_daemon(f"http://{args.host}:{args.port}/status")
    if result is None:
        print(_color("[agentguard] daemon not reachable", HALT_COLOR), file=sys.stderr)
        sys.exit(1)
    action = result.get("action", "continue")
    color = HALT_COLOR if action == "halt" else WARN_COLOR if action == "warn" else OK_COLOR
    print(_color(f"action: {action}", color))
    print(f"reason: {result.get('reason', '')}")
    print(f"calls:  {result.get('total_calls', 0)}")
    print(f"loops:  {result.get('loop_detected', False)}")
    print(f"dangers: {result.get('danger_count', 0)}")
    print(f"budget_exceeded: {result.get('budget_exceeded', False)}")


def cmd_reset(args: argparse.Namespace) -> None:
    result = _post_to_daemon(f"http://{args.host}:{args.port}/reset", {})
    if result is None:
        print(_color("[agentguard] reset failed — daemon not reachable", HALT_COLOR), file=sys.stderr)
        sys.exit(1)
    print("[agentguard] session reset")


def cmd_audit(args: argparse.Namespace) -> None:
    """Analyse a saved session snapshot and print a report."""
    from agentguard import AgentGuard

    try:
        guard = AgentGuard.load(args.file)
    except FileNotFoundError:
        print(f"[agentguard] file not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    s = guard.stats()
    report = guard.report()

    print(f"{'─'*50}")
    print(f"agentguard session audit: {args.file}")
    print(f"{'─'*50}")
    print(f"Total calls:    {s.total_calls}")
    print(f"Unique tools:   {', '.join(s.unique_tools)}")
    print(f"Error count:    {s.error_count}  ({s.error_rate:.1%})")
    print(f"Loop events:    {s.loop_events}")
    print(f"Danger events:  {s.danger_events}")
    print(f"Total tokens:   {s.total_tokens}")
    print(f"Total cost:     ${s.total_cost_usd:.4f}")
    print(f"Duration:       {s.duration_seconds:.1f}s")
    print()
    print(f"Tool frequency:")
    for tool, count in sorted(s.tool_frequency.items(), key=lambda x: -x[1]):
        print(f"  {tool:20} {count}")
    print()
    action = report.action.value
    color = HALT_COLOR if action == "halt" else WARN_COLOR if action == "warn" else OK_COLOR
    print(_color(f"Final status: {action.upper()} — {report.reason}", color))


def cmd_explain(args: argparse.Namespace) -> None:
    """One-shot explain: check a tool call and print full diagnostic."""
    from agentguard import AgentGuard, GuardConfig

    try:
        tool_args: dict = json.loads(args.args) if args.args else {}
    except json.JSONDecodeError:
        tool_args = {"raw": args.args}

    guard = AgentGuard(GuardConfig(
        halt_on_severity=args.halt_severity,
        warn_on_severity=args.warn_severity,
    ))
    report = guard.record(args.tool, tool_args, output=args.output)

    action = report.action.value
    color = HALT_COLOR if action == "halt" else WARN_COLOR if action == "warn" else OK_COLOR

    print(f"{'─'*55}")
    print(_color(f"  agentguard explain", "1"))
    print(f"{'─'*55}")
    print(f"  tool:    {args.tool}")
    print(f"  args:    {args.args or '{}'}")
    print(f"  action:  {_color(action.upper(), color)}")
    print(f"  reason:  {report.reason}")
    print()

    if report.dangers:
        print(_color("  Danger flags:", HALT_COLOR if any(d.severity >= 9 for d in report.dangers) else WARN_COLOR))
        for d in report.dangers:
            sev_color = HALT_COLOR if d.severity >= 9 else WARN_COLOR
            print(f"    [{_color(str(d.severity), sev_color)}] {d.category.value}: {d.description}")
            print(f"         matched: …{d.args_snippet}…")
    else:
        print(f"  {_color('No danger patterns matched.', OK_COLOR)}")

    if report.loop:
        print()
        print(_color(f"  Loop: {report.loop.loop_type.value}", HALT_COLOR))
        print(f"    {report.loop.description}")

    if report.output_flags:
        print()
        print(_color("  Output issues:", WARN_COLOR))
        for f in report.output_flags:
            print(f"    [{f.severity}] {f.issue.value}: {f.description}")

    if report.allowlist_match:
        print()
        print(_color(f"  Allowlisted: {report.allowlist_match}", OK_COLOR))

    print(f"{'─'*55}")


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(prog="agentguard", description="Agent safety monitor")
    sub = parser.add_subparsers(dest="command")

    # serve
    p_serve = sub.add_parser("serve", help="start daemon")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=7420)
    p_serve.add_argument("--halt-severity", type=int, default=9)
    p_serve.add_argument("--warn-severity", type=int, default=6)
    p_serve.add_argument("--token-limit", type=int, default=None)
    p_serve.add_argument("--cost-limit", type=float, default=None)
    p_serve.add_argument("--exact-threshold", type=int, default=3)
    p_serve.add_argument("--stall-threshold", type=int, default=5)

    # check (Metis hook mode)
    p_check = sub.add_parser("check", help="one-shot check from Metis env vars")
    p_check.add_argument("--halt-severity", type=int, default=9)
    p_check.add_argument("--warn-severity", type=int, default=6)

    # status / reset
    for name in ("status", "reset"):
        p = sub.add_parser(name)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=7420)

    # audit
    p_audit = sub.add_parser("audit", help="analyse a saved session snapshot")
    p_audit.add_argument("file", help="path to session JSON snapshot")

    # explain
    p_explain = sub.add_parser("explain", help="explain why a tool call is flagged")
    p_explain.add_argument("tool", help="tool name (e.g. bash)")
    p_explain.add_argument("args", nargs="?", default="{}", help="JSON args string")
    p_explain.add_argument("--output", default=None, help="tool output string")
    p_explain.add_argument("--halt-severity", type=int, default=9)
    p_explain.add_argument("--warn-severity", type=int, default=6)

    args = parser.parse_args()
    {
        "serve": cmd_serve,
        "check": cmd_check,
        "status": cmd_status,
        "reset": cmd_reset,
        "audit": cmd_audit,
        "explain": cmd_explain,
    }.get(args.command or "", lambda _: (parser.print_help(), sys.exit(1)))(args)
