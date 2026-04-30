"""
CLI entry points:

  agentguard serve      start the FastAPI daemon
  agentguard check      one-shot check (reads from env vars, prints action)
  agentguard status     query a running daemon
  agentguard reset      reset session on a running daemon
"""

from __future__ import annotations

import argparse
import json
import os
import sys


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
    One-shot check — reads METIS_TOOL_NAME + METIS_TOOL_ARGS from env.
    Exits 0 = continue, 1 = warn, 2 = halt.
    Designed to be used directly as a Metis hook command.
    """
    tool = os.environ.get("METIS_TOOL_NAME", "")
    raw_args = os.environ.get("METIS_TOOL_ARGS", "{}")
    if not tool:
        print("[agentguard] METIS_TOOL_NAME not set, skipping", file=sys.stderr)
        sys.exit(0)

    try:
        parsed_args = json.loads(raw_args)
    except json.JSONDecodeError:
        parsed_args = {"raw": raw_args}

    # Try to hit the daemon first; fall back to in-process
    daemon_url = os.environ.get("AGENTGUARD_URL", "http://127.0.0.1:7420")
    try:
        import urllib.request
        payload = json.dumps({"tool": tool, "args": parsed_args}).encode()
        req = urllib.request.Request(
            f"{daemon_url}/record",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            result = json.loads(resp.read())
        action = result.get("action", "continue")
        reason = result.get("reason", "")
    except Exception:
        # Daemon not running — in-process check (no session history)
        from agentguard.guard import AgentGuard, GuardConfig
        config = GuardConfig(
            halt_on_severity=args.halt_severity,
            warn_on_severity=args.warn_severity,
        )
        guard = AgentGuard(config)
        report = guard.record(tool, parsed_args)
        action = report.action.value
        reason = report.reason

    if action == "halt":
        print(f"[agentguard] HALT: {reason}", file=sys.stderr)
        sys.exit(2)
    elif action == "warn":
        print(f"[agentguard] WARN: {reason}", file=sys.stderr)
        sys.exit(1)
    else:
        sys.exit(0)


def cmd_status(args: argparse.Namespace) -> None:
    import urllib.request
    url = f"http://{args.host}:{args.port}/status"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
        print(json.dumps(data, indent=2))
    except Exception as e:
        print(f"[agentguard] could not reach daemon: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_reset(args: argparse.Namespace) -> None:
    import urllib.request
    url = f"http://{args.host}:{args.port}/reset"
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            print(json.loads(resp.read()))
    except Exception as e:
        print(f"[agentguard] reset failed: {e}", file=sys.stderr)
        sys.exit(1)


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

    # check (hook mode)
    p_check = sub.add_parser("check", help="one-shot check from env vars (Metis hook)")
    p_check.add_argument("--halt-severity", type=int, default=9)
    p_check.add_argument("--warn-severity", type=int, default=6)

    # status / reset
    for name in ("status", "reset"):
        p = sub.add_parser(name)
        p.add_argument("--host", default="127.0.0.1")
        p.add_argument("--port", type=int, default=7420)

    args = parser.parse_args()
    if args.command == "serve":
        cmd_serve(args)
    elif args.command == "check":
        cmd_check(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "reset":
        cmd_reset(args)
    else:
        parser.print_help()
        sys.exit(1)
