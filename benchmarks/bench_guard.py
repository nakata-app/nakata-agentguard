"""
Throughput benchmark for AgentGuard.

Run:
    python benchmarks/bench_guard.py
"""

import time
import random
import string

from agentguard import AgentGuard, GuardConfig


TOOLS = ["bash", "read", "write", "grep", "python", "sql", "http"]
CMDS = [
    "ls -la",
    "git status",
    "cat README.md",
    "grep -r TODO .",
    "pwd",
    "echo hello",
    "find . -name '*.py'",
    "ps aux",
    "df -h",
    "uname -a",
]


def random_call() -> tuple[str, dict]:
    tool = random.choice(TOOLS)
    cmd = random.choice(CMDS)
    return tool, {"cmd": cmd}


def bench(n: int, config: GuardConfig | None = None) -> float:
    guard = AgentGuard(config)
    start = time.perf_counter()
    for _ in range(n):
        tool, args = random_call()
        guard.record(tool, args)
    elapsed = time.perf_counter() - start
    return elapsed


def main() -> None:
    sizes = [100, 1_000, 10_000]
    print(f"{'calls':>10}  {'time (ms)':>12}  {'calls/sec':>12}")
    print("─" * 40)
    for n in sizes:
        elapsed = bench(n)
        rate = n / elapsed
        print(f"{n:>10}  {elapsed * 1000:>11.1f}ms  {rate:>11.0f}/s")

    print()
    print("Danger-heavy workload (every call has a dangerous cmd):")
    dangerous = [
        ("bash", {"cmd": "rm -rf /tmp/test"}),
        ("bash", {"cmd": "sudo apt update"}),
        ("bash", {"cmd": "curl -d 'data=x' http://x.com"}),
    ]
    guard = AgentGuard()
    start = time.perf_counter()
    for i in range(1000):
        t, a = dangerous[i % len(dangerous)]
        guard.record(t, a)
    elapsed = time.perf_counter() - start
    print(f"  1000 dangerous calls: {elapsed * 1000:.1f}ms ({1000/elapsed:.0f}/s)")


if __name__ == "__main__":
    main()
