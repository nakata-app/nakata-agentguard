"""Basic usage examples for nakata-agentguard."""

from agentguard import Action, AgentGuard, GuardConfig

# 1. Drop-in guard with defaults
guard = AgentGuard()

tools = [
    ("bash", {"cmd": "git status"}),
    ("bash", {"cmd": "git diff HEAD"}),
    ("read", {"path": "README.md"}),
    ("bash", {"cmd": "git status"}),  # repeat
    ("bash", {"cmd": "git status"}),  # repeat
    ("bash", {"cmd": "git status"}),  # repeat — loop!
]

for tool, args in tools:
    report = guard.record(tool, args)
    print(f"{tool:10} → {report.action.value:8}  {report.reason}")
    if report.action == Action.HALT:
        print("Agent halted.")
        break

print()

# 2. Dangerous command detection
guard2 = AgentGuard()
report = guard2.record("bash", {"cmd": "rm -rf /home/user/important"})
print(f"Dangerous call: {report.action.value} — {report.reason}")

print()

# 3. Budget monitoring
guard3 = AgentGuard(GuardConfig(token_limit=1000, cost_limit_usd=0.10))
for i in range(5):
    report = guard3.record("llm", {"prompt": f"step {i}"}, tokens=250, cost_usd=0.025)
    print(f"step {i}: tokens={report.budget.total_tokens}  action={report.action.value}")
    if report.action == Action.HALT:
        break
