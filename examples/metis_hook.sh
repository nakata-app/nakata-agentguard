#!/usr/bin/env bash
# Metis PostToolUse hook — drop this in your .metis/hooks/ directory
# or reference it from hooks.toml.
#
# Metis sets METIS_TOOL_NAME and METIS_TOOL_ARGS before calling the hook.
# Exit code semantics:
#   0  → continue (AGENTGUARD says ok or warn)
#   1  → WARN (printed but execution continues unless Metis is strict)
#   2  → HALT (Metis blocks the tool result and stops the turn)
#
# The hook talks to the agentguard daemon if running; falls back to
# stateless in-process check otherwise.

agentguard check
EXIT=$?

if [ $EXIT -eq 2 ]; then
    echo "[agentguard] halting agent turn" >&2
    exit 1   # Metis interprets non-zero as blocked
fi

exit 0
