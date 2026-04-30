#!/usr/bin/env bash
# Install agentguard and wire it into Metis as a PostToolUse hook.
#
# Usage:
#   bash metis_setup.sh             # install + configure with defaults
#   bash metis_setup.sh --uninstall # remove agentguard hooks from Metis
#   bash metis_setup.sh --port 7421 --halt-severity 8

set -e

AGENTGUARD_PORT=7420
HALT_SEVERITY=9
WARN_SEVERITY=6
TOKEN_LIMIT=""
UNINSTALL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --port)          AGENTGUARD_PORT=$2; shift 2 ;;
        --halt-severity) HALT_SEVERITY=$2; shift 2 ;;
        --warn-severity) WARN_SEVERITY=$2; shift 2 ;;
        --token-limit)   TOKEN_LIMIT=$2; shift 2 ;;
        --uninstall)     UNINSTALL=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

HOOKS_FILE="$HOME/.metis/hooks.toml"

# ── Uninstall ──────────────────────────────────────────────────────────────
if $UNINSTALL; then
    echo "[agentguard] removing hooks from $HOOKS_FILE"
    if [[ -f "$HOOKS_FILE" ]]; then
        python3 - <<'PY'
import re, sys
with open("$HOOKS_FILE") as f:
    content = f.read()
# Remove blocks tagged with # agentguard-managed
cleaned = re.sub(r'\n# agentguard-managed.*?(?=\n\[\[|\Z)', '', content, flags=re.DOTALL)
with open("$HOOKS_FILE", "w") as f:
    f.write(cleaned)
print("[agentguard] hooks removed")
PY
    fi
    exit 0
fi

# ── Install ────────────────────────────────────────────────────────────────
echo "[agentguard] installing nakata-agentguard..."
pip install "nakata-agentguard[serve]" -q

echo "[agentguard] verifying install..."
agentguard --help > /dev/null

# ── Write hooks ────────────────────────────────────────────────────────────
mkdir -p "$HOME/.metis"

TOKEN_LIMIT_FLAG=""
if [[ -n "$TOKEN_LIMIT" ]]; then
    TOKEN_LIMIT_FLAG=" --token-limit $TOKEN_LIMIT"
fi

cat >> "$HOOKS_FILE" << HOOKS

# agentguard-managed — do not edit this block manually
# Run: bash metis_setup.sh --uninstall to remove

[[hooks]]
event      = "SessionStart"
command    = "agentguard serve --port $AGENTGUARD_PORT --halt-severity $HALT_SEVERITY --warn-severity $WARN_SEVERITY$TOKEN_LIMIT_FLAG"
background = true
description = "Start agentguard daemon for this session"

[[hooks]]
event       = "PreToolUse"
command     = "AGENTGUARD_URL=http://127.0.0.1:$AGENTGUARD_PORT agentguard check --halt-severity $HALT_SEVERITY --warn-severity $WARN_SEVERITY"
description = "Check tool args for dangerous patterns before execution"

[[hooks]]
event       = "PostToolUse"
command     = "AGENTGUARD_URL=http://127.0.0.1:$AGENTGUARD_PORT agentguard check"
description = "Check tool output for size/error loops after execution"

[[hooks]]
event       = "SessionEnd"
command     = "agentguard reset --port $AGENTGUARD_PORT 2>/dev/null || true"
description = "Reset agentguard session on exit"
# agentguard-managed-end
HOOKS

echo "[agentguard] hooks written to $HOOKS_FILE"
echo "[agentguard] setup complete. Start a new metis session to activate."
