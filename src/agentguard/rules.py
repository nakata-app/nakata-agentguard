"""
Custom rule loading from TOML or JSON files.

Rule file format (TOML):

    [[rules]]
    pattern  = "kubectl delete"
    category = "destructive"
    severity = 8
    description = "kubectl delete without --dry-run"

    [[rules]]
    pattern  = "DROP KEYSPACE"
    category = "destructive"
    severity = 9
    description = "Cassandra keyspace drop"

    [[allowlist]]
    pattern = "rm -rf /tmp/build"
    tool    = "bash"
    reason  = "CI build cleanup"

JSON equivalent uses the same schema as a dict with "rules" and "allowlist" arrays.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentguard.allowlist import Allowlist
from agentguard.models import DangerCategory

_VALID_CATEGORIES = {c.value for c in DangerCategory}


def _parse_rules(raw: list[dict[str, Any]]) -> list[tuple[str, DangerCategory, int, str]]:
    out = []
    for r in raw:
        pattern = r.get("pattern", "")
        raw_cat = r.get("category", "destructive")
        if raw_cat not in _VALID_CATEGORIES:
            raise ValueError(
                f"Invalid category '{raw_cat}'. Valid: {sorted(_VALID_CATEGORIES)}"
            )
        category = DangerCategory(raw_cat)
        severity = int(r.get("severity", 7))
        if not (1 <= severity <= 10):
            raise ValueError(f"Severity must be 1-10, got {severity}")
        description = r.get("description", pattern)
        out.append((pattern, category, severity, description))
    return out


def _parse_allowlist(raw: list[dict[str, Any]]) -> Allowlist:
    return Allowlist.from_list(raw)


def load_rules_file(path: str | Path) -> dict[str, Any]:
    """
    Load a rules file (TOML or JSON).

    Returns dict with keys:
      "patterns": list of (pattern, category, severity, description)
      "allowlist": Allowlist instance
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Rules file not found: {path}")

    suffix = p.suffix.lower()
    if suffix == ".toml":
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # fallback
            except ImportError:
                raise ImportError(
                    "TOML support requires Python 3.11+ or: pip install tomli"
                )
        with open(p, "rb") as f:
            data = tomllib.load(f)
    elif suffix in (".json", ".jsonc"):
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
    else:
        raise ValueError(f"Unsupported rules file format: {suffix} (use .toml or .json)")

    patterns = _parse_rules(data.get("patterns", data.get("rules", [])))
    allowlist = _parse_allowlist(data.get("allowlist", []))

    return {"patterns": patterns, "allowlist": allowlist, "raw": data}
