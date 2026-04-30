"""
Allowlist support: exempt specific tool/args combinations from danger checks.

Patterns are matched against the tool name and normalised arg string.
Supports exact strings and compiled regexes.
"""

from __future__ import annotations

import json
import re
from typing import Any


class AllowlistEntry:
    def __init__(self, tool: str | None, pattern: str, reason: str = "") -> None:
        self.tool = tool                     # None = any tool
        self.pattern = pattern
        self.reason = reason
        self._regex = re.compile(pattern, re.IGNORECASE | re.DOTALL)

    def matches(self, tool: str, args: dict[str, Any]) -> bool:
        if self.tool and self.tool != tool:
            return False
        text = " ".join(
            v if isinstance(v, str) else json.dumps(v)
            for v in args.values()
        )
        return bool(self._regex.search(text))


class Allowlist:
    """
    Example::

        al = Allowlist()
        al.add(tool="bash", pattern=r"rm -rf /tmp/build", reason="CI cleanup")
        al.add(tool="bash", pattern=r"rm -rf \\.venv", reason="venv cleanup")
    """

    def __init__(self) -> None:
        self._entries: list[AllowlistEntry] = []

    def add(self, pattern: str, tool: str | None = None, reason: str = "") -> None:
        self._entries.append(AllowlistEntry(tool=tool, pattern=pattern, reason=reason))

    def is_allowed(self, tool: str, args: dict[str, Any]) -> bool:
        return any(e.matches(tool, args) for e in self._entries)

    def matching_reason(self, tool: str, args: dict[str, Any]) -> str | None:
        for e in self._entries:
            if e.matches(tool, args):
                return e.reason or e.pattern
        return None

    def __len__(self) -> int:
        return len(self._entries)

    @classmethod
    def from_list(cls, entries: list[dict]) -> Allowlist:
        """
        Load from a list of dicts::

            [{"pattern": "rm -rf /tmp", "tool": "bash", "reason": "CI"}]
        """
        al = cls()
        for e in entries:
            al.add(
                pattern=e["pattern"],
                tool=e.get("tool"),
                reason=e.get("reason", ""),
            )
        return al
