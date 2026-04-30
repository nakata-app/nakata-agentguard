"""
Output size and quality monitor.

Catches the "464MB cat" class of bugs where an agent pipes a massive file
into context, exploding token count and crashing the session.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class OutputIssue(str, Enum):
    TOO_LARGE = "too_large"       # output exceeds byte limit
    BINARY = "binary"             # output looks like binary data
    REPEATED_LINE = "repeated_line"  # same line repeated many times (e.g. log spam)
    TRUNCATED = "truncated"       # output appears to be cut off mid-line


@dataclass
class OutputFlag:
    issue: OutputIssue
    severity: int           # 1-10
    description: str
    output_bytes: int


_BINARY_THRESHOLD = 0.10   # >10% non-printable → binary


def _is_mostly_binary(text: str, sample: int = 512) -> bool:
    chunk = text[:sample]
    non_printable = sum(1 for c in chunk if not c.isprintable() and c not in "\n\r\t")
    return non_printable / max(len(chunk), 1) > _BINARY_THRESHOLD


def _has_repeated_lines(text: str, threshold: int = 20) -> bool:
    lines = text.splitlines()
    if len(lines) < threshold:
        return False
    from collections import Counter
    counts = Counter(lines)
    top_count = counts.most_common(1)[0][1]
    return top_count >= threshold


def _looks_truncated(text: str) -> bool:
    """Heuristic: ends mid-word or mid-line without newline."""
    if not text:
        return False
    stripped = text.rstrip(" \t")
    if stripped and stripped[-1] not in ".!?\"'\n>}])\n":
        # Last char is alphanumeric/identifier — likely truncated
        return stripped[-1].isalnum() or stripped[-1] in "_-/"
    return False


class OutputMonitor:
    def __init__(
        self,
        max_bytes: int = 512_000,      # 512 KB default
        warn_bytes: int = 100_000,     # 100 KB warning
        check_binary: bool = True,
        check_repeated_lines: bool = True,
        repeated_line_threshold: int = 20,
        check_truncated: bool = True,
    ) -> None:
        self.max_bytes = max_bytes
        self.warn_bytes = warn_bytes
        self.check_binary = check_binary
        self.check_repeated_lines = check_repeated_lines
        self.repeated_line_threshold = repeated_line_threshold
        self.check_truncated = check_truncated

    def check(self, output: str | None) -> list[OutputFlag]:
        if not output:
            return []
        flags: list[OutputFlag] = []
        byte_len = len(output.encode("utf-8", errors="replace"))

        if byte_len >= self.max_bytes:
            flags.append(OutputFlag(
                issue=OutputIssue.TOO_LARGE,
                severity=8,
                description=f"output is {byte_len:,} bytes (limit {self.max_bytes:,})",
                output_bytes=byte_len,
            ))
        elif byte_len >= self.warn_bytes:
            flags.append(OutputFlag(
                issue=OutputIssue.TOO_LARGE,
                severity=5,
                description=f"output is {byte_len:,} bytes (warning at {self.warn_bytes:,})",
                output_bytes=byte_len,
            ))

        if self.check_binary and _is_mostly_binary(output):
            flags.append(OutputFlag(
                issue=OutputIssue.BINARY,
                severity=7,
                description="output contains >10% non-printable bytes — likely binary file",
                output_bytes=byte_len,
            ))

        if self.check_repeated_lines and _has_repeated_lines(output, self.repeated_line_threshold):
            flags.append(OutputFlag(
                issue=OutputIssue.REPEATED_LINE,
                severity=6,
                description=f"same line repeated ≥{self.repeated_line_threshold}× in output",
                output_bytes=byte_len,
            ))

        if self.check_truncated and _looks_truncated(output):
            flags.append(OutputFlag(
                issue=OutputIssue.TRUNCATED,
                severity=4,
                description="output appears truncated (ends mid-line)",
                output_bytes=byte_len,
            ))

        return flags
