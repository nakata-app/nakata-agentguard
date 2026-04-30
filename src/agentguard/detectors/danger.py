from __future__ import annotations

import json
import re
from typing import Any

from agentguard.models import DangerCategory, DangerFlag

# (pattern, category, severity, description)
_PATTERNS: list[tuple[str, DangerCategory, int, str]] = [
    # Data wipe / destructive filesystem
    (r"\brm\s+-[^\s]*r[^\s]*f\b", DangerCategory.DESTRUCTIVE, 10, "recursive force delete"),
    (r"\brm\s+-[^\s]*f[^\s]*r\b", DangerCategory.DESTRUCTIVE, 10, "recursive force delete"),
    (r"\bdd\s+if=", DangerCategory.DATA_WIPE, 10, "raw disk write via dd"),
    (r"\bshred\b", DangerCategory.DESTRUCTIVE, 8, "secure file wipe"),
    (r"\bformat\s+[a-zA-Z]:", DangerCategory.DATA_WIPE, 10, "Windows drive format"),
    (r"\bmkfs\b", DangerCategory.DATA_WIPE, 9, "filesystem format"),
    (r">\s*/dev/sd[a-z]\b", DangerCategory.DATA_WIPE, 10, "direct disk overwrite"),
    (r"\btruncate\s+--size=0\b", DangerCategory.DESTRUCTIVE, 7, "file truncation to zero"),
    # SQL destructive
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA)\b", DangerCategory.DESTRUCTIVE, 9, "SQL DROP"),
    (r"\bTRUNCATE\s+TABLE\b", DangerCategory.DESTRUCTIVE, 8, "SQL TRUNCATE"),
    (r"\bDELETE\s+FROM\b(?!\s+\w+\s+WHERE)", DangerCategory.DESTRUCTIVE, 7, "DELETE without WHERE"),
    # Privilege escalation
    (r"\bsudo\s+", DangerCategory.PRIVILEGE_ESCALATION, 6, "sudo execution"),
    (r"\bchmod\s+(777|a\+rwx)\b", DangerCategory.PRIVILEGE_ESCALATION, 7, "world-writable permission"),
    (r"\bchown\s+root\b", DangerCategory.PRIVILEGE_ESCALATION, 8, "chown to root"),
    (r"\bsu\s+-\b", DangerCategory.PRIVILEGE_ESCALATION, 8, "switch to root"),
    (r"\bvisudo\b", DangerCategory.PRIVILEGE_ESCALATION, 7, "sudoers edit"),
    (r"/etc/shadow", DangerCategory.PRIVILEGE_ESCALATION, 9, "shadow password file access"),
    (r"/etc/sudoers", DangerCategory.PRIVILEGE_ESCALATION, 8, "sudoers file access"),
    # Exfiltration
    (r"\bcurl\b.*-d\s+[\"@]", DangerCategory.EXFILTRATION, 7, "curl POST with data"),
    (r"\bwget\b.*--post-data\b", DangerCategory.EXFILTRATION, 7, "wget POST"),
    (r"\bscp\b.*@", DangerCategory.EXFILTRATION, 6, "scp to remote host"),
    (r"\brsync\b.*@.*::", DangerCategory.EXFILTRATION, 6, "rsync to remote"),
    (r"\bbase64\b.*\|\s*(curl|wget|nc)\b", DangerCategory.EXFILTRATION, 8, "encoded exfil pipe"),
    (r"\bnc\b.*-[^\s]*e\b", DangerCategory.EXFILTRATION, 9, "netcat reverse shell"),
    (r"\bbash\b.*-i\b.*>&\s*/dev/tcp/", DangerCategory.EXFILTRATION, 10, "bash reverse shell"),
    # Code injection
    (r"\beval\b.*\$\(", DangerCategory.CODE_INJECTION, 8, "eval with command substitution"),
    (r"\bexec\b.*\$\{IFS\}", DangerCategory.CODE_INJECTION, 9, "IFS-based injection"),
    (r"__import__\s*\(\s*['\"]os['\"]", DangerCategory.CODE_INJECTION, 8, "Python os import injection"),
    (r"\bpickle\.loads\b", DangerCategory.CODE_INJECTION, 7, "unsafe pickle deserialization"),
    (r"\bsubprocess\.call\b.*shell=True", DangerCategory.CODE_INJECTION, 7, "shell=True subprocess"),
    (r"\bos\.system\b", DangerCategory.CODE_INJECTION, 6, "os.system call"),
    # Crypto / key material theft
    (r"~/\.ssh/id_", DangerCategory.EXFILTRATION, 9, "SSH private key access"),
    (r"~/\.aws/credentials", DangerCategory.EXFILTRATION, 9, "AWS credential access"),
    (r"PRIVATE KEY", DangerCategory.EXFILTRATION, 8, "private key material in args"),
]

_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), cat, sev, desc) for p, cat, sev, desc in _PATTERNS]


def _args_to_text(args: dict[str, Any]) -> str:
    """Flatten all arg values to a single searchable string."""
    parts = []
    for v in args.values():
        if isinstance(v, str):
            parts.append(v)
        else:
            try:
                parts.append(json.dumps(v))
            except Exception:
                parts.append(str(v))
    return " ".join(parts)


class DangerDetector:
    def __init__(self, min_severity: int = 1) -> None:
        self.min_severity = min_severity

    def check(self, tool: str, args: dict[str, Any]) -> list[DangerFlag]:
        text = _args_to_text(args)
        flags: list[DangerFlag] = []
        for regex, category, severity, description in _COMPILED:
            if severity < self.min_severity:
                continue
            m = regex.search(text)
            if m:
                snippet = text[max(0, m.start() - 20): m.end() + 20].strip()
                flags.append(
                    DangerFlag(
                        category=category,
                        severity=severity,
                        matched_pattern=regex.pattern,
                        tool=tool,
                        args_snippet=snippet,
                        description=description,
                    )
                )
        # De-duplicate: keep highest-severity per category
        seen: dict[DangerCategory, DangerFlag] = {}
        for f in flags:
            if f.category not in seen or f.severity > seen[f.category].severity:
                seen[f.category] = f
        return sorted(seen.values(), key=lambda f: f.severity, reverse=True)
