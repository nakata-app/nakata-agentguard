from __future__ import annotations

import json
import re
from typing import Any

from agentguard.models import DangerCategory, DangerFlag

# (pattern, category, severity, description)
_PATTERNS: list[tuple[str, DangerCategory, int, str]] = [
    # ── Destructive filesystem ─────────────────────────────────────────────
    (r"\brm\s+-[^\s]*r[^\s]*f\b",        DangerCategory.DESTRUCTIVE, 10, "recursive force delete (rm -rf)"),
    (r"\brm\s+-[^\s]*f[^\s]*r\b",        DangerCategory.DESTRUCTIVE, 10, "recursive force delete (rm -fr)"),
    (r"\bfind\b.*-delete\b",             DangerCategory.DESTRUCTIVE, 8,  "find -delete mass file removal"),
    (r"\bfind\b.*-exec\s+rm\b",          DangerCategory.DESTRUCTIVE, 8,  "find -exec rm"),
    (r"\bshred\b",                        DangerCategory.DESTRUCTIVE, 8,  "secure file wipe (shred)"),
    (r"\bwipe\b.*-[rRf]",                DangerCategory.DESTRUCTIVE, 8,  "wipe utility"),
    (r"\bsrm\b",                          DangerCategory.DESTRUCTIVE, 8,  "secure rm"),
    # ── Data wipe / disk ───────────────────────────────────────────────────
    (r"\bdd\s+if=",                       DangerCategory.DATA_WIPE, 10, "raw disk write via dd"),
    (r"\bformat\s+[a-zA-Z]:",            DangerCategory.DATA_WIPE, 10, "Windows drive format"),
    (r"\bmkfs\b",                         DangerCategory.DATA_WIPE,  9, "filesystem format (mkfs)"),
    (r">\s*/dev/sd[a-z]\b",              DangerCategory.DATA_WIPE, 10, "direct block device overwrite"),
    (r">\s*/dev/nvme",                   DangerCategory.DATA_WIPE, 10, "direct NVMe overwrite"),
    (r"\btruncate\s+--size=0\b",         DangerCategory.DATA_WIPE,  7, "file truncation to zero"),
    (r"\bblkdiscard\b",                  DangerCategory.DATA_WIPE,  9, "block device discard"),
    # ── SQL destructive ────────────────────────────────────────────────────
    (r"\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b", DangerCategory.DESTRUCTIVE, 9, "SQL DROP object"),
    (r"\bTRUNCATE\s+TABLE\b",            DangerCategory.DESTRUCTIVE, 8, "SQL TRUNCATE TABLE"),
    (r"\bDELETE\s+FROM\b(?!\s+\w+\s+WHERE)", DangerCategory.DESTRUCTIVE, 7, "DELETE without WHERE"),
    (r"\bALTER\s+TABLE\b.*\bDROP\b",    DangerCategory.DESTRUCTIVE, 7, "ALTER TABLE DROP column"),
    # ── Privilege escalation ───────────────────────────────────────────────
    (r"\bsudo\s+",                        DangerCategory.PRIVILEGE_ESCALATION, 6, "sudo execution"),
    (r"\bsu\s+-\b",                       DangerCategory.PRIVILEGE_ESCALATION, 8, "switch to root (su -)"),
    (r"\bchmod\s+(777|a\+rwx)\b",        DangerCategory.PRIVILEGE_ESCALATION, 7, "world-writable chmod 777"),
    (r"\bchown\s+root\b",                DangerCategory.PRIVILEGE_ESCALATION, 8, "chown to root"),
    (r"\bvisudo\b",                       DangerCategory.PRIVILEGE_ESCALATION, 7, "sudoers edit (visudo)"),
    (r"/etc/shadow\b",                   DangerCategory.PRIVILEGE_ESCALATION, 9, "shadow password file"),
    (r"/etc/sudoers\b",                  DangerCategory.PRIVILEGE_ESCALATION, 8, "sudoers file access"),
    (r"/etc/passwd\b",                   DangerCategory.PRIVILEGE_ESCALATION, 7, "/etc/passwd access"),
    (r"\bpasswd\b.*--stdin\b",           DangerCategory.PRIVILEGE_ESCALATION, 8, "non-interactive passwd change"),
    (r"\busermod\b.*-G\s*sudo\b",        DangerCategory.PRIVILEGE_ESCALATION, 9, "add user to sudo group"),
    (r"\bsetuid\b",                       DangerCategory.PRIVILEGE_ESCALATION, 8, "setuid bit manipulation"),
    # ── Exfiltration ────────────────────────────────────────────────────────
    (r"\bcurl\b.*-d\s+[\"@]",           DangerCategory.EXFILTRATION, 7, "curl POST with data"),
    (r"\bcurl\b.*--data\b",              DangerCategory.EXFILTRATION, 7, "curl --data"),
    (r"\bwget\b.*--post-data\b",         DangerCategory.EXFILTRATION, 7, "wget POST data"),
    (r"\bscp\b.*@",                       DangerCategory.EXFILTRATION, 6, "scp to remote host"),
    (r"\brsync\b.*@.*::",                DangerCategory.EXFILTRATION, 6, "rsync to remote"),
    (r"\bnc\b.*-[^\s]*e\b",             DangerCategory.EXFILTRATION, 9, "netcat with -e (reverse shell)"),
    (r"\bbash\b.*-i\b.*>&\s*/dev/tcp/", DangerCategory.EXFILTRATION, 10, "bash reverse shell"),
    (r"/dev/tcp/",                        DangerCategory.EXFILTRATION, 10, "bash /dev/tcp redirect"),
    (r"\bbase64\b.*\|\s*(curl|wget|nc)\b", DangerCategory.EXFILTRATION, 8, "base64-encoded exfil pipe"),
    (r"\bpython[23]?\b.*-c.*socket\b",  DangerCategory.EXFILTRATION, 9, "Python socket reverse shell"),
    # ── Secrets / credentials ──────────────────────────────────────────────
    (r"~/\.ssh/id_",                     DangerCategory.SECRETS, 9, "SSH private key access"),
    (r"~/\.aws/credentials\b",           DangerCategory.SECRETS, 9, "AWS credentials file"),
    (r"~/\.config/gcloud\b",             DangerCategory.SECRETS, 8, "GCloud config/credentials"),
    (r"PRIVATE KEY",                     DangerCategory.SECRETS, 8, "PEM private key material"),
    (r"\bGHOST_API_KEY\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b", DangerCategory.SECRETS, 8, "GitHub token"),
    (r"\.env\b",                          DangerCategory.SECRETS, 6, ".env file access (may contain secrets)"),
    (r"\bkeychain\b.*-a\b",              DangerCategory.SECRETS, 7, "macOS keychain access"),
    # ── Network / scanning ────────────────────────────────────────────────
    (r"\bnmap\b",                         DangerCategory.NETWORK, 6, "network scanner (nmap)"),
    (r"\bmasscan\b",                      DangerCategory.NETWORK, 7, "high-speed port scanner"),
    (r"\bshodan\b",                       DangerCategory.NETWORK, 6, "Shodan query"),
    (r"\biptables\b.*-(F|flush)\b",      DangerCategory.NETWORK, 8, "iptables flush (disable firewall)"),
    (r"\bufw\s+disable\b",               DangerCategory.NETWORK, 7, "UFW firewall disable"),
    # ── Code injection ────────────────────────────────────────────────────
    (r"\beval\b.*\$\(",                  DangerCategory.CODE_INJECTION, 8, "eval with command substitution"),
    (r"\$\{IFS\}",                        DangerCategory.CODE_INJECTION, 9, "IFS-based shell injection"),
    (r"__import__\s*\(\s*['\"]os['\"]",  DangerCategory.CODE_INJECTION, 8, "Python os-import injection"),
    (r"\bpickle\.loads\b",               DangerCategory.CODE_INJECTION, 7, "unsafe pickle deserialization"),
    (r"\bsubprocess\.call\b.*shell=True", DangerCategory.CODE_INJECTION, 7, "subprocess shell=True"),
    (r"\bos\.system\b",                  DangerCategory.CODE_INJECTION, 6, "os.system()"),
    (r"\bexec\s*\(",                      DangerCategory.CODE_INJECTION, 6, "exec() call"),
    (r"\bcompile\s*\(.*exec\b",          DangerCategory.CODE_INJECTION, 7, "compile+exec code injection"),
    (r"<script\b",                        DangerCategory.CODE_INJECTION, 7, "XSS script injection"),
    (r"javascript:",                      DangerCategory.CODE_INJECTION, 7, "javascript: URI injection"),
]

_COMPILED = [
    (re.compile(p, re.IGNORECASE | re.DOTALL), cat, sev, desc)
    for p, cat, sev, desc in _PATTERNS
]


def _args_to_text(args: dict[str, Any]) -> str:
    parts: list[str] = []
    for v in args.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, dict)):
            try:
                parts.append(json.dumps(v))
            except Exception:
                parts.append(str(v))
        else:
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
                start = max(0, m.start() - 25)
                snippet = text[start: m.end() + 25].strip()
                flags.append(DangerFlag(
                    category=category,
                    severity=severity,
                    matched_pattern=regex.pattern,
                    tool=tool,
                    args_snippet=snippet,
                    description=description,
                ))
        # Keep highest-severity per category
        seen: dict[DangerCategory, DangerFlag] = {}
        for f in flags:
            if f.category not in seen or f.severity > seen[f.category].severity:
                seen[f.category] = f
        return sorted(seen.values(), key=lambda f: f.severity, reverse=True)
