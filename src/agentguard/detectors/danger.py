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
    (r"\bnsenter\b",                      DangerCategory.PRIVILEGE_ESCALATION, 9, "nsenter (namespace escape)"),
    (r"\bunshare\b.*--user\b",           DangerCategory.PRIVILEGE_ESCALATION, 8, "unshare user namespace"),
    (r"capabilities.*CAP_SYS_ADMIN",     DangerCategory.PRIVILEGE_ESCALATION, 9, "CAP_SYS_ADMIN capability"),
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
    (r"\bmsfvenom\b",                    DangerCategory.EXFILTRATION, 10, "Metasploit payload generator"),
    (r"\bDNSlog\b|\bdnslog\b",           DangerCategory.EXFILTRATION, 8, "DNS exfiltration via DNSlog"),
    (r"0\.0\.0\.0:\d+.*\brp\b|\bsocat\b.*TCP:", DangerCategory.EXFILTRATION, 8, "socat TCP tunnel"),
    # ── Secrets / credentials ──────────────────────────────────────────────
    (r"~/\.ssh/id_",                     DangerCategory.SECRETS, 9, "SSH private key access"),
    (r"~/\.aws/credentials\b",           DangerCategory.SECRETS, 9, "AWS credentials file"),
    (r"~/\.config/gcloud\b",             DangerCategory.SECRETS, 8, "GCloud config/credentials"),
    (r"PRIVATE KEY",                     DangerCategory.SECRETS, 8, "PEM private key material"),
    (r"\bGHOST_API_KEY\b|\bGITHUB_TOKEN\b|\bGH_TOKEN\b", DangerCategory.SECRETS, 8, "GitHub token"),
    (r"\.env\b",                          DangerCategory.SECRETS, 6, ".env file access (may contain secrets)"),
    (r"\bkeychain\b.*-a\b",              DangerCategory.SECRETS, 7, "macOS keychain access"),
    (r"OPENAI_API_KEY|ANTHROPIC_API_KEY|sk-[a-zA-Z0-9]{20,}", DangerCategory.SECRETS, 9, "AI API key in args"),
    (r"STRIPE_SECRET|STRIPE_SK_LIVE",    DangerCategory.SECRETS, 10, "Stripe live secret key"),
    (r"\.kube/config\b",                 DangerCategory.SECRETS, 8, "Kubernetes kubeconfig"),
    (r"~/.docker/config\.json\b",        DangerCategory.SECRETS, 7, "Docker credentials file"),
    (r"\bvault\s+kv\s+get\b",           DangerCategory.SECRETS, 8, "HashiCorp Vault secret retrieval"),
    (r"\baws\s+secretsmanager\s+get-secret",  DangerCategory.SECRETS, 8, "AWS Secrets Manager access"),
    # ── Network / scanning ────────────────────────────────────────────────
    (r"\bnmap\b",                         DangerCategory.NETWORK, 6, "network scanner (nmap)"),
    (r"\bmasscan\b",                      DangerCategory.NETWORK, 7, "high-speed port scanner"),
    (r"\bshodan\b",                       DangerCategory.NETWORK, 6, "Shodan query"),
    (r"\biptables\b.*-(F|flush)\b",      DangerCategory.NETWORK, 8, "iptables flush (disable firewall)"),
    (r"\bufw\s+disable\b",               DangerCategory.NETWORK, 7, "UFW firewall disable"),
    (r"\barp-scan\b|\barpscan\b",        DangerCategory.NETWORK, 6, "ARP network scanner"),
    (r"\bzmap\b",                         DangerCategory.NETWORK, 7, "ZMap internet scanner"),
    (r"\baircrack-ng\b|\baireplay-ng\b", DangerCategory.NETWORK, 9, "WiFi attack tool"),
    (r"\bettercap\b|\bbettercap\b",      DangerCategory.NETWORK, 9, "network MITM tool"),
    (r"\bhping3?\b",                      DangerCategory.NETWORK, 7, "hping packet crafter"),
    (r"\bsliver\b|\bcobalt.?strike\b",   DangerCategory.NETWORK, 10, "C2 framework"),
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
    (r"\bSELECT\b.*\bUNION\b.*\bSELECT\b", DangerCategory.CODE_INJECTION, 8, "SQL UNION injection"),
    (r"';\s*DROP\b|';\s*DELETE\b|';\s*INSERT\b", DangerCategory.CODE_INJECTION, 9, "SQL injection statement terminator"),
    (r"\bxp_cmdshell\b",                 DangerCategory.CODE_INJECTION, 10, "MSSQL xp_cmdshell"),
    (r"\bdeserialize\b.*yaml\.load\b|\byaml\.load\b(?!.*Loader)", DangerCategory.CODE_INJECTION, 8, "unsafe YAML deserialization"),
    (r"\bSystem\.Reflection\b.*\bInvokeMember\b", DangerCategory.CODE_INJECTION, 8, ".NET reflection invoke"),
    # ── Docker / container destructive ───────────────────────────────────
    (r"\bdocker\s+(rm|rmi)\s+(-f|-a|--all|--force)",  DangerCategory.DESTRUCTIVE, 8, "docker force-remove containers/images"),
    (r"\bdocker\s+system\s+prune\b",     DangerCategory.DESTRUCTIVE, 9, "docker system prune (remove all unused)"),
    (r"\bdocker\s+volume\s+prune\b",     DangerCategory.DESTRUCTIVE, 8, "docker volume prune"),
    (r"\bdocker\s+network\s+rm\b",       DangerCategory.DESTRUCTIVE, 6, "docker network remove"),
    (r"\bdocker\s+run\b.*--privileged",  DangerCategory.PRIVILEGE_ESCALATION, 9, "privileged container (host access)"),
    (r"\bdocker\s+run\b.*-v\s+/:/",     DangerCategory.PRIVILEGE_ESCALATION, 10, "container with host root mount"),
    (r"\bdocker\s+run\b.*--pid=host",   DangerCategory.PRIVILEGE_ESCALATION, 9, "container sharing host PID namespace"),
    (r"\bdocker\s+run\b.*--net=host",   DangerCategory.NETWORK, 7, "container sharing host network"),
    # ── Kubernetes destructive ────────────────────────────────────────────
    (r"\bkubectl\s+delete\b.*--all\b",  DangerCategory.DESTRUCTIVE, 9, "kubectl delete --all resources"),
    (r"\bkubectl\s+delete\s+namespace\b", DangerCategory.DESTRUCTIVE, 9, "kubectl delete namespace"),
    (r"\bhelm\s+uninstall\b|\bhelm\s+delete\b", DangerCategory.DESTRUCTIVE, 8, "Helm release uninstall"),
    (r"\bkubectl\s+drain\b",            DangerCategory.DESTRUCTIVE, 7, "kubectl drain node"),
    (r"\bkubectl\s+cordon\b",           DangerCategory.DESTRUCTIVE, 6, "kubectl cordon node"),
    (r"\bkubectl\s+exec\b.*--\s*(sh|bash|cmd)\b", DangerCategory.CODE_INJECTION, 8, "kubectl exec shell"),
    # ── Git destructive ───────────────────────────────────────────────────
    (r"\bgit\s+(push\b.*--force|-f\b.*push)",        DangerCategory.DESTRUCTIVE, 8, "git force push"),
    (r"\bgit\s+reset\b.*(--hard|HEAD~[2-9])",        DangerCategory.DESTRUCTIVE, 8, "git reset --hard"),
    (r"\bgit\s+clean\b.*-[dDfFx]",                  DangerCategory.DESTRUCTIVE, 7, "git clean -df (delete untracked)"),
    (r"\bgit\s+branch\b.*-[Dd]\s+",                 DangerCategory.DESTRUCTIVE, 6, "git branch delete"),
    (r"\bgit\s+rebase\b.*--onto\b",                 DangerCategory.DESTRUCTIVE, 6, "git rebase --onto (rewrites history)"),
    (r"\bgit\s+filter-branch\b|\bgit\s+filter-repo\b", DangerCategory.DESTRUCTIVE, 8, "git history rewrite"),
    # ── Cloud provider destructive ────────────────────────────────────────
    (r"\baws\s+s3\s+rm\b.*--recursive", DangerCategory.DESTRUCTIVE, 9, "AWS S3 recursive delete"),
    (r"\baws\s+ec2\s+terminate-instances\b", DangerCategory.DESTRUCTIVE, 9, "AWS EC2 terminate instances"),
    (r"\baws\s+rds\s+delete-db-instance\b", DangerCategory.DESTRUCTIVE, 9, "AWS RDS delete DB instance"),
    (r"\baws\s+iam\s+delete-(user|role|group|policy)\b", DangerCategory.DESTRUCTIVE, 8, "AWS IAM identity deletion"),
    (r"\bgcloud\s+(projects|compute|sql|container)\s+delete\b", DangerCategory.DESTRUCTIVE, 9, "GCloud resource deletion"),
    (r"\bterraform\s+destroy\b",         DangerCategory.DESTRUCTIVE, 9, "terraform destroy infrastructure"),
    (r"\bpulumi\s+destroy\b",            DangerCategory.DESTRUCTIVE, 9, "pulumi destroy infrastructure"),
    (r"\baz\s+(group|vm|disk|storage|sql)\s+delete\b", DangerCategory.DESTRUCTIVE, 9, "Azure resource deletion"),
    # ── Supply chain / package injection ─────────────────────────────────
    (r"\bpip\s+install\b.*-i\s+http://", DangerCategory.CODE_INJECTION, 8, "pip install from insecure HTTP index"),
    (r"\bnpm\s+install\b.*--unsafe-perm", DangerCategory.CODE_INJECTION, 7, "npm install --unsafe-perm"),
    (r"\bcurl\b.*\|\s*(bash|sh|python|ruby|perl)\b", DangerCategory.CODE_INJECTION, 10, "curl-pipe-shell execution"),
    (r"\bwget\b.*-O-.*\|\s*(bash|sh)\b", DangerCategory.CODE_INJECTION, 10, "wget-pipe-shell execution"),
    (r"\bnpm\s+publish\b.*--access\s+public", DangerCategory.EXFILTRATION, 6, "npm public package publish"),
    # ── Crypto mining / resource abuse ───────────────────────────────────
    (r"\bxmrig\b|\bccminer\b|\bnbminer\b|\blolminer\b", DangerCategory.NETWORK, 9, "crypto miner binary"),
    (r"\bstratum\+tcp://\b|\bstratum\+ssl://\b", DangerCategory.NETWORK, 9, "crypto mining pool connection"),
    (r"\bmoneroocean\b|\bpool\.minexmr\b|\bnanopool\b", DangerCategory.NETWORK, 9, "crypto mining pool URL"),
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
    def __init__(
        self,
        min_severity: int = 1,
        extra_patterns: list[tuple[str, DangerCategory, int, str]] | None = None,
    ) -> None:
        self.min_severity = min_severity
        if extra_patterns:
            self._compiled = _COMPILED + [
                (re.compile(p, re.IGNORECASE | re.DOTALL), cat, sev, desc)
                for p, cat, sev, desc in extra_patterns
            ]
        else:
            self._compiled = _COMPILED

    def check(self, tool: str, args: dict[str, Any]) -> list[DangerFlag]:
        text = _args_to_text(args)
        flags: list[DangerFlag] = []
        for regex, category, severity, description in self._compiled:
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
