# Security Policy

## Reporting a vulnerability

Email: hey@nakata.app

Please include:
- Description of the issue
- Steps to reproduce
- Potential impact

Do NOT open a public GitHub issue for security vulnerabilities.

Response within 72 hours. Fix target: 14 days for critical, 30 days for others.

## Scope

agentguard is a **detection** tool, not a sandbox. It does not prevent tool execution by itself, it signals to the agent runtime (Metis, your code) that execution should be blocked. The calling code is responsible for enforcement.

**False negatives are expected.** Do not rely on agentguard as your only safety layer. Use it in combination with OS-level permissions, sandboxing (Docker, seccomp), and principle of least privilege.

## Known limitations

- Pattern matching can be bypassed with obfuscation (base64, variable expansion, unicode tricks).
- Loop detection operates on call history held in memory, a process restart resets the counter.
- The HTTP daemon has no authentication. Bind to 127.0.0.1 only (default) and never expose port 7420 externally.
