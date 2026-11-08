# Security Policies & Threat Categories

AgentGuard classifies tool-calling anomalies into four distinct threat tiers:

| Tier | Level | Action Taken | Example Triggers |
| :--- | :--- | :--- | :--- |
| 🔴 **Tier 1** | `CRITICAL` | Immediate Block & Audit Log | `rm -rf /`, `cat ~/.ssh/id_rsa`, `format C:`, `nc -e /bin/sh` |
| 🟠 **Tier 2** | `BLOCKED` | Immediate Block | Obfuscated Base64 PowerShell execution, commands exceeding max length |
| 🟡 **Tier 3** | `WARNING` | Logged (Executed only if allowed) | Unwhitelisted network tools (`curl`, `wget`) when `allow_network=False` |
| 🟢 **Tier 4** | `SAFE` | Allowed & Sandboxed | `pytest`, `npm test`, `git status`, `python -m build` |

---

## Default Protected Files & Directories
- SSH Keys: `~/.ssh/id_rsa`, `id_ed25519`, `authorized_keys`
- Cloud Credentials: `~/.aws/credentials`, `~/.gcp/credentials`
- Environment Variables: `.env`, `.env.local`, `.env.production`
- OS Security Files: `/etc/shadow`, `/etc/passwd`, Windows SAM
