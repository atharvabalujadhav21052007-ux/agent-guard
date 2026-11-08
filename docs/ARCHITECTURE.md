# AgentGuard Architecture & Security Model

AgentGuard provides a deterministic, zero-dependency defense layer between autonomous LLM agents (AutoGPT, LangChain, CrewAI, Custom Agents) and host operating systems.

```
┌────────────────────────────────────────────────────────┐
│           Autonomous AI Agent / Tool Caller            │
└───────────────────────────┬────────────────────────────┘
                            │ (Candidate Command String)
                            ▼
           ┌─────────────────────────────────┐
           │      AgentGuard Rule Engine     │
           │  • AST & Regex Threat Analysis  │
           │  • Credential Leak Scanner      │
           │  • Destructive Command Blocker  │
           │  • Network Egress Enforcement   │
           └────────────────┬────────────────┘
                            │
               ┌────────────┴────────────┐
               │                         │
     [Violations Found]           [Policy Passed]
               ▼                         ▼
   ┌───────────────────────┐   ┌───────────────────────┐
   │ Execution Intercepted │   │   Sandboxed Runner    │
   │  • Return Status -1   │   │  • Subprocess Jail    │
   │  • Non-zero Exit Code │   │  • Watchdog Timeout   │
   │  • Audit Trail Event  │   │  • Output Buffer Trap │
   └───────────────────────┘   └───────────┬───────────┘
                                           │
                                           ▼
                               ┌───────────────────────┐
                               │  Audit Trail (JSONL)  │
                               └───────────────────────┘
```

## Core Components

1. **`agentguard.rules` (Rule Engine)**
   - Performs rapid pre-execution syntax validation.
   - Detects dangerous file system targets (`/`, `C:\`, `~/.ssh`, `~/.aws`, `.env`).
   - Blocks recursive destruction (`rm -rf`, `del /s`, `format`).
   - Detects exfiltration payloads (`curl -d @.env`, reverse shells, base64 blobs).

2. **`agentguard.runner` (Sandboxed Execution Engine)**
   - Spawns subprocesses within a controlled working directory.
   - Configures non-blocking watchdog timers to prevent hanging / runaway agent loops.
   - Captures stdout/stderr streams cleanly without leaking sensitive handles.

3. **`agentguard.audit` (Compliance Logger)**
   - Emits structured JSON Lines (`agentguard-audit.jsonl`) recording timestamp, rule violations, execution duration, and exit codes.
