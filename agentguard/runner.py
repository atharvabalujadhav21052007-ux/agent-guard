"""Sandboxed subprocess runner with timeout enforcement and violation guards."""

from dataclasses import dataclass, field
import os
import subprocess
import time
from typing import List, Optional

from .rules import SecurityPolicy, ThreatLevel, RuleViolation, analyze_command


@dataclass
class ExecutionResult:
    command: str
    allowed: bool
    exit_code: Optional[int]
    stdout: str
    stderr: str
    duration_sec: float
    violations: List[RuleViolation] = field(default_factory=list)
    timed_out: bool = False


class SandboxedRunner:
    """Safe execution sandbox for commands issued by agentic workflows."""

    def __init__(
        self,
        policy: Optional[SecurityPolicy] = None,
        timeout: float = 10.0,
        work_dir: Optional[str] = None
    ):
        self.policy = policy or SecurityPolicy()
        self.timeout = timeout
        self.work_dir = work_dir or os.getcwd()

    def run(self, command: str) -> ExecutionResult:
        violations = analyze_command(command, self.policy)
        has_critical = any(v.threat_level in (ThreatLevel.BLOCKED, ThreatLevel.CRITICAL) for v in violations)

        if has_critical:
            return ExecutionResult(
                command=command,
                allowed=False,
                exit_code=-1,
                stdout="",
                stderr="AgentGuard: Command blocked by active security policy.",
                duration_sec=0.0,
                violations=violations,
                timed_out=False
            )

        start_time = time.time()
        timed_out = False

        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=self.work_dir,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            duration = round(time.time() - start_time, 4)
            return ExecutionResult(
                command=command,
                allowed=True,
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                duration_sec=duration,
                violations=violations,
                timed_out=False
            )
        except subprocess.TimeoutExpired as exc:
            duration = round(time.time() - start_time, 4)
            return ExecutionResult(
                command=command,
                allowed=True,
                exit_code=-9,
                stdout=exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                stderr=f"AgentGuard: Execution timed out after {self.timeout}s limit.",
                duration_sec=duration,
                violations=violations,
                timed_out=True
            )
        except Exception as exc:
            duration = round(time.time() - start_time, 4)
            return ExecutionResult(
                command=command,
                allowed=True,
                exit_code=-1,
                stdout="",
                stderr=f"Execution error: {str(exc)}",
                duration_sec=duration,
                violations=violations,
                timed_out=False
            )
