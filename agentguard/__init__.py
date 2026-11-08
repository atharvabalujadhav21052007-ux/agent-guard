"""
AgentGuard: Lightweight, zero-dependency security firewall & execution sandbox
for autonomous AI agents and LLM tool execution.
"""

from .rules import SecurityPolicy, ThreatLevel, RuleViolation, analyze_command
from .runner import SandboxedRunner, ExecutionResult
from .audit import AuditLogger

__version__ = "0.1.0"
__all__ = [
    "SecurityPolicy",
    "ThreatLevel",
    "RuleViolation",
    "analyze_command",
    "SandboxedRunner",
    "ExecutionResult",
    "AuditLogger",
    "safe_exec"
]

def safe_exec(command: str, timeout: float = 10.0, work_dir: str = None) -> ExecutionResult:
    """Convenience helper to inspect and safely execute an agent command."""
    runner = SandboxedRunner(timeout=timeout, work_dir=work_dir)
    return runner.run(command)
