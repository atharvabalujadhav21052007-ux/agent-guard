"""Structured JSON and console audit logger for agent security events."""

from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, Optional

from .runner import ExecutionResult


class AuditLogger:
    """Manages append-only JSON audit trails for compliance and threat tracking."""

    def __init__(self, log_path: str = "agentguard-audit.jsonl"):
        self.log_path = log_path

    def log_event(self, result: ExecutionResult, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "command": result.command,
            "allowed": result.allowed,
            "exit_code": result.exit_code,
            "duration_sec": result.duration_sec,
            "timed_out": result.timed_out,
            "violations_count": len(result.violations),
            "violations": [
                {
                    "rule": v.rule_name,
                    "threat_level": v.threat_level.value,
                    "description": v.description,
                    "match": v.pattern_matched
                }
                for v in result.violations
            ],
            "metadata": metadata or {}
        }

        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

        return event
