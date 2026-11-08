"""Security policy and rule evaluation engine for commands and tool inputs."""

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import List, Optional, Pattern


class ThreatLevel(str, Enum):
    SAFE = "SAFE"
    WARNING = "WARNING"
    BLOCKED = "BLOCKED"
    CRITICAL = "CRITICAL"


@dataclass
class RuleViolation:
    rule_name: str
    threat_level: ThreatLevel
    description: str
    pattern_matched: str
    command_snippet: str


@dataclass
class SecurityPolicy:
    allow_network: bool = False
    allow_env_reads: bool = False
    max_command_length: int = 4096
    forbidden_commands: List[str] = field(default_factory=lambda: [
        "rm -rf /", "rm -rf *", "mkfs", "dd if=/dev",
        "format c:", "del /f /s /q c:\\", "shutdown",
        ":(){ :|:& };:", "drop database", "sudo rm"
    ])
    whitelisted_prefixes: List[str] = field(default_factory=list)


# Precompiled regex patterns for known threat vectors
DANGEROUS_PATTERNS = [
    # Destructive filesystem actions
    (
        r"(rm\s+-[a-zA-Z]*r[a-zA-Z]*f\s+([/~]|\*|\.\.))|(del\s+/[sfq]\s+[c-z]:)|(format\s+[c-z]:)",
        ThreatLevel.CRITICAL,
        "Destructive recursive deletion or volume format",
        "destructive-fs"
    ),
    # Credential & key extraction
    (
        r"(\.ssh/(id_rsa|id_ed25519|authorized_keys))|(\.aws/credentials)|(\.env\b)|(/etc/shadow)|(/etc/passwd)",
        ThreatLevel.CRITICAL,
        "Attempt to read private keys or authentication secrets",
        "credential-leak"
    ),
    # Reverse shell & socket hijacking
    (
        r"(/dev/tcp/|nc\s+-e|ncat\s+-e|bash\s+-i\s+>&|python[23]?\s+-c\s+.*socket.*connect)",
        ThreatLevel.CRITICAL,
        "Reverse shell or socket hijacking payload",
        "reverse-shell"
    ),
    # Encoded / obfuscated execution
    (
        r"(powershell.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{10,})|(base64\s+-d\s*\|\s*(sh|bash))",
        ThreatLevel.BLOCKED,
        "Obfuscated / Base64 encoded payload execution",
        "obfuscated-exec"
    ),
    # Suspicious exfiltration
    (
        r"(curl|wget|invoke-webrequest)\s+.*(@\.env|--data.*passwd|--post-file.*id_rsa)",
        ThreatLevel.CRITICAL,
        "Direct credential exfiltration via HTTP POST",
        "data-exfiltration"
    ),
    # Fork bombs & system exhaustion
    (
        r"(:(){\s*:\|:&\s*};:)|(%0\|%0)",
        ThreatLevel.CRITICAL,
        "System exhaustion / Fork bomb pattern",
        "fork-bomb"
    )
]


def analyze_command(command: str, policy: Optional[SecurityPolicy] = None) -> List[RuleViolation]:
    """Analyzes a candidate command string against security rules."""
    policy = policy or SecurityPolicy()
    violations: List[RuleViolation] = []
    clean_cmd = command.strip()

    if len(clean_cmd) > policy.max_command_length:
        violations.append(RuleViolation(
            rule_name="max-length",
            threat_level=ThreatLevel.BLOCKED,
            description=f"Command length ({len(clean_cmd)}) exceeds policy limit ({policy.max_command_length})",
            pattern_matched="length_check",
            command_snippet=clean_cmd[:50] + "..."
        ))

    # Check exact forbidden commands
    lower_cmd = clean_cmd.lower()
    for forbidden in policy.forbidden_commands:
        if forbidden.lower() in lower_cmd:
            violations.append(RuleViolation(
                rule_name="forbidden-command",
                threat_level=ThreatLevel.CRITICAL,
                description=f"Contains explicitly forbidden token '{forbidden}'",
                pattern_matched=forbidden,
                command_snippet=clean_cmd
            ))

    # Check regex threat signatures
    for regex, threat_lvl, desc, rule_id in DANGEROUS_PATTERNS:
        match = re.search(regex, clean_cmd, re.IGNORECASE)
        if match:
            violations.append(RuleViolation(
                rule_name=rule_id,
                threat_level=threat_lvl,
                description=desc,
                pattern_matched=match.group(0),
                command_snippet=clean_cmd
            ))

    # Network restrictions
    if not policy.allow_network:
        net_pattern = r"\b(curl|wget|nc|netcat|ssh|scp|ftp|rsync|telnet)\b"
        net_match = re.search(net_pattern, clean_cmd, re.IGNORECASE)
        if net_match and not any(v.rule_name == "data-exfiltration" for v in violations):
            violations.append(RuleViolation(
                rule_name="network-blocked",
                threat_level=ThreatLevel.WARNING,
                description="Network egress command detected while allow_network=False",
                pattern_matched=net_match.group(0),
                command_snippet=clean_cmd
            ))

    return violations
