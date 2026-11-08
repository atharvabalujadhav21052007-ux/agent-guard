"""AgentGuard Command-Line Interface."""

import argparse
import json
import sys
from typing import List

from .audit import AuditLogger
from .demo import run_demo
from .rules import SecurityPolicy, ThreatLevel, analyze_command
from .runner import SandboxedRunner

CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"


def main(argv: List[str] = None):
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="Zero-dependency security firewall & execution sandbox for autonomous AI agents."
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Evaluate and safely execute a command")
    run_parser.add_argument("cmd", help="The command string to evaluate and execute")
    run_parser.add_argument("--timeout", type=float, default=10.0, help="Execution timeout in seconds")
    run_parser.add_argument("--allow-network", action="store_true", help="Permit network commands")
    run_parser.add_argument("--audit-log", default="agentguard-audit.jsonl", help="Path to audit trail log file")

    # Command: check
    check_parser = subparsers.add_parser("check", help="Statically inspect a command for violations without executing")
    check_parser.add_argument("cmd", help="The command string to evaluate")

    # Command: demo
    subparsers.add_parser("demo", help="Run interactive terminal defense demonstration")

    # Command: audit
    audit_parser = subparsers.add_parser("audit", help="Display summary from audit log")
    audit_parser.add_argument("--file", default="agentguard-audit.jsonl", help="Audit log file path")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "demo":
        run_demo()
        return

    if args.command == "check":
        violations = analyze_command(args.cmd)
        if not violations:
            print(f"{GREEN}{BOLD}✔ SAFE:{RESET} No security policy violations found.")
            sys.exit(0)
        else:
            print(f"{RED}{BOLD}✖ VIOLATIONS DETECTED:{RESET}")
            for v in violations:
                print(f"  • [{v.threat_level.value}] {v.rule_name}: {v.description} (Token: '{v.pattern_matched}')")
            sys.exit(1)

    if args.command == "run":
        policy = SecurityPolicy(allow_network=args.allow_network)
        runner = SandboxedRunner(policy=policy, timeout=args.timeout)
        logger = AuditLogger(log_path=args.audit_log)

        result = runner.run(args.cmd)
        logger.log_event(result)

        if not result.allowed:
            print(f"{RED}{BOLD}[AgentGuard BLOCKED]{RESET} Command prevented from execution:", file=sys.stderr)
            for v in result.violations:
                print(f"  ↳ [{v.threat_level.value}] {v.rule_name}: {v.description}", file=sys.stderr)
            sys.exit(2)

        if result.timed_out:
            print(f"{YELLOW}{BOLD}[AgentGuard TIMEOUT]{RESET} Process killed after {args.timeout}s limit.", file=sys.stderr)
            sys.exit(124)

        if result.stdout:
            sys.stdout.write(result.stdout)
        if result.stderr:
            sys.stderr.write(result.stderr)
        sys.exit(result.exit_code or 0)

    if args.command == "audit":
        try:
            with open(args.file, "r", encoding="utf-8") as f:
                lines = f.readlines()
            total = len(lines)
            blocked = sum(1 for line in lines if not json.loads(line).get("allowed", True))
            print(f"{BOLD}{CYAN}=== AgentGuard Audit Summary ({args.file}) ==={RESET}")
            print(f"Total Events Logged: {total}")
            print(f"Commands Blocked:    {blocked}")
            print(f"Commands Executed:   {total - blocked}")
        except FileNotFoundError:
            print(f"{YELLOW}No audit log found at {args.file}{RESET}")


if __name__ == "__main__":
    main()
