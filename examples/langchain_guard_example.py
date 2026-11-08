"""Example: Guarding LangChain / Custom Agent Tool Execution with AgentGuard."""

from agentguard import SandboxedRunner, SecurityPolicy

# Define our secure policy
policy = SecurityPolicy(
    allow_network=False,
    max_command_length=2048
)
guard = SandboxedRunner(policy=policy, timeout=5.0)

def agent_shell_tool(command: str) -> str:
    """Simulated Agent Tool that executes shell commands securely through AgentGuard."""
    print(f"\n[Agent Tool Call Received]: {command}")
    
    # Intercept command before execution
    result = guard.run(command)
    
    if not result.allowed:
        violations_summary = ", ".join(f"{v.rule_name} ({v.description})" for v in result.violations)
        return f"ERROR: Execution blocked by AgentGuard security firewall. Reason: {violations_summary}"
    
    if result.timed_out:
        return f"ERROR: Command timed out after {guard.timeout} seconds."
    
    return result.stdout or "Command completed with no output."


if __name__ == "__main__":
    # Test 1: Benign developer command
    print(agent_shell_tool("python -c \"print('Calculated result: 42')\""))

    # Test 2: Injected prompt attacking system
    print(agent_shell_tool("cat ~/.ssh/id_rsa"))
