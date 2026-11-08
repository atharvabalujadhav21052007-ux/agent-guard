"""Unit tests for sandboxed command execution and timeout handling."""

import os
import sys
import unittest
from agentguard.runner import SandboxedRunner


class TestRunner(unittest.TestCase):
    def setUp(self):
        self.runner = SandboxedRunner(timeout=2.0)

    def test_benign_execution(self):
        cmd = f'"{sys.executable}" -c "print(\'AgentGuard OK\')"'
        result = self.runner.run(cmd)
        self.assertTrue(result.allowed)
        self.assertEqual(result.exit_code, 0)
        self.assertIn("AgentGuard OK", result.stdout)
        self.assertFalse(result.timed_out)

    def test_critical_command_intercepted(self):
        cmd = "rm -rf /"
        result = self.runner.run(cmd)
        self.assertFalse(result.allowed)
        self.assertEqual(result.exit_code, -1)
        self.assertIn("blocked", result.stderr.lower())

    def test_timeout_enforced(self):
        cmd = f'"{sys.executable}" -c "import time; time.sleep(5)"'
        runner = SandboxedRunner(timeout=1.0)
        result = runner.run(cmd)
        self.assertTrue(result.timed_out)
        self.assertIn("timed out", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
