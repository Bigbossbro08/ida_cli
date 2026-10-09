"""Phase 8 tests: doctor, mcp-config, and the foreign-CLI collision guard."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

from ida_cli import __version__, cli


REPO = Path(__file__).resolve().parents[1]


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "ida_cli.cli", *args],
        capture_output=True, text=True,
    )


class TestDoctor(unittest.TestCase):
    def test_doctor_runs_and_reports(self):
        res = _run("doctor")
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("ida-cli doctor", res.stdout)
        self.assertIn(__version__, res.stdout)
        self.assertIn("instances dir", res.stdout)
        self.assertIn("IDA_CLI_TOOL_TIMEOUT_SEC", res.stdout)


class TestMcpConfig(unittest.TestCase):
    def test_stdio_config(self):
        res = _run("mcp-config", "--json")
        self.assertEqual(res.returncode, 0, res.stderr)
        config = json.loads(res.stdout)
        self.assertEqual(config["mcpServers"]["ida-cli"]["command"], "ida-cli")
        self.assertEqual(config["mcpServers"]["ida-cli"]["args"], ["serve", "--stdio"])

    def test_proxy_mode_without_instance_fails(self):
        # No instances in a clean environment -> proxy mode errors out.
        res = _run("mcp-config", "--mode", "proxy", "--json", "-i", "does-not-exist")
        self.assertNotEqual(res.returncode, 0)


class TestCollisionGuard(unittest.TestCase):
    def test_foreign_flag_is_rejected(self):
        for flag in ("--path", "--compact", "--streamable-http"):
            res = _run(flag, "x")
            self.assertEqual(res.returncode, 2, f"{flag}: {res.stdout}")
            self.assertIn("different 'ida-cli' project", res.stderr)

    def test_our_own_help_still_works(self):
        res = _run("--help")
        self.assertEqual(res.returncode, 0)
        self.assertIn("doctor", res.stdout)
        self.assertIn("mcp-config", res.stdout)


if __name__ == "__main__":
    unittest.main()
