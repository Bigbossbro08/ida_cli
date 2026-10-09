"""Phase 10 tests: package public API and CLI help coverage."""

import subprocess
import sys
import unittest


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "ida_cli.cli", *args],
        capture_output=True, text=True,
    )


class TestPublicApi(unittest.TestCase):
    def test_lazy_exports(self):
        import ida_cli
        self.assertTrue(callable(ida_cli.install))
        self.assertTrue(callable(ida_cli.uninstall))
        self.assertTrue(callable(ida_cli.get_ida_user_plugins_dir))

    def test_version_is_string(self):
        import ida_cli
        self.assertIsInstance(ida_cli.__version__, str)

    def test_unknown_attribute_raises(self):
        import ida_cli
        with self.assertRaises(AttributeError):
            _ = ida_cli.does_not_exist


class TestHelpCoverage(unittest.TestCase):
    def test_every_phase_command_is_listed(self):
        res = _run("--help")
        self.assertEqual(res.returncode, 0, res.stderr)
        for name in ("doctor", "mcp-config", "install", "uninstall",
                     "install-paths", "exec-file", "serve", "analyze", "vtable"):
            self.assertIn(name, res.stdout, f"{name} missing from --help")


if __name__ == "__main__":
    unittest.main()
