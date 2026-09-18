"""
Unit tests for ida-cli plugin system and dynamic target resolution.
"""

import shutil
import tempfile
import unittest
from pathlib import Path

from ida_cli.cli import resolve_target
from ida_cli.plugins import (
    get_plugin_search_paths,
    load_plugin_module,
    register_cli_plugins,
    register_server_plugins,
)


class TestPluginSystem(unittest.TestCase):
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.plugin_dir = self.temp_dir / ".ida-cli" / "plugins"
        self.plugin_dir.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_load_plugin_module(self):
        code = """
def register_cli(subparsers, common_parser):
    p = subparsers.add_parser("dummy-tool", parents=[common_parser])
    p.set_defaults(func=lambda args: "dummy")

def register_server(command_registry):
    command_registry["dummy_server"] = (lambda: "ok", "Dummy Server Command", True)
"""
        plugin_file = self.plugin_dir / "dummy_plugin.py"
        plugin_file.write_text(code, encoding="utf-8")

        mod = load_plugin_module(plugin_file)
        self.assertIsNotNone(mod)
        self.assertTrue(hasattr(mod, "register_cli"))
        self.assertTrue(hasattr(mod, "register_server"))

        # Test server registry hook
        registry = {}
        mod.register_server(registry)
        self.assertIn("dummy_server", registry)
        func, desc, sync_wrap = registry["dummy_server"]
        self.assertEqual(func(), "ok")
        self.assertEqual(desc, "Dummy Server Command")
        self.assertTrue(sync_wrap)

    def test_02_resolve_target_static(self):
        class DummyClient:
            pass

        client = DummyClient()
        # Non-cursor targets should pass through unmodified
        self.assertEqual(resolve_target(client, "0x401000"), "0x401000")
        self.assertEqual(resolve_target(client, "MyFunction"), "MyFunction")


if __name__ == "__main__":
    unittest.main()
