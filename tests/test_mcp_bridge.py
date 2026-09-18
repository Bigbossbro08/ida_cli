"""
Unit tests for ida-cli bridge and MCP tool integration.
"""

import unittest
from ida_cli.bridge import load_mcp_commands
from ida_cli.cli import parse_param_value, parse_key_value_params
from ida_cli import server


class TestMcpBridge(unittest.TestCase):
    def test_01_parse_param_helpers(self):
        self.assertEqual(parse_param_value("true"), True)
        self.assertEqual(parse_param_value("FALSE"), False)
        self.assertEqual(parse_param_value("null"), None)
        self.assertEqual(parse_param_value("123"), 123)
        self.assertEqual(parse_param_value("0x401000"), "0x401000")
        self.assertEqual(parse_param_value("hello"), "hello")

        parsed = parse_key_value_params(["addr=0x401000", "limit=10", "verbose=true", "dry_run"])
        self.assertEqual(parsed["addr"], "0x401000")
        self.assertEqual(parsed["limit"], 10)
        self.assertEqual(parsed["verbose"], True)
        self.assertEqual(parsed["dry_run"], True)

    def test_02_load_mcp_commands_structure(self):
        cmds = load_mcp_commands()
        # If ida-pro-mcp is installed in the python environment, cmds will be non-empty
        if cmds:
            self.assertIn("decompile", cmds)
            self.assertIn("disasm", cmds)
            self.assertIn("xrefs_to", cmds)
            self.assertIn("lookup_funcs", cmds)
            self.assertIn("search_text", cmds)

            # Check 3-tuple structure: (func, doc, needs_sync_wrap)
            func, doc, needs_sync = cmds["decompile"]
            self.assertTrue(callable(func))
            self.assertIsInstance(doc, str)
            self.assertFalse(needs_sync)

    def test_03_server_registry_contains_mcp(self):
        server.register_mcp_tools()
        # Built-ins must be present
        self.assertIn("status", server._command_registry)
        self.assertIn("exec", server._command_registry)
        self.assertIn("funcs_list", server._command_registry)
        self.assertIn("func_inspect", server._command_registry)


if __name__ == "__main__":
    unittest.main()
