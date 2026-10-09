"""Phase 5 tests: native read-command fallbacks degrade cleanly outside IDA.

Inside IDA these handlers back `decompile/disasm/xrefs/callees/lookup/bytes`
when ida-pro-mcp is absent; the tests here pin the output shapes and the
graceful-error contract (IDA modules unavailable).
"""

import unittest

from ida_cli import native


class TestNativeFallbackShapes(unittest.TestCase):
    def test_parse_address_int_passthrough(self):
        self.assertEqual(native.parse_address(0x1234), 0x1234)

    def test_decompile_error_shape(self):
        res = native.handle_decompile("0x401000", include_addresses=False)
        self.assertEqual(res["addr"], "0x401000")
        self.assertIn("code", res)
        self.assertIn("error", res)

    def test_disasm_error_shape(self):
        res = native.handle_disasm("0x401000", max_instructions=10, offset=0, include_total=True)
        self.assertEqual(res["addr"], "0x401000")
        self.assertIn("asm", res)
        self.assertIn("cursor", res)

    def test_xrefs_to_list_and_scalar(self):
        for arg in ("0x401000", ["0x401000", "0x402000"]):
            res = native.handle_xrefs_to(arg, limit=10)
            self.assertIsInstance(res, list)
            expected = 2 if isinstance(arg, list) else 1
            self.assertEqual(len(res), expected)
            for entry in res:
                self.assertIn("addr", entry)
                self.assertIn("xrefs", entry)

    def test_callees_shape(self):
        res = native.handle_callees(["0x401000"], limit=10)
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 1)
        self.assertIn("callees", res[0])

    def test_lookup_funcs_shape(self):
        res = native.handle_lookup_funcs(["main"])
        self.assertIsInstance(res, list)
        self.assertEqual(res[0]["query"], "main")
        self.assertIn("fn", res[0])

    def test_get_bytes_shape_single_and_list(self):
        single = native.handle_get_bytes({"addr": "0x401000", "size": 4})
        self.assertEqual(len(single), 1)
        self.assertIn("data", single[0])
        many = native.handle_get_bytes([{"addr": "0x401000", "size": 4}, {"addr": "0x402000", "size": 8}])
        self.assertEqual(len(many), 2)

    def test_disasm_chunks_shape(self):
        res = native.handle_disasm_chunks("0x401000")
        self.assertIn("chunks", res)
        self.assertIn("chunk_count", res)
        self.assertIsInstance(res["chunks"], list)

    def test_analyze_function_shape(self):
        res = native.handle_analyze_function("0x401000")
        self.assertIn("addr", res)
        self.assertIn("error", res)

    def test_insn_query_shape(self):
        res = native.handle_insn_query(["mov"])
        self.assertIsInstance(res, list)
        self.assertEqual(len(res), 1)
        self.assertIn("matches", res[0])

    def test_force_recompile_shape(self):
        res = native.handle_force_recompile(["0x401000"])
        self.assertIsInstance(res, list)
        self.assertIn("ok", res[0])

    def test_type_apply_batch_shape(self):
        res = native.handle_type_apply_batch([{"addr": "0x401000", "type": "int"}])
        self.assertIsInstance(res, list)
        self.assertIn("ok", res[0])


if __name__ == "__main__":
    unittest.main()
