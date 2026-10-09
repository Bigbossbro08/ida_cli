"""Phase 3 tests: full IDAPython exec namespace + script-file execution."""

import os
import tempfile
import unittest

from ida_cli import idapython


class TestIdaPythonExec(unittest.TestCase):
    def test_make_exec_globals_returns_ida_names(self):
        namespace = idapython.make_exec_globals()
        # Outside IDA the modules resolve to None, but the keys must exist.
        for name in ("idaapi", "idc", "ida_bytes", "ida_typeinf", "ida_hexrays"):
            self.assertIn(name, namespace)

    def test_single_expression(self):
        self.assertEqual(idapython.run_code("1 + 1")["result"], "2")

    def test_stdout_capture(self):
        res = idapython.run_code("print('hello')")
        self.assertIn("hello", res["stdout"])

    def test_trailing_expression_after_statements(self):
        res = idapython.run_code("a = 5\na * 3")
        self.assertEqual(res["result"], "15")

    def test_error_becomes_stderr_traceback(self):
        res = idapython.run_code("x = 1 / 0")
        self.assertIn("ZeroDivisionError", res["stderr"])

    def test_result_variable(self):
        res = idapython.run_code("result = 41 + 1")
        self.assertEqual(res["result"], "42")

    def test_run_file(self):
        fd, path = tempfile.mkstemp(suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write("import sys\nsys.stdout.write('from-file\\n')\nresult = 7\n")
            res = idapython.run_file(path)
            self.assertEqual(res["result"], "7")
            self.assertIn("from-file", res["stdout"])
        finally:
            os.unlink(path)

    def test_run_file_missing(self):
        res = idapython.run_file("Z:\\does\\not\\exist.py")
        self.assertIn("not found", res["stderr"].lower())


if __name__ == "__main__":
    unittest.main()
