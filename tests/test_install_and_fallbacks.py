"""Phase 9 tests: installer and extra native fallbacks."""

import os
import tempfile
import unittest
from pathlib import Path

from ida_cli import installer, native


class TestInstaller(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="idacli_install_"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_install_copies_plugin_files(self):
        report = installer.install(self.tmp)
        self.assertTrue((self.tmp / "ida_cli_plugin.py").is_file())
        self.assertTrue((self.tmp / "ida_cli_server.py").is_file())
        self.assertEqual(len(report["copied"]), 2)
        # .pth should reference the repo root that contains the ida_cli package.
        pth = self.tmp / "ida_cli_path.pth"
        self.assertTrue(pth.is_file())
        root = Path(pth.read_text(encoding="utf-8").strip().splitlines()[-1])
        self.assertTrue((root / "ida_cli" / "__init__.py").is_file())

    def test_uninstall_removes(self):
        installer.install(self.tmp)
        report = installer.uninstall(self.tmp)
        self.assertEqual(len(report["removed"]), 3)
        self.assertFalse((self.tmp / "ida_cli_plugin.py").exists())
        self.assertFalse((self.tmp / "ida_cli_path.pth").exists())

    def test_get_ida_user_plugins_dir_override(self):
        with unittest.mock.patch.dict(os.environ, {"IDA_CLI_IDA_PLUGINS_DIR": str(self.tmp / "p")}):
            self.assertEqual(installer.get_ida_user_plugins_dir(), self.tmp / "p")


class TestExtraFallbacks(unittest.TestCase):
    def test_survey_binary_shape(self):
        res = native.handle_survey_binary("summary")
        self.assertIn("error", res)  # outside IDA -> graceful

    def test_search_text_shape(self):
        res = native.handle_search_text("mov")
        self.assertIn("hits", res)
        self.assertIn("n", res)

    def test_struct_inspect_shape(self):
        res = native.handle_struct_inspect("Nope")
        self.assertIn("error", res)

    def test_struct_search_shape(self):
        self.assertIsInstance(native.handle_struct_search(""), list)


if __name__ == "__main__":
    unittest.main()
