"""Phase 2 tests: output limiter + MCP / output HTTP endpoints."""

import json
import unittest
import urllib.error
import urllib.request
from unittest import mock

from ida_cli import server
from ida_cli.output import OUTPUT_STORE, OutputStore, truncate_value


class TestOutputLimiter(unittest.TestCase):
    def test_truncate_long_string(self):
        out = truncate_value("a" * 5000)
        self.assertIn("chars total", out)
        self.assertLess(len(out), 5000)

    def test_truncate_long_list(self):
        out = truncate_value(list(range(100)))
        self.assertEqual(len(out), 10)

    def test_truncate_preserves_shape(self):
        value = {"code": "z" * 4000, "nested": {"items": list(range(50))}}
        out = truncate_value(value)
        self.assertIn("code", out)
        self.assertIn("nested", out)
        self.assertEqual(len(out["nested"]["items"]), 10)

    def test_limit_below_threshold_returns_no_meta(self):
        store = OutputStore(max_size=5)
        with mock.patch.dict("os.environ", {"IDA_CLI_OUTPUT_LIMIT_CHARS": "100000"}):
            data, meta = store.limit({"small": "ok"})
        self.assertIsNone(meta)
        self.assertEqual(data, {"small": "ok"})

    def test_limit_above_threshold_stores_and_returns_meta(self):
        store = OutputStore(max_size=5)
        big = {"blob": "x" * 5000}
        with mock.patch.dict("os.environ", {"IDA_CLI_OUTPUT_LIMIT_CHARS": "100"}):
            data, meta = store.limit(big, download_base_url="http://127.0.0.1:28100")
        self.assertIsNotNone(meta)
        self.assertTrue(meta["truncated"])
        self.assertIn("/output/", meta["download_url"])
        self.assertIn("chars total", data["blob"])
        # Full payload is retrievable.
        self.assertEqual(store.get(meta["output_id"]), big)

    def test_store_lru_eviction(self):
        store = OutputStore(max_size=2)
        a = store.put("A")
        b = store.put("B")
        store.put("C")
        self.assertIsNone(store.get(a))
        self.assertEqual(store.get(b), "B")


class TestHttpEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = server.start_server()
        cls.base = f"http://127.0.0.1:{cls.port}"
        cls._old_limit = None

    @classmethod
    def tearDownClass(cls):
        server.stop_server()

    def _post_mcp(self, body):
        req = urllib.request.Request(
            self.base + "/mcp", data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"}, method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_mcp_unavailable_returns_jsonrpc_error(self):
        # Outside IDA the ida_mcp package is not importable; /mcp must degrade cleanly.
        status, body = self._post_mcp({"jsonrpc": "2.0", "method": "initialize",
                                       "params": {}, "id": 1})
        self.assertEqual(status, 503)
        self.assertEqual(body["error"]["code"], -32601)
        self.assertEqual(body["id"], 1)

    def test_output_download_roundtrip(self):
        full = {"blob": "y" * 4096, "n": 7}
        oid = server.OUTPUT_STORE.put(full)
        with urllib.request.urlopen(f"{self.base}/output/{oid}.json", timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertEqual(json.loads(resp.read().decode("utf-8")), full)

    def test_output_download_unknown_is_404(self):
        try:
            urllib.request.urlopen(f"{self.base}/output/does-not-exist.json", timeout=10)
            self.fail("expected 404")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)

    def test_command_response_is_limited_and_downloadable(self):
        big = {"blob": "q" * 5000}

        def _big_handler():
            return big

        server._command_registry["_test_big"] = (_big_handler, "test", False)
        try:
            with mock.patch.dict("os.environ", {"IDA_CLI_OUTPUT_LIMIT_CHARS": "500"}):
                req = urllib.request.Request(
                    self.base + "/command",
                    data=json.dumps({"command": "_test_big", "params": {}}).encode("utf-8"),
                    headers={"Content-Type": "application/json"}, method="POST",
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
            self.assertTrue(body["success"])
            self.assertIn("_output", body)
            self.assertTrue(body["_output"]["truncated"])
            self.assertIn("chars total", body["data"]["blob"])
            url = body["_output"]["download_url"]
            self.assertTrue(url.startswith(f"http://127.0.0.1:{self.port}/output/"))
            with urllib.request.urlopen(url, timeout=10) as resp:
                self.assertEqual(json.loads(resp.read().decode("utf-8")), big)
        finally:
            server._command_registry.pop("_test_big", None)


if __name__ == "__main__":
    unittest.main()
