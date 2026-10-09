"""Phase 7 tests: matcher-compatible HTTP routes on the ida-cli connector."""

import json
import unittest
import urllib.error
import urllib.request

from ida_cli import server


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            ctype = resp.headers.get("Content-Type", "")
            raw = resp.read()
            return resp.status, ctype, raw
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type", ""), e.read()


class TestMatcherRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = server.start_server()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        server.stop_server()

    def tearDown(self):
        for name in ("match_get_func", "match_get_funcs", "match_all_names", "match_get_baseline"):
            server._command_registry.pop(name, None)

    def test_func_route_delegates_to_command(self):
        server._command_registry["match_get_func"] = (
            lambda name: {"name": name, "bytes": "c3", "size": 1}, "test", True,
        )
        status, _, raw = _get(f"{self.base}/func?name=foo")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["bytes"], "c3")

    def test_func_route_missing_is_404(self):
        status, _, _ = _get(f"{self.base}/func?name=missing")
        self.assertEqual(status, 404)

    def test_funcs_route_wraps_results(self):
        server._command_registry["match_get_funcs"] = (
            lambda names: {"results": {n: {"bytes": "90"} for n in names}}, "test", True,
        )
        status, _, raw = _get(f"{self.base}/funcs?names=a,b")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertEqual(set(body["results"].keys()), {"a", "b"})

    def test_all_names_route(self):
        server._command_registry["match_all_names"] = (
            lambda: {"names": ["alpha", "beta"]}, "test", True,
        )
        status, _, raw = _get(f"{self.base}/all_names")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["names"], ["alpha", "beta"])

    def test_baseline_route(self):
        server._command_registry["match_get_baseline"] = (
            lambda: {"functions": {"f": {"bytes": "cc"}}}, "test", True,
        )
        status, _, raw = _get(f"{self.base}/baseline")
        self.assertEqual(status, 200)
        self.assertIn("functions", json.loads(raw))

    def test_health_ok(self):
        status, _, _ = _get(f"{self.base}/health")
        self.assertEqual(status, 200)

    def test_synthetic_obj_missing_is_404(self):
        status, _, _ = _get(f"{self.base}/synthetic_obj?name=x")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
