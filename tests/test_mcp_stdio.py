"""Phase 3 tests: stdio MCP proxy (<-> ida-cli /mcp)."""

import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ida_cli.mcp_stdio import run_stdio_proxy


class _FakeMcpHandler(BaseHTTPRequestHandler):
    received = []

    def log_message(self, *args):
        pass

    def _header(self, name):
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None

    def do_POST(self):
        length = int(self.headers.get("content-length", 0))
        body = self.rfile.read(length).decode("utf-8")
        _FakeMcpHandler.received.append((self._header("Mcp-Session-Id"), body))
        message = json.loads(body)
        method = message.get("method")

        if method == "initialize":
            payload = json.dumps({
                "jsonrpc": "2.0",
                "result": {"protocolVersion": "2024-11-05", "serverInfo": {"name": "fake"}},
                "id": message.get("id"),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Mcp-Session-Id", "sess-123")
        elif method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif method == "tools/call":
            payload = json.dumps({
                "jsonrpc": "2.0",
                "result": {"content": [{"type": "text", "text": "ok"}]},
                "id": message.get("id"),
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif method == "sse/echo":
            payload = b"event: message\ndata: " + json.dumps({
                "jsonrpc": "2.0", "result": {"sse": True}, "id": message.get("id"),
            }).encode("utf-8") + b"\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class TestMcpStdio(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _FakeMcpHandler.received = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeMcpHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _run(self, lines):
        instream = io.BytesIO("".join(line + "\n" for line in lines).encode("utf-8"))
        outstream = io.BytesIO()
        rc = run_stdio_proxy(port=self.port, instream=instream, outstream=outstream)
        self.assertEqual(rc, 0)
        return [json.loads(l) for l in outstream.getvalue().decode("utf-8").splitlines() if l]

    def test_initialize_and_session_reuse(self):
        _FakeMcpHandler.received = []
        out = self._run([
            json.dumps({"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}),
            json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                        "params": {"name": "decompile", "arguments": {}}, "id": 2}),
        ])
        self.assertEqual(len(out), 2)
        self.assertEqual(out[0]["result"]["serverInfo"]["name"], "fake")
        self.assertEqual(out[1]["result"]["content"][0]["text"], "ok")
        # Second request must carry the session id returned by initialize.
        self.assertEqual(_FakeMcpHandler.received[1][0], "sess-123")

    def test_notification_produces_no_output(self):
        out = self._run([
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        ])
        self.assertEqual(out, [])

    def test_parse_error_line(self):
        out = self._run(["this is not json"])
        self.assertEqual(out[0]["error"]["code"], -32700)

    def test_sse_response_is_unwrapped(self):
        out = self._run([
            json.dumps({"jsonrpc": "2.0", "method": "sse/echo", "params": {}, "id": 9}),
        ])
        self.assertEqual(out[0]["result"]["sse"], True)


if __name__ == "__main__":
    unittest.main()
