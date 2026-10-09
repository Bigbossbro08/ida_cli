"""stdio MCP transport for ida-cli.

Lets MCP clients that speak stdio (Claude Desktop, Cursor, ...) drive ida-cli:
each newline-delimited JSON-RPC message on stdin is forwarded to the ida-cli
connector's ``POST /mcp`` endpoint, and the response is written back to stdout.

stdout carries protocol data only; diagnostics go to stderr.
"""

import http.client
import json
import sys
from typing import Optional

from .discovery import resolve_instance


def _emit(outstream, message: dict) -> None:
    outstream.write(json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n")
    outstream.flush()


def _forward_response(outstream, body: bytes, content_type: str) -> None:
    """Write a JSON or SSE-delimited response to stdout as single-line JSON."""
    if "text/event-stream" in (content_type or "").lower():
        for block in body.decode("utf-8", errors="replace").split("\n\n"):
            data = "\n".join(
                line[5:].strip() for line in block.splitlines() if line.startswith("data:")
            )
            if data:
                outstream.write(data.encode("utf-8") + b"\n")
        outstream.flush()
        return

    text = body.decode("utf-8", errors="replace").strip()
    if text:
        try:
            outstream.write(json.dumps(json.loads(text), separators=(",", ":")).encode("utf-8") + b"\n")
        except Exception:
            outstream.write(text.encode("utf-8") + b"\n")
        outstream.flush()


def run_stdio_proxy(
    instance_target: Optional[str] = None,
    port: Optional[int] = None,
    instream=None,
    outstream=None,
    timeout: float = 120.0,
) -> int:
    """Run the stdio<->HTTP MCP bridge until stdin closes. Returns an exit code."""
    instream = instream if instream is not None else sys.stdin.buffer
    outstream = outstream if outstream is not None else sys.stdout.buffer

    if port is None:
        instance = resolve_instance(target=instance_target)
        if not instance:
            sys.stderr.write("ida-cli: no active IDA instance found for MCP stdio bridge.\n")
            return 1
        port = instance.port

    session_id: Optional[str] = None

    for raw in instream:
        line = raw.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except Exception:
            _emit(outstream, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})
            continue

        is_notification = isinstance(message, dict) and "id" not in message
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Connection": "close",
        }
        if session_id:
            headers["Mcp-Session-Id"] = session_id

        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        try:
            conn.request("POST", "/mcp", body=line, headers=headers)
            response = conn.getresponse()
            content_type = response.getheader("Content-Type", "")
            new_session = response.getheader("Mcp-Session-Id")
            if new_session:
                session_id = new_session
            body = response.read()
            status = response.status
        except Exception as exc:
            if not is_notification:
                _emit(outstream, {
                    "jsonrpc": "2.0",
                    "error": {"code": -32000, "message": f"ida-cli server unreachable on port {port}: {exc}"},
                    "id": message.get("id") if isinstance(message, dict) else None,
                })
            else:
                sys.stderr.write(f"[ida-cli serve] forward failed: {exc}\n")
            continue
        finally:
            try:
                conn.close()
            except Exception:
                pass

        if status == 202 or not body:
            continue
        _forward_response(outstream, body, content_type)

    return 0
