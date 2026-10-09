"""
IDA CLI Client
Handles HTTP REST communication with the IDA Pro connector server.
Uses standard library urllib for zero-dependency reliability.
"""

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional
from .discovery import IdaInstance


class IdaClientError(Exception):
    pass


# The server-side tool budget defaults to 60s (IDA_CLI_TOOL_TIMEOUT_SEC); the
# HTTP timeout must exceed it so a cancelled tool reports a clean error instead
# of the client hanging up first.
_DEFAULT_TIMEOUT_SEC = float(os.environ.get("IDA_CLI_HTTP_TIMEOUT_SEC", "120") or 120)


class IdaClient:
    def __init__(self, instance: IdaInstance, timeout: Optional[float] = None):
        self.instance = instance
        self.base_url = f"http://127.0.0.1:{instance.port}"
        self.timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT_SEC
        self.last_output_meta: Optional[Dict[str, Any]] = None

    def _request(self, path: str, method: str = "GET", data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Content-Type": "application/json",
            "Connection": "close",
        }
        payload = json.dumps(data).encode("utf-8") if data else None

        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
                return json.loads(body)
        except urllib.error.HTTPError as e:
            msg = f"HTTP {e.code}: {e.reason}"
            try:
                err_body = e.read().decode("utf-8")
                err_json = json.loads(err_body)
                tb = err_json.get("traceback")
                msg = err_json.get("error", msg)
                if tb:
                    msg = f"{msg}\n--- Server Traceback ---\n{tb}"
            except Exception:
                pass
            raise IdaClientError(msg)
        except urllib.error.URLError as e:
            raise IdaClientError(f"Could not connect to IDA at 127.0.0.1:{self.instance.port}: {e.reason}")
        except Exception as e:
            raise IdaClientError(f"Request failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        resp = self._request("/status", method="GET")
        if not resp.get("success"):
            raise IdaClientError(resp.get("error", "Failed to retrieve status"))
        return resp.get("data", {})

    def get_commands(self) -> Dict[str, Any]:
        resp = self._request("/commands", method="GET")
        if not resp.get("success"):
            raise IdaClientError(resp.get("error", "Failed to list commands"))
        return resp.get("commands", {})

    def exec_code(self, code: str) -> Dict[str, Any]:
        resp = self._request("/exec", method="POST", data={"code": code})
        if not resp.get("success"):
            raise IdaClientError(resp.get("error", "Execution failed"))
        return resp.get("data", {})

    def run_command(self, name: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        resp = self._request("/command", method="POST", data={"command": name, "params": params or {}})
        if not resp.get("success"):
            tb = resp.get("traceback")
            err = resp.get("error", f"Command '{name}' failed")
            if tb:
                raise IdaClientError(f"{err}\n--- IDA Server Traceback ---\n{tb.strip()}")
            raise IdaClientError(err)
        self.last_output_meta = resp.get("_output")
        if (
            isinstance(self.last_output_meta, dict)
            and self.last_output_meta.get("truncated")
            and not os.environ.get("IDA_CLI_QUIET")
        ):
            import sys
            print(
                f"[ida-cli] output truncated; full result: {self.last_output_meta.get('download_url')}",
                file=sys.stderr,
            )
        return resp.get("data", {})

    def describe_command(self, name: str) -> Optional[Dict[str, Any]]:
        """Get description and metadata for a named command from the server."""
        commands = self.get_commands()
        return commands.get(name)
