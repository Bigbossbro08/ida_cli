"""
IDA CLI Connector Server
Runs inside IDA Pro, starts an HTTP listener, manages instance discovery registration,
and dispatches incoming commands onto IDA's main thread via execute_sync.
"""

import hashlib
import io
import json
import os
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# IDA imports
try:
    import ida_auto
    import ida_ida
    import ida_idaapi
    import ida_kernwin
    import ida_loader
    import ida_nalt
    import idc
    import idautils
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


DEFAULT_PORT_RANGE = range(28100, 28150)
HEARTBEAT_INTERVAL_MS = 2000

_server = None
_server_thread = None
_heartbeat_timer = None
_instance_file_path = None
_command_registry = {}


def get_instances_dir() -> Path:
    instances_dir = Path.home() / ".ida-cli" / "instances"
    instances_dir.mkdir(parents=True, exist_ok=True)
    return instances_dir


def get_idb_path() -> str:
    if not IDA_AVAILABLE:
        return ""
    try:
        path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        return str(Path(path).resolve()) if path else ""
    except Exception:
        return ""


def get_input_file_path() -> str:
    if not IDA_AVAILABLE:
        return ""
    try:
        path = ida_nalt.get_input_file_path()
        return str(Path(path).resolve()) if path else ""
    except Exception:
        return ""


def get_instance_info(port: int, status: str = "ready") -> dict:
    idb_path = get_idb_path()
    input_file = get_input_file_path()
    root_dir = str(Path(idb_path).parent) if idb_path else (str(Path(input_file).parent) if input_file else "")

    current_ea = 0
    version = "unknown"
    if IDA_AVAILABLE:
        try:
            current_ea = ida_kernwin.get_screen_ea()
            version = ida_kernwin.get_kernel_version()
        except Exception:
            pass

    return {
        "pid": os.getpid(),
        "port": port,
        "idb_path": idb_path,
        "input_file": input_file,
        "root_dir": root_dir,
        "status": status,
        "ida_version": version,
        "current_ea": f"0x{current_ea:X}" if current_ea else "0x0",
        "started_at": int(time.time()),
        "last_heartbeat": int(time.time()),
    }


def register_instance_file(port: int) -> Path:
    global _instance_file_path
    instances_dir = get_instances_dir()
    idb = get_idb_path()
    slug = Path(idb).stem if idb else "nodb"
    file_name = f"ida_{os.getpid()}_{port}_{slug}.json"
    _instance_file_path = instances_dir / file_name

    data = get_instance_info(port, status="ready")
    _instance_file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return _instance_file_path


def update_instance_heartbeat(port: int) -> None:
    global _instance_file_path
    if not _instance_file_path:
        return
    try:
        if _instance_file_path.exists():
            data = json.loads(_instance_file_path.read_text(encoding="utf-8"))
            data["last_heartbeat"] = int(time.time())
            if IDA_AVAILABLE:
                ea = ida_kernwin.get_screen_ea()
                data["current_ea"] = f"0x{ea:X}"
                data["idb_path"] = get_idb_path()
                data["input_file"] = get_input_file_path()
                data["status"] = "busy" if ida_auto.auto_is_ok() is False else "ready"
            _instance_file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception as e:
        print(f"[IDA-CLI] Warning updating heartbeat: {e}")


def unregister_instance_file() -> None:
    global _instance_file_path
    if _instance_file_path and _instance_file_path.exists():
        try:
            _instance_file_path.unlink()
        except Exception as e:
            print(f"[IDA-CLI] Warning removing instance file: {e}")
    _instance_file_path = None


def execute_on_main_thread(func, *args, **kwargs):
    """Executes a callable on IDA's main UI thread safely using execute_sync."""
    if not IDA_AVAILABLE:
        return func(*args, **kwargs)

    result_box = [None, None]  # [value, exception]
    event = threading.Event()

    def sync_callable():
        try:
            result_box[0] = func(*args, **kwargs)
        except Exception as ex:
            result_box[1] = ex
        finally:
            event.set()
        return 1

    ida_kernwin.execute_sync(sync_callable, ida_kernwin.MFF_WRITE)
    event.wait(timeout=30.0)

    if result_box[1]:
        raise result_box[1]
    return result_box[0]


# Built-in command handlers
def handle_status():
    idb_path = get_idb_path()
    input_file = get_input_file_path()
    func_count = len(list(idautils.Functions())) if IDA_AVAILABLE else 0
    ea = ida_kernwin.get_screen_ea() if IDA_AVAILABLE else 0
    auto_done = ida_auto.auto_is_ok() if IDA_AVAILABLE else True

    return {
        "pid": os.getpid(),
        "idb_path": idb_path,
        "input_file": input_file,
        "ida_version": ida_kernwin.get_kernel_version() if IDA_AVAILABLE else "unknown",
        "current_ea": f"0x{ea:X}",
        "total_functions": func_count,
        "auto_analysis_complete": auto_done,
    }


def handle_exec(code: str):
    """Executes Python code inside IDA, capturing stdout."""
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    ret_val = None
    try:
        globals_dict = {
            "ida_auto": ida_auto,
            "ida_idaapi": ida_idaapi,
            "ida_kernwin": ida_kernwin,
            "ida_loader": ida_loader,
            "ida_nalt": ida_nalt,
            "idc": idc,
            "idautils": idautils,
        }
        # Try eval first for one-liners
        try:
            ret_val = eval(code, globals_dict)
        except SyntaxError:
            # Fall back to exec
            exec(code, globals_dict)
    finally:
        sys.stdout = old_stdout

    return {
        "output": buffer.getvalue(),
        "result": str(ret_val) if ret_val is not None else None,
    }


def handle_funcs_list(filter_str: str = "", limit: int = 50, offset: int = 0, compact: bool = True):
    """Returns functions with token-conscious pagination and filtering."""
    results = []
    total = 0

    filter_lower = filter_str.lower() if filter_str else ""
    for ea in idautils.Functions():
        name = idc.get_func_name(ea)
        if filter_lower and filter_lower not in name.lower() and filter_lower not in f"0x{ea:x}":
            continue
        total += 1
        if total <= offset:
            continue
        if len(results) < limit:
            func = ida_idaapi.get_func(ea)
            size = (func.end_ea - func.start_ea) if func else 0
            if compact:
                results.append({"ea": f"0x{ea:X}", "name": name, "size": size})
            else:
                proto = idc.get_type(ea) or ""
                results.append({
                    "ea": f"0x{ea:X}",
                    "name": name,
                    "size": size,
                    "flags": f"0x{func.flags:X}" if func else "0x0",
                    "prototype": proto,
                })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(results),
        "functions": results,
    }


def handle_func_inspect(target: str):
    """Compound super-command returning high-density function card in 1 call."""
    try:
        ea = int(target, 16) if target.startswith("0x") or target.startswith("0X") else int(target)
    except ValueError:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            raise ValueError(f"Function symbol '{target}' not found")

    func = ida_idaapi.get_func(ea)
    if not func:
        raise ValueError(f"No function defined at 0x{ea:X}")

    start_ea = func.start_ea
    name = idc.get_func_name(start_ea)
    size = func.end_ea - func.start_ea
    proto = idc.get_type(start_ea) or ""

    # Callers (XREFs to function start)
    callers = []
    for xref in idautils.CodeRefsTo(start_ea, 0):
        c_name = idc.get_func_name(xref) or f"0x{xref:X}"
        callers.append(f"0x{xref:X} ({c_name})")
        if len(callers) >= 10:
            break

    # Callees (Calls made from within function)
    callees = []
    seen_callees = set()
    for item_ea in idautils.FuncItems(start_ea):
        for xref in idautils.CodeRefsFrom(item_ea, 0):
            if xref not in seen_callees and xref != item_ea:
                seen_callees.add(xref)
                callee_func = ida_idaapi.get_func(xref)
                if callee_func:
                    callees.append(f"0x{xref:X} ({idc.get_func_name(xref)})")
            if len(callees) >= 15:
                break
        if len(callees) >= 15:
            break

    return {
        "ea": f"0x{start_ea:X}",
        "name": name,
        "size": size,
        "prototype": proto,
        "callers_count": len(list(idautils.CodeRefsTo(start_ea, 0))),
        "sample_callers": callers,
        "callees_count": len(seen_callees),
        "sample_callees": callees,
    }


# Register built-ins
_command_registry["status"] = (handle_status, "Get active database and IDA status")
_command_registry["exec"] = (handle_exec, "Execute arbitrary Python code inside IDA")
_command_registry["funcs_list"] = (handle_funcs_list, "List functions with filtering and pagination")
_command_registry["func_inspect"] = (handle_func_inspect, "Inspect a function (summary card with callers/callees)")


class IdaCliRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path in ("/status", "/health"):
            try:
                res = execute_on_main_thread(handle_status)
                self._send_json(200, {"success": True, "data": res})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e)})

        elif path == "/commands":
            cmd_list = {
                name: {"description": doc}
                for name, (_, doc) in _command_registry.items()
            }
            self._send_json(200, {"success": True, "commands": cmd_list})

        else:
            self._send_json(404, {"success": False, "error": f"Unknown endpoint {path}"})

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            self._send_json(400, {"success": False, "error": "Invalid JSON body"})
            return

        if path == "/exec":
            code = payload.get("code", "")
            try:
                res = execute_on_main_thread(handle_exec, code)
                self._send_json(200, {"success": True, "data": res})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e), "traceback": traceback.format_exc()})

        elif path == "/command":
            cmd_name = payload.get("command", "")
            params = payload.get("params", {})
            if cmd_name not in _command_registry:
                self._send_json(400, {"success": False, "error": f"Command '{cmd_name}' not registered"})
                return

            func, _ = _command_registry[cmd_name]
            try:
                res = execute_on_main_thread(func, **params)
                self._send_json(200, {"success": True, "command": cmd_name, "data": res})
            except Exception as e:
                self._send_json(500, {"success": False, "error": str(e), "traceback": traceback.format_exc()})
        else:
            self._send_json(404, {"success": False, "error": f"Unknown endpoint {path}"})

    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging to keep IDA console clean
        pass


def _heartbeat_callback():
    global _server
    if _server:
        update_instance_heartbeat(_server.server_port)
    return HEARTBEAT_INTERVAL_MS


def start_server() -> int:
    global _server, _server_thread, _heartbeat_timer

    if _server is not None:
        print(f"[IDA-CLI] Server already running on port {_server.server_port}")
        return _server.server_port

    selected_port = None
    for port in DEFAULT_PORT_RANGE:
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), IdaCliRequestHandler)
            selected_port = port
            _server = server
            break
        except OSError:
            continue

    if not _server:
        # Ephemeral port fallback
        _server = ThreadingHTTPServer(("127.0.0.1", 0), IdaCliRequestHandler)
        selected_port = _server.server_port

    # Register discovery file
    instance_path = register_instance_file(selected_port)
    print(f"[IDA-CLI] Server started on http://127.0.0.1:{selected_port}")
    print(f"[IDA-CLI] Registered instance descriptor at {instance_path}")

    _server_thread = threading.Thread(target=_server.serve_forever, daemon=True)
    _server_thread.start()

    # Schedule periodic heartbeat on IDA's main thread
    if IDA_AVAILABLE:
        _heartbeat_timer = ida_kernwin.register_timer(HEARTBEAT_INTERVAL_MS, _heartbeat_callback)

    return selected_port


def stop_server():
    global _server, _server_thread, _heartbeat_timer

    if _heartbeat_timer and IDA_AVAILABLE:
        ida_kernwin.unregister_timer(_heartbeat_timer)
        _heartbeat_timer = None

    unregister_instance_file()

    if _server:
        print("[IDA-CLI] Stopping server...")
        _server.shutdown()
        _server.server_close()
        _server = None
        _server_thread = None
        print("[IDA-CLI] Server stopped.")


if __name__ == "__main__":
    port = start_server()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_server()
