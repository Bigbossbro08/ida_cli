"""
IDA CLI Connector Server
Runs inside IDA Pro, starts a lightweight socket HTTP server,
manages instance discovery registration, and dispatches incoming
commands onto IDA's main thread via execute_sync safely.
"""

import io
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
import traceback
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import deadline as deadline_guard
from . import discovery
from . import idapython
from . import native
from .cache import TTLCache
from .output import OUTPUT_STORE

# Full-scan inventory results (functions/names/strings/classes), reused across
# requests for a short TTL and invalidated by mutating commands.
_INVENTORY_CACHE = TTLCache()

# IDA imports
try:
    import ida_auto
    import ida_bytes
    import ida_funcs
    import ida_ida
    import ida_idaapi
    import ida_kernwin
    import ida_loader
    import ida_nalt
    import ida_segment
    import idc
    import idautils
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


DEFAULT_PORT_RANGE = range(28100, 28150)
HEARTBEAT_INTERVAL_MS = 2000

if "SERVER_SOCKET" not in globals():
    SERVER_SOCKET = None
if "_server_thread" not in globals():
    _server_thread = None
if "_server_port" not in globals():
    _server_port = None
if "_heartbeat_timer" not in globals():
    _heartbeat_timer = None
if "_instance_file_path" not in globals():
    _instance_file_path = None
if "_command_registry" not in globals():
    _command_registry = {}


def get_instances_dir() -> Path:
    # Single source of truth (honours IDA_CLI_INSTANCES_DIR).
    return discovery.get_instances_dir()


def _atomic_write_json(path: Path, data: dict) -> None:
    """Write JSON atomically: temp file in the same directory + os.replace.

    Prevents the zero-filled / truncated descriptors that a non-atomic
    write_text() can leave behind if IDA is killed mid-write.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


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
            ea = ida_kernwin.get_screen_ea()
            if ea not in (0, ida_idaapi.BADADDR):
                current_ea = ea
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
    input_file = get_input_file_path()
    slug = Path(idb).stem if idb else (Path(input_file).stem if input_file else "nodb")
    file_name = f"ida_{os.getpid()}_{port}_{slug}.json"
    _instance_file_path = instances_dir / file_name

    data = get_instance_info(port, status="ready")
    _atomic_write_json(_instance_file_path, data)
    return _instance_file_path


def _instance_info_is_meaningful(info: dict) -> bool:
    """True once the IDB/input path is known (i.e. IDA finished loading)."""
    if not info:
        return False
    return bool(info.get("idb_path") or info.get("input_file"))


def _collect_instance_fields() -> dict:
    """Gather IDB/input/status fields. Must be called on IDA's main thread."""
    fields = {
        "idb_path": get_idb_path(),
        "input_file": get_input_file_path(),
    }
    if IDA_AVAILABLE:
        try:
            ea = ida_kernwin.get_screen_ea()
            fields["current_ea"] = f"0x{ea:X}" if ea not in (0, ida_idaapi.BADADDR) else "0x0"
        except Exception:
            pass
        try:
            fields["status"] = "busy" if (hasattr(ida_auto, "auto_is_ok") and not ida_auto.auto_is_ok()) else "ready"
        except Exception:
            pass
    return fields


def refresh_instance_info() -> None:
    """Refresh the descriptor's IDB/input paths and status.

    Called from IDB hooks (``savebase``) and from the headless refresh thread.
    IDA's path APIs must run on the main thread, so when called from a non-IDB
    thread we marshal through ``execute_on_main_thread``.
    """
    global _instance_file_path
    if not _instance_file_path or not _instance_file_path.exists():
        return
    try:
        fields = execute_on_main_thread(_collect_instance_fields)
    except Exception:
        # Fallback (e.g. IDA not fully initialized yet): try inline.
        try:
            fields = _collect_instance_fields()
        except Exception:
            return
    if not fields:
        return
    try:
        data = json.loads(_instance_file_path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
        data.update(fields)
        _atomic_write_json(_instance_file_path, data)
    except Exception as e:
        print(f"[IDA-CLI] Warning refreshing instance info: {e}")


def update_instance_heartbeat(port: int) -> None:
    global _instance_file_path
    if not _instance_file_path:
        return
    try:
        data = None
        if _instance_file_path.exists():
            try:
                data = json.loads(_instance_file_path.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    data = None
            except Exception:
                data = None

        if data is None:
            # Descriptor missing or corrupt (e.g. truncated by a crash):
            # rebuild it so discovery can find this instance again.
            register_instance_file(port)
            return

        data["last_heartbeat"] = int(time.time())
        if IDA_AVAILABLE:
            data["idb_path"] = get_idb_path()
            data["input_file"] = get_input_file_path()
            try:
                ea = ida_kernwin.get_screen_ea()
                # Headless idat reports BADADDR; store 0x0 rather than 0xFFFF...
                data["current_ea"] = f"0x{ea:X}" if ea not in (0, ida_idaapi.BADADDR) else "0x0"
            except Exception:
                pass
            data["status"] = "busy" if (hasattr(ida_auto, "auto_is_ok") and not ida_auto.auto_is_ok()) else "ready"
        _atomic_write_json(_instance_file_path, data)
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


class IdaSyncTimeoutError(Exception):
    """Raised when an IDA main-thread operation exceeds its time budget."""


_TOOL_TIMEOUT_ENV = "IDA_CLI_TOOL_TIMEOUT_SEC"
_DEFAULT_TOOL_TIMEOUT_SEC = 60.0


def get_tool_timeout_seconds() -> float:
    raw = os.environ.get(_TOOL_TIMEOUT_ENV, "").strip()
    if not raw:
        return _DEFAULT_TOOL_TIMEOUT_SEC
    try:
        value = float(raw)
        return value if value > 0 else _DEFAULT_TOOL_TIMEOUT_SEC
    except ValueError:
        return _DEFAULT_TOOL_TIMEOUT_SEC


def execute_on_main_thread(func, *args, _write: bool = False, **kwargs):
    """Execute a callable on IDA's main thread with a timeout and cancellation.

    Uses ``ida_kernwin.execute_sync`` to marshal onto the UI thread. A watchdog
    timer calls ``ida_kernwin.set_cancelled()`` at the deadline; IDA SDK calls
    that poll for cancellation (decompiler, auto-analysis, searches, string
    building) bail out, freeing the main thread. We never invoke IDA's API from
    the request thread -- a timed-out call raises IdaSyncTimeoutError instead.
    """
    if not IDA_AVAILABLE:
        return func(*args, **kwargs)

    timeout = get_tool_timeout_seconds()
    deadline = (time.monotonic() + timeout) if timeout > 0 else None
    result_box = [None, None]
    event = threading.Event()
    cancel_fired = [None]

    def sync_callable():
        try:
            result_box[0] = deadline_guard.run_with_deadline(
                lambda: func(*args, **kwargs),
                deadline,
                cancel_fired_at=cancel_fired,
            )
        except deadline_guard.DeadlineExceeded as ex:
            result_box[1] = IdaSyncTimeoutError(str(ex))
        except Exception as ex:
            result_box[1] = ex
        finally:
            event.set()
        return 1

    def _fire_cancel():
        cancel_fired[0] = time.monotonic()
        try:
            ida_kernwin.set_cancelled()
        except Exception:
            pass

    flag = getattr(ida_kernwin, "MFF_WRITE", 0x2) if _write else (getattr(ida_kernwin, "MFF_FAST", 0x4) | getattr(ida_kernwin, "MFF_READ", 0x1))

    watchdog = None
    if timeout > 0:
        watchdog = threading.Timer(timeout, _fire_cancel)
        watchdog.daemon = True
        watchdog.start()

    try:
        ida_kernwin.execute_sync(sync_callable, flag)
    finally:
        if watchdog is not None:
            watchdog.cancel()
        # Sticky flag: always clear so the next tool starts clean.
        try:
            ida_kernwin.clr_cancelled()
        except Exception:
            pass

    if not event.wait(timeout=5.0):
        raise IdaSyncTimeoutError(
            f"Tool did not run on the IDA main thread within {timeout:.0f}s. "
            "IDA may be blocked by a modal dialog; retry or raise "
            f"{_TOOL_TIMEOUT_ENV}."
        )

    if cancel_fired[0] is not None:
        raise IdaSyncTimeoutError(
            f"Tool exceeded the {timeout:.0f}s budget and was cancelled. "
            f"Increase {_TOOL_TIMEOUT_ENV} for long operations."
        )

    if result_box[1]:
        raise result_box[1]
    return result_box[0]



# Built-in command handlers
def handle_status():
    idb_path = get_idb_path()
    input_file = get_input_file_path()
    func_count = 0
    if IDA_AVAILABLE:
        if hasattr(ida_funcs, "get_func_qty"):
            func_count = ida_funcs.get_func_qty()
        elif hasattr(idc, "get_func_qty"):
            func_count = idc.get_func_qty()
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
    """Execute Python in a full IDAPython context; capture stdout/stderr/result."""
    res = idapython.run_code(code)
    return {
        "output": res["stdout"],
        "stderr": res["stderr"],
        "result": res["result"] or None,
    }


def handle_exec_file(path: str):
    """Execute a Python script file in a full IDAPython context."""
    res = idapython.run_file(path)
    return {
        "output": res["stdout"],
        "stderr": res["stderr"],
        "result": res["result"] or None,
    }


def _scan_functions():
    """Full, unfiltered function inventory (cached)."""
    if not IDA_AVAILABLE:
        return []
    records = []
    for ea in idautils.Functions():
        func = ida_funcs.get_func(ea)
        records.append({
            "ea_int": ea,
            "ea": f"0x{ea:X}",
            "name": idc.get_func_name(ea),
            "size": (func.end_ea - func.start_ea) if func else 0,
            "flags": f"0x{func.flags:X}" if func else "0x0",
        })
    return records


def handle_funcs_list(filter_str: str = "", limit: int = 50, offset: int = 0, compact: bool = True):
    """Returns functions with token-conscious pagination and filtering."""
    records = _INVENTORY_CACHE.get_or_set("functions", _scan_functions)

    filter_lower = filter_str.lower() if filter_str else ""
    matched = []
    for rec in records:
        if filter_lower and filter_lower not in rec["name"].lower() and filter_lower not in f"0x{rec['ea_int']:x}":
            continue
        matched.append(rec)

    page = matched[offset:offset + limit]
    results = []
    for rec in page:
        if compact:
            results.append({"ea": rec["ea"], "name": rec["name"], "size": rec["size"]})
        else:
            results.append({
                "ea": rec["ea"],
                "name": rec["name"],
                "size": rec["size"],
                "flags": rec["flags"],
                "prototype": (idc.get_type(rec["ea_int"]) or ""),
            })

    return {
        "total": len(matched),
        "offset": offset,
        "limit": limit,
        "count": len(results),
        "functions": results,
    }


def handle_func_inspect(target: str, chunks: bool = False):
    """Compound super-command returning high-density function card in 1 call.

    With ``chunks=True``, also reports the function's chunk ranges (e.g. distant
    ``.text$x`` EH funclets) instead of only the main body's span.
    """
    try:
        ea = int(target, 16) if target.startswith("0x") or target.startswith("0X") else int(target)
    except ValueError:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            raise ValueError(f"Function symbol '{target}' not found")

    func = ida_funcs.get_func(ea)
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
                callee_func = ida_funcs.get_func(xref)
                if callee_func:
                    callees.append(f"0x{xref:X} ({idc.get_func_name(xref)})")
            if len(callees) >= 15:
                break
        if len(callees) >= 15:
            break

    result = {
        "ea": f"0x{start_ea:X}",
        "name": name,
        "size": size,
        "prototype": proto,
        "callers_count": len(list(idautils.CodeRefsTo(start_ea, 0))),
        "sample_callers": callers,
        "callees_count": len(seen_callees),
        "sample_callees": callees,
    }

    if chunks:
        chunk_list = []
        try:
            ranges = list(idautils.Chunks(start_ea))
        except Exception:
            ranges = [(start_ea, func.end_ea)]
        for index, (chunk_start, chunk_end) in enumerate(ranges):
            chunk_list.append({
                "index": index,
                "start_ea": f"0x{chunk_start:X}",
                "end_ea": f"0x{chunk_end:X}",
                "size": chunk_end - chunk_start,
                "kind": "main" if index == 0 else "tail",
            })
        result["chunk_count"] = len(chunk_list)
        result["chunks"] = chunk_list

    return result



def handle_cursor_info():
    """Returns the current GUI cursor address, active function, and disassembly line."""
    if not IDA_AVAILABLE:
        return {"ea": "0x0", "func_ea": None, "func_name": None, "disasm": ""}

    ea = ida_kernwin.get_screen_ea()
    func = ida_funcs.get_func(ea)
    func_ea = f"0x{func.start_ea:X}" if func else None
    func_name = idc.get_func_name(func.start_ea) if func else None
    disasm = idc.generate_disasm_line(ea, 0) or ""
    if hasattr(idc, "tag_remove"):
        disasm = idc.tag_remove(disasm)

    return {
        "ea": f"0x{ea:X}",
        "func_ea": func_ea,
        "func_name": func_name,
        "disasm": disasm.strip(),
    }


def handle_segments_list():
    """Lists all memory segments, boundaries, and permissions."""
    if not IDA_AVAILABLE:
        return []

    results = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea) if hasattr(ida_segment, "getseg") else None
        if not seg:
            continue
        name = idc.get_segm_name(seg_ea) or "<unnamed>"
        size = seg.end_ea - seg.start_ea
        perm = ""
        p = seg.perm
        if p & getattr(ida_segment, "SEGPERM_READ", 4):
            perm += "r"
        if p & getattr(ida_segment, "SEGPERM_WRITE", 2):
            perm += "w"
        if p & getattr(ida_segment, "SEGPERM_EXEC", 1):
            perm += "x"
        results.append({
            "name": name,
            "start": f"0x{seg.start_ea:X}",
            "end": f"0x{seg.end_ea:X}",
            "size": f"0x{size:X}",
            "size_bytes": size,
            "permissions": perm or "-",
        })
    return results


def _scan_strings():
    """Full, unfiltered string inventory (cached)."""
    if not IDA_AVAILABLE:
        return []
    return [
        {"ea": f"0x{s.ea:X}", "length": s.length, "string": str(s)}
        for s in idautils.Strings()
    ]


def handle_strings_list(filter_str: str = "", limit: int = 50, offset: int = 0):
    """Lists defined strings with substring filtering and pagination."""
    records = _INVENTORY_CACHE.get_or_set("strings", _scan_strings)

    filter_lower = filter_str.lower() if filter_str else ""
    matched = [r for r in records if not filter_lower or filter_lower in r["string"].lower()]

    return {
        "total": len(matched),
        "offset": offset,
        "limit": limit,
        "count": len(matched[offset:offset + limit]),
        "strings": matched[offset:offset + limit],
    }


def _scan_classes():
    """Full, unfiltered class inventory (cached)."""
    if not IDA_AVAILABLE:
        return []
    class_map = {}
    inf_short = getattr(idc, "INF_SHORT_DN", 0)
    for ea in idautils.Functions():
        raw_name = idc.get_func_name(ea)
        demangled = (idc.demangle_name(raw_name, inf_short) or raw_name) if hasattr(idc, "demangle_name") else raw_name
        if "::" not in demangled:
            continue
        parts = demangled.split("::")
        class_name = "::".join(parts[:-1]).strip()
        if " " in class_name:
            class_name = class_name.split()[-1]
        entry = class_map.setdefault(class_name, {"name": class_name, "method_count": 0, "sample_methods": []})
        entry["method_count"] += 1
        if len(entry["sample_methods"]) < 5:
            entry["sample_methods"].append(f"0x{ea:X}: {parts[-1]}")
    return sorted(class_map.values(), key=lambda c: c["name"])


def handle_classes_list(filter_str: str = "", limit: int = 50):
    """Lists demangled C++ classes/namespaces with method counts."""
    classes = _INVENTORY_CACHE.get_or_set("classes", _scan_classes)
    if filter_str:
        filter_lower = filter_str.lower()
        classes = [c for c in classes if filter_lower in c["name"].lower()]
    return {
        "total": len(classes),
        "classes": classes[:limit],
    }


def handle_xrefs_from(target: str, limit: int = 50):
    """Lists code and data references originating from an address or function."""
    if not IDA_AVAILABLE:
        return {"target": target, "count": 0, "xrefs": []}

    try:
        ea = int(target, 16) if target.startswith("0x") or target.startswith("0X") else int(target)
    except ValueError:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            raise ValueError(f"Symbol '{target}' not found")

    func = ida_funcs.get_func(ea)
    items = list(idautils.FuncItems(ea)) if (func and func.start_ea == ea) else [ea]
    xrefs = []
    seen = set()

    for item_ea in items:
        # Code refs
        for to_ea in idautils.CodeRefsFrom(item_ea, 0):
            if to_ea not in seen:
                seen.add(to_ea)
                name = idc.get_func_name(to_ea) or idc.get_name(to_ea, idc.GN_VISIBLE)
                xrefs.append({
                    "from": f"0x{item_ea:X}",
                    "to": f"0x{to_ea:X}",
                    "type": "code",
                    "name": name or "<unnamed>",
                })
                if len(xrefs) >= limit:
                    break
        if len(xrefs) >= limit:
            break
        # Data refs
        for to_ea in idautils.DataRefsFrom(item_ea):
            if to_ea not in seen:
                seen.add(to_ea)
                name = idc.get_name(to_ea, idc.GN_VISIBLE) or idc.get_func_name(to_ea)
                xrefs.append({
                    "from": f"0x{item_ea:X}",
                    "to": f"0x{to_ea:X}",
                    "type": "data",
                    "name": name or "<unnamed>",
                })
                if len(xrefs) >= limit:
                    break
        if len(xrefs) >= limit:
            break

    return {
        "target": f"0x{ea:X}",
        "count": len(xrefs),
        "xrefs": xrefs,
    }


def handle_struct_inspect(name: str, include_members: bool = True, max_members: int = 200):
    """Inspect a named struct/class type: size, member count, and optional field layout."""
    if not IDA_AVAILABLE:
        return {}
    try:
        import ida_typeinf
        tif = ida_typeinf.tinfo_t()
        til = ida_typeinf.get_idati()
        if not tif.get_named_type(til, name):
            raise ValueError(f"Type '{name}' not found in IDA type system")

        size = tif.get_size()
        is_union = tif.is_union()
        result = {
            "name": name,
            "size": size,
            "size_hex": f"0x{size:X}",
            "is_union": is_union,
        }

        if include_members and tif.is_struct():
            udt = ida_typeinf.udt_type_data_t()
            if tif.get_udt_details(udt):
                members = []
                for i, member in enumerate(udt):
                    if i >= max_members:
                        break
                    moff = member.offset // 8  # bits → bytes
                    msize = member.size // 8
                    mname = member.name
                    try:
                        mtype = str(member.type) if member.type else ""
                    except Exception:
                        mtype = ""
                    members.append({
                        "name": mname,
                        "offset": moff,
                        "offset_hex": f"0x{moff:X}",
                        "size": msize,
                        "type": mtype,
                    })
                result["members"] = members
                result["member_count"] = len(udt)
        return result
    except Exception:
        # Fallback: try idc approach
        try:
            sid = idc.get_struc_id(name)
            if sid == idc.BADADDR:
                raise ValueError(f"Struct '{name}' not found")
            size = idc.get_struc_size(sid)
            result = {"name": name, "size": size, "size_hex": f"0x{size:X}", "is_union": False}
            if include_members:
                members = []
                moff = idc.get_first_member(sid)
                while moff != idc.BADADDR:
                    mname = idc.get_member_name(sid, moff)
                    msize = idc.get_member_size(sid, moff)
                    if mname is not None:
                        members.append({
                            "name": mname,
                            "offset": moff,
                            "offset_hex": f"0x{moff:X}",
                            "size": msize,
                            "type": "",
                        })
                    moff = idc.get_next_member(sid, moff)
                result["members"] = members
                result["member_count"] = len(members)
            return result
        except Exception as e:
            raise ValueError(f"Could not inspect type '{name}': {e}")


def handle_struct_search(pattern: str = "", limit: int = 50):
    """Search IDA local types by name pattern (case-insensitive substring)."""
    if not IDA_AVAILABLE:
        return []
    try:
        import ida_typeinf
        til = ida_typeinf.get_idati()
        count = ida_typeinf.get_ordinal_qty(til)
        pat = pattern.lower()
        results = []
        for ordinal in range(1, count + 1):
            tif = ida_typeinf.tinfo_t()
            if not tif.get_numbered_type(til, ordinal):
                continue
            name = tif.get_type_name() or ""
            if pat and pat not in name.lower():
                continue
            if not (tif.is_struct() or tif.is_union()):
                continue
            size = tif.get_size()
            results.append({
                "name": name,
                "size": size,
                "size_hex": f"0x{size:X}",
                "is_union": tif.is_union(),
                "ordinal": ordinal,
            })
            if len(results) >= limit:
                break
        return results
    except Exception:
        # Fallback: iterate idc structs
        results = []
        for i in range(idc.get_struc_qty() if hasattr(idc, "get_struc_qty") else 0):
            sid = idc.get_struc_by_idx(i)
            name = idc.get_struc_name(sid) or ""
            if pattern.lower() and pattern.lower() not in name.lower():
                continue
            size = idc.get_struc_size(sid)
            results.append({"name": name, "size": size, "size_hex": f"0x{size:X}"})
            if len(results) >= limit:
                break
        return results


def handle_locals_list(target: str):
    """List local variables (stack frame layout) of a function."""
    if not IDA_AVAILABLE:
        return {"target": target, "locals": []}
    try:
        ea = int(target, 16) if target.startswith(("0x", "0X")) else int(target)
    except ValueError:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            raise ValueError(f"Symbol '{target}' not found")

    func = ida_funcs.get_func(ea)
    if not func:
        raise ValueError(f"No function at 0x{ea:X}")

    frame = idc.get_func_attr(func.start_ea, idc.FUNCATTR_FRAME) if hasattr(idc, "FUNCATTR_FRAME") else None
    locals_list = []
    try:
        import ida_struct
        import ida_frame
        frm = ida_frame.get_frame(func) if hasattr(ida_frame, "get_frame") else None
        if frm:
            member = ida_struct.get_first_member(frm)
            while member:
                mname = ida_struct.get_member_name(member.id) or ""
                moff = member.soff
                msize = member.eoff - member.soff
                try:
                    mtype = idc.get_type(member.id) or ""
                except Exception:
                    mtype = ""
                # Negative offsets are stack args (above frame base), positive are locals
                locals_list.append({
                    "name": mname,
                    "offset": moff,
                    "offset_hex": f"{moff:+#x}",
                    "size": msize,
                    "type": mtype,
                    "kind": "arg" if mname.startswith("arg_") else "var" if mname.startswith("var_") else "other",
                })
                member = ida_struct.get_next_member(frm, member.soff)
    except Exception:
        pass

    return {
        "target": f"0x{func.start_ea:X}",
        "name": idc.get_func_name(func.start_ea),
        "frame_size": idc.get_frame_size(func.start_ea) if hasattr(idc, "get_frame_size") else 0,
        "local_count": len(locals_list),
        "locals": locals_list,
    }


def handle_vtable_list(target: str, limit: int = 128, include_rtti: bool = True, scan: bool = False):
    """Dump MSVC C++ vtable slots for a class name or vtable address.

    Understands MSVC naming (``??_7<Class>@@6B@``), reports the RTTI complete
    object locator pointer that immediately precedes the vtable, and stops at the
    first non-code slot unless ``scan`` is set (to walk past nulls into secondary
    / base-class vtables).
    """
    if not IDA_AVAILABLE:
        return {"target": target, "slots": []}

    import ida_bytes

    try:
        import ida_ida
        ptr_size = 8 if ida_ida.inf_is_64bit() else 4
    except Exception:
        ptr_size = 4

    def _read_ptr(addr):
        if ptr_size == 8:
            return ida_bytes.get_qword(addr)
        return ida_bytes.get_dword(addr)

    def _resolve_vtable_ea(name_or_addr: str):
        if name_or_addr.startswith(("0x", "0X")):
            try:
                return int(name_or_addr, 16)
            except ValueError:
                return idc.BADADDR
        ea_candidate = idc.get_name_ea_simple(name_or_addr)
        if ea_candidate != idc.BADADDR:
            return ea_candidate
        simple = name_or_addr.split("::")[-1].strip("`")
        for pattern in (f"??_7{name_or_addr}@@6B@", f"??_7{simple}@@6B@",
                        f"{name_or_addr}::`vftable'", name_or_addr):
            candidate = idc.get_name_ea_simple(pattern)
            if candidate != idc.BADADDR:
                return candidate
        return idc.BADADDR

    ea = _resolve_vtable_ea(target)
    if ea == idc.BADADDR:
        raise ValueError(f"Could not find vtable for '{target}'")

    # MSVC places the RTTI complete object locator immediately before the vftable.
    # Only report it when the preceding pointer is a mapped, non-code address;
    # the raw word before a vftable is not always a COL (e.g. padding/0x80000000).
    rtti = None
    if include_rtti:
        col_ptr = _read_ptr(ea - ptr_size)
        if col_ptr not in (0, idc.BADADDR) and ida_bytes.is_loaded(col_ptr):
            is_code = ida_bytes.is_code(ida_bytes.get_full_flags(col_ptr))
            if not is_code:
                try:
                    col_name = idc.get_name(col_ptr, getattr(idc, "GN_VISIBLE", 0)) or ""
                except Exception:
                    col_name = ""
                rtti = {"ea": f"0x{col_ptr:X}", "name": col_name}

    slots = []
    for i in range(limit):
        slot_ea = ea + i * ptr_size
        if not ida_bytes.is_loaded(slot_ea):
            break
        fn_ea = _read_ptr(slot_ea)
        if fn_ea == 0 or fn_ea == idc.BADADDR:
            if scan:
                continue
            break
        func = ida_funcs.get_func(fn_ea)
        if not func and not ida_bytes.is_code(ida_bytes.get_full_flags(fn_ea)):
            if scan:
                continue
            break
        name = idc.get_func_name(fn_ea) or f"sub_{fn_ea:X}"
        demangled = (idc.demangle_name(name, getattr(idc, "INF_SHORT_DN", 0)) or name) if hasattr(idc, "demangle_name") else name
        slots.append({
            "index": i,
            "slot_ea": f"0x{slot_ea:X}",
            "fn_ea": f"0x{fn_ea:X}",
            "vtable_offset": f"0x{i * ptr_size:X}",
            "mangled": name,
            "name": demangled,
        })

    return {
        "vtable_ea": f"0x{ea:X}",
        "target": target,
        "ptr_size": ptr_size,
        "rtti": rtti,
        "slot_count": len(slots),
        "slots": slots,
    }


def _scan_names():
    """Full, unfiltered name inventory (cached)."""
    if not IDA_AVAILABLE:
        return []
    return [(ea, name) for ea, name in idautils.Names()]


def handle_names_list(filter_str: str = "", limit: int = 100, offset: int = 0):
    """List all named items in the IDB (functions, globals, labels, imports, etc.)."""
    records = _INVENTORY_CACHE.get_or_set("names", _scan_names)
    filter_lower = filter_str.lower() if filter_str else ""
    matched = [r for r in records if not filter_lower or filter_lower in r[1].lower()]
    page = matched[offset:offset + limit]
    results = [{"ea": f"0x{ea:X}", "name": name} for ea, name in page]
    return {"total": len(matched), "offset": offset, "limit": limit, "count": len(results), "names": results}


def handle_cache_invalidate():
    """Drop cached inventory scans (call after any mutation)."""
    _INVENTORY_CACHE.invalidate()
    return {"status": "invalidated"}


def handle_cache_stats():
    """Report cache keys and hit/miss counters."""
    return _INVENTORY_CACHE.stats()


def handle_imports_list(filter_str: str = "", limit: int = 200):
    """List PE import entries: DLL name, function name, and import table address."""
    if not IDA_AVAILABLE:
        return {"total": 0, "imports": []}
    results = []
    filter_lower = filter_str.lower() if filter_str else ""
    try:
        import ida_nalt as _nalt
        nimps = _nalt.get_import_module_qty()
        for mod_idx in range(nimps):
            mod_name = _nalt.get_import_module_name(mod_idx)
            def _cb(ea, name, ordinal, _mod=mod_name, _res=results, _fl=filter_lower, _lim=limit):
                if len(_res) >= _lim:
                    return False
                sym = name or f"#{ordinal}"
                if _fl and _fl not in (_mod + sym).lower():
                    return True
                _res.append({"module": _mod, "name": sym, "ea": f"0x{ea:X}", "ordinal": ordinal})
                return True
            _nalt.enum_import_names(mod_idx, _cb)
    except Exception:
        pass
    return {"total": len(results), "imports": results}


def handle_exports_list(filter_str: str = ""):
    """List PE export entries: ordinal, name, and entry address."""
    if not IDA_AVAILABLE:
        return {"total": 0, "exports": []}
    filter_lower = filter_str.lower() if filter_str else ""
    results = []
    try:
        for ordinal, ea, name in idautils.Entries():
            sym = name or f"#{ordinal}"
            if filter_lower and filter_lower not in sym.lower():
                continue
            results.append({"ordinal": ordinal, "ea": f"0x{ea:X}", "name": sym})
    except Exception:
        pass
    return {"total": len(results), "exports": results}


def handle_goto_addr(target: str):
    """Jump the IDA GUI cursor to the given address or symbol name."""
    if not IDA_AVAILABLE:
        return {"status": "offline", "ea": target}
    try:
        ea = int(target, 16) if target.startswith(("0x", "0X")) else int(target)
    except ValueError:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            raise ValueError(f"Symbol '{target}' not found")
    ida_kernwin.jumpto(ea)
    return {"status": "ok", "ea": f"0x{ea:X}"}


def handle_close_ida(save: bool = True, exit_code: int = 0):
    """Save (optional) and gracefully exit IDA Pro."""
    if not IDA_AVAILABLE:
        return {"status": "offline"}

    saved = False
    if save:
        try:
            import ida_loader
            ida_loader.save_database(None, 0)
            saved = True
        except Exception:
            try:
                import idc
                idc.save_database("")
                saved = True
            except Exception:
                pass
    else:
        try:
            import ida_loader
            if hasattr(ida_loader, "set_database_flag") and hasattr(ida_loader, "DBFL_KILL"):
                ida_loader.set_database_flag(ida_loader.DBFL_KILL)
        except Exception:
            pass

    try:
        unregister_instance_file()
    except Exception:
        pass

    def _do_exit():
        time.sleep(0.2)
        try:
            import ida_pro
            ida_pro.qexit(exit_code)
        except Exception:
            try:
                import idaapi
                idaapi.qexit(exit_code)
            except Exception:
                os._exit(exit_code)

    threading.Thread(target=_do_exit, daemon=True).start()
    return {"status": "closing", "saved": saved, "exit_code": exit_code}


def register_mcp_tools() -> bool:
    """Register ida-pro-mcp's richer tools. Returns True if any were loaded."""
    try:
        from .bridge import load_mcp_commands
        mcp_cmds = load_mcp_commands()
        if mcp_cmds:
            _command_registry.update(mcp_cmds)
            print(f"[IDA-CLI] Loaded {len(mcp_cmds)} tools from ida-pro-mcp")
            return True
        print("[IDA-CLI] Notice: ida-pro-mcp present but exposed no tools; "
              "native fallbacks remain active")
        return False
    except Exception as e:
        print(f"[IDA-CLI] Notice: Could not load ida-pro-mcp tools: {e}")
        return False


def register_plugins():
    try:
        from .plugins import register_server_plugins
        register_server_plugins(_command_registry)
    except Exception as e:
        print(f"[IDA-CLI] Notice: Could not load server plugins: {e}")


# Register built-ins
_command_registry["status"]         = (handle_status,         "Get active database and IDA status", True)
_command_registry["exec"]           = (handle_exec,           "Execute arbitrary Python code inside IDA", True)
_command_registry["exec_file"]      = (handle_exec_file,      "Execute a Python script file inside IDA", True)
_command_registry["funcs_list"]     = (handle_funcs_list,     "List functions with filtering and pagination", True)
_command_registry["func_inspect"]   = (handle_func_inspect,   "Inspect a function (summary card with callers/callees)", True)
_command_registry["cursor_info"]    = (handle_cursor_info,    "Get active GUI cursor position, function, and disassembly", True)
_command_registry["segments_list"]  = (handle_segments_list,  "List all memory segments, boundaries, and permissions", True)
_command_registry["strings_list"]   = (handle_strings_list,   "List defined strings with substring filtering and pagination", True)
_command_registry["classes_list"]   = (handle_classes_list,   "List demangled C++ classes/namespaces with method counts", True)
_command_registry["xrefs_from"]     = (handle_xrefs_from,    "List outgoing code and data references from an address", True)
_command_registry["struct_inspect"] = (handle_struct_inspect, "Inspect a named struct/class type layout and members", True)
_command_registry["struct_search"]  = (handle_struct_search,  "Search IDA local types by name pattern", True)
_command_registry["locals_list"]    = (handle_locals_list,    "List local variables (stack frame) of a function", True)
_command_registry["vtable_list"]    = (handle_vtable_list,    "Dump vtable slots for a class or vtable address", True)
_command_registry["names_list"]     = (handle_names_list,     "List all named items in the IDB (globals, labels, imports)", True)
_command_registry["imports_list"]   = (handle_imports_list,   "List PE import entries (DLL, name, address)", True)
_command_registry["exports_list"]   = (handle_exports_list,   "List PE export entries (ordinal, name, address)", True)
_command_registry["goto_addr"]      = (handle_goto_addr,      "Jump the IDA GUI cursor to an address or symbol", True)
_command_registry["close_ida"]      = (handle_close_ida,      "Save (optional) and exit IDA Pro instance", True)
_command_registry["quit"]           = (handle_close_ida,      "Save (optional) and exit IDA Pro instance", True)
_command_registry["cache_invalidate"] = (handle_cache_invalidate, "Invalidate cached inventory scans", True)
_command_registry["cache_stats"]      = (handle_cache_stats,      "Report inventory cache statistics", True)

# Commands that can change the database and therefore invalidate inventory caches.
_CACHE_INVALIDATING_COMMANDS = frozenset({
    "rename", "set_type", "type_apply_batch", "set_comments", "append_comments",
    "patch", "patch_asm", "define_func", "define_code", "undefine", "make_data",
    "set_op_type", "force_recompile", "declare_type", "enum_upsert",
    "add_bookmark", "declare_stack", "delete_stack", "exec", "exec_file", "idb_save",
})

# Native fallbacks for core read commands. Registered before the MCP bridge so
# ida-pro-mcp's richer tools override these when available; without ida-pro-mcp
# they keep decompile/disasm/xrefs/callees/lookup/bytes working.
_command_registry["decompile"]    = (native.handle_decompile,    "Decompile function to C pseudocode (native fallback)", True)
_command_registry["disasm"]       = (native.handle_disasm,       "Disassemble function instructions (native fallback)", True)
_command_registry["xrefs_to"]     = (native.handle_xrefs_to,     "Cross-references to address(es) (native fallback)", True)
_command_registry["callees"]      = (native.handle_callees,      "Functions called by target(s) (native fallback)", True)
_command_registry["lookup_funcs"] = (native.handle_lookup_funcs, "Look up functions by name/address (native fallback)", True)
_command_registry["get_bytes"]    = (native.handle_get_bytes,    "Read memory bytes (native fallback)", True)
_command_registry["disasm_chunks"]    = (native.handle_disasm_chunks,    "Disassemble all function chunks (incl. .text$x tails)", True)
_command_registry["analyze_function"] = (native.handle_analyze_function, "Composite function analysis (native fallback)", True)
_command_registry["insn_query"]       = (native.handle_insn_query,       "Scan instructions by mnemonic/operand/imm (native fallback)", True)
_command_registry["force_recompile"]  = (native.handle_force_recompile,  "Invalidate Hex-Rays cache for functions (native fallback)", True)
_command_registry["type_apply_batch"] = (native.handle_type_apply_batch, "Apply multiple type declarations (native fallback)", True)
_command_registry["survey_binary"]    = (native.handle_survey_binary,    "High-level binary survey (native fallback)", True)
_command_registry["search_text"]      = (native.handle_search_text,      "Search disassembly text (native fallback)", True)
_command_registry["struct_inspect"]   = (native.handle_struct_inspect,   "Inspect a named struct/class type (native fallback)", True)
_command_registry["struct_search"]    = (native.handle_struct_search,    "Search local types by name (native fallback)", True)

_MCP_TOOLS_LOADED = register_mcp_tools()
register_plugins()

# Explicit warning when the simplified native implementations are what callers
# will actually hit. Without ida-pro-mcp they are approximate (no tail-chunk
# disasm, no per-line refs, linear scans) and users should know.
if not _MCP_TOOLS_LOADED:
    print("[IDA-CLI] Warning: ida-pro-mcp unavailable; using approximate native "
          "fallbacks for decompile/disasm/xrefs/callees/lookup/bytes/analyze/"
          "insn_query/search/structs. Install ida-pro-mcp for full fidelity.")


def send_http_response(conn, status_code: int, status_text: str, data: dict):
    send_raw_response(conn, status_code, status_text, json.dumps(data, indent=2).encode("utf-8"))


def send_raw_response(conn, status_code: int, status_text: str, body: bytes,
                      content_type: str = "application/json", extra_headers=None):
    headers = (
        f"HTTP/1.1 {status_code} {status_text}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n"
    )
    if extra_headers:
        for k, v in extra_headers.items():
            headers += f"{k}: {v}\r\n"
    try:
        conn.settimeout(None)
        conn.sendall(headers.encode("utf-8") + b"\r\n" + body)
    except Exception:
        pass


_OUTPUT_PATH_RE = re.compile(r"^/output/([A-Za-z0-9\-]+)\.(\w+)$")


def get_download_base_url() -> str:
    if _server_port:
        return f"http://127.0.0.1:{_server_port}"
    return ""


def get_mcp_server():
    """Return ida-pro-mcp's in-process MCP server, or None if unavailable."""
    try:
        from ida_pro_mcp.ida_mcp import MCP_SERVER as mcp
        return mcp
    except Exception:
        try:
            from ida_mcp import MCP_SERVER as mcp
            return mcp
        except Exception:
            return None


def get_mcp_cached_output(output_id: str):
    """Fetch a full payload from ida-pro-mcp's tools/call output cache."""
    try:
        from ida_pro_mcp.ida_mcp import rpc as _rpc
    except Exception:
        try:
            from ida_mcp import rpc as _rpc
        except Exception:
            return None
    try:
        return _rpc.get_cached_output(output_id)
    except Exception:
        return None


def render_output_download(data, extension: str) -> bytes:
    if extension == "json":
        return json.dumps(data, indent=2).encode("utf-8")
    if isinstance(data, dict) and "code" in data:
        return str(data["code"]).encode("utf-8")
    if isinstance(data, list) and data and isinstance(data[0], dict):
        text = "\n\n".join(
            str(item.get("code", item.get("asm", item.get("lines", "")))) for item in data
        )
        return text.encode("utf-8")
    return json.dumps(data, indent=2).encode("utf-8")


# ---------------------------------------------------------------------------
# Matcher compatibility (ida_live_matching_diff) — serves the same HTTP API as
# the legacy port-28000 ida_server.py so the matcher can talk to any ida-cli
# instance. Prefers the plugin's registered match_* commands; falls back to
# ida_matcher.matcher.ida_logic (which self-synchronizes on the main thread).
# ---------------------------------------------------------------------------

def _matcher_logic():
    from ida_matcher.matcher import ida_logic
    return ida_logic


def _matcher_get_func(name):
    return _matcher_logic().get_function_bytes(name)


def _matcher_get_funcs(names):
    il = _matcher_logic()
    return {n: il.get_function_bytes(n) for n in names}


def _matcher_get_data(name):
    return _matcher_logic().get_data_bytes(name)


def _matcher_get_datas(names):
    il = _matcher_logic()
    return {n: il.get_data_bytes(n) for n in names}


def _matcher_all_names():
    il = _matcher_logic()
    if not il.FUNC_CACHE:
        il.build_cache()
    return {"names": list(il.FUNC_CACHE.keys())}


def _matcher_baseline():
    return _matcher_logic().get_baseline()


def _matcher_refresh():
    _matcher_logic().build_cache()
    return {"status": "refreshed"}


def _matcher_synthetic_obj(name):
    il = _matcher_logic()
    builder = getattr(il, "build_synthetic_obj", None)
    return builder(name) if builder else None


def call_matcher(cmd_name, params, fallback):
    """Invoke a matcher command via the registry, else the ida_logic fallback."""
    entry = _command_registry.get(cmd_name)
    try:
        if entry:
            func = entry[0]
            needs_wrap = entry[2] if len(entry) > 2 else True
            return execute_on_main_thread(func, **params) if needs_wrap else func(**params)
        return fallback(**params)
    except Exception:
        traceback.print_exc()
        return None


def handle_client(conn):
    try:
        conn.settimeout(1.0)
        raw_header = b""
        while b"\r\n\r\n" not in raw_header:
            chunk = conn.recv(1024)
            if not chunk:
                break
            raw_header += chunk

        if not raw_header:
            return

        header_part, _, body_prefix = raw_header.partition(b"\r\n\r\n")
        header_text = header_part.decode("utf-8", errors="ignore")
        lines = header_text.split("\r\n")
        if not lines:
            return

        request_line = lines[0]
        parts = request_line.split()
        if len(parts) < 2:
            return

        method, full_path = parts[0], parts[1]
        parsed = urlparse(full_path)
        path = parsed.path

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        content_length = int(headers.get("content-length", 0))
        body_bytes = body_prefix
        while len(body_bytes) < content_length:
            remaining = content_length - len(body_bytes)
            chunk = conn.recv(min(4096, remaining))
            if not chunk:
                break
            body_bytes += chunk

        payload = {}
        if body_bytes:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except Exception:
                send_http_response(conn, 400, "Bad Request", {"success": False, "error": "Invalid JSON"})
                return

        if method == "GET":
            if path in ("/status", "/health"):
                try:
                    res = execute_on_main_thread(handle_status)
                    send_http_response(conn, 200, "OK", {"success": True, "data": res})
                except Exception as e:
                    send_http_response(conn, 500, "Internal Server Error", {"success": False, "error": str(e)})

            elif path == "/commands":
                cmd_list = {}
                for name, entry in _command_registry.items():
                    doc = entry[1] if len(entry) > 1 else ""
                    cmd_list[name] = {"description": doc}
                send_http_response(conn, 200, "OK", {"success": True, "commands": cmd_list})

            elif _OUTPUT_PATH_RE.match(path):
                match = _OUTPUT_PATH_RE.match(path)
                output_id, extension = match.group(1), match.group(2)
                data = OUTPUT_STORE.get(output_id)
                if data is None:
                    data = get_mcp_cached_output(output_id)
                if data is None:
                    send_http_response(conn, 404, "Not Found",
                                       {"success": False, "error": "Output not found or expired"})
                else:
                    body = render_output_download(data, extension)
                    content_type = "application/json" if extension == "json" else "text/plain"
                    send_raw_response(conn, 200, "OK", body, content_type=content_type,
                                      extra_headers={"Content-Disposition": f'attachment; filename="{output_id}.{extension}"'})

            elif path == "/func":
                name = (parse_qs(parsed.query).get("name") or [None])[0]
                rec = call_matcher("match_get_func", {"name": name}, _matcher_get_func) if name else None
                if rec:
                    send_raw_response(conn, 200, "OK", json.dumps(rec).encode("utf-8"))
                else:
                    send_raw_response(conn, 404, "Not Found", json.dumps({"error": "not found"}).encode("utf-8"))

            elif path == "/funcs":
                names = [n for n in (parse_qs(parsed.query).get("names") or [""])[0].split(",") if n]
                recs = call_matcher("match_get_funcs", {"names": names}, _matcher_get_funcs) or {}
                if isinstance(recs, dict) and "results" in recs:
                    recs = recs.get("results") or {}
                send_raw_response(conn, 200, "OK", json.dumps({"results": recs}).encode("utf-8"))

            elif path == "/data":
                name = (parse_qs(parsed.query).get("name") or [None])[0]
                rec = call_matcher("match_get_data", {"name": name}, _matcher_get_data) if name else None
                if rec:
                    send_raw_response(conn, 200, "OK", json.dumps(rec).encode("utf-8"))
                else:
                    send_raw_response(conn, 404, "Not Found", json.dumps({"error": "not found"}).encode("utf-8"))

            elif path == "/datas":
                names = [n for n in (parse_qs(parsed.query).get("names") or [""])[0].split(",") if n]
                recs = call_matcher("match_get_datas", {"names": names}, _matcher_get_datas) or {}
                if isinstance(recs, dict) and "results" in recs:
                    recs = recs.get("results") or {}
                send_raw_response(conn, 200, "OK", json.dumps({"results": recs}).encode("utf-8"))

            elif path == "/all_names":
                names = call_matcher("match_all_names", {}, _matcher_all_names) or {}
                if isinstance(names, dict):
                    names = names.get("names", [])
                send_raw_response(conn, 200, "OK", json.dumps({"names": names}).encode("utf-8"))

            elif path == "/baseline":
                baseline = call_matcher("match_get_baseline", {}, _matcher_baseline) or {}
                body = json.dumps(baseline).encode("utf-8")
                # Legacy behaviour serves the full snapshot raw (it is a bulk
                # export, not a browse response), but log oversized payloads so a
                # huge IDB doesn't silently blow up memory/transfer unnoticed.
                if len(body) > 10_000_000:
                    print(f"[IDA-CLI] Warning: /baseline payload is {len(body)} bytes "
                          "(no output limiter applied to matcher baseline exports)")
                send_raw_response(conn, 200, "OK", body)

            elif path == "/refresh":
                call_matcher("match_refresh", {}, _matcher_refresh)
                send_raw_response(conn, 200, "OK", json.dumps({"status": "refreshed"}).encode("utf-8"))

            elif path == "/synthetic_obj":
                name = (parse_qs(parsed.query).get("name") or [None])[0]
                blob = call_matcher("match_get_synthetic_obj", {"name": name}, _matcher_synthetic_obj) if name else None
                if blob:
                    send_raw_response(conn, 200, "OK", bytes(blob), content_type="application/octet-stream")
                else:
                    send_raw_response(conn, 404, "Not Found", json.dumps({"error": "not found"}).encode("utf-8"))

            elif path == "/mcp":
                # MCP streamable-HTTP uses POST; no server-initiated SSE stream.
                send_raw_response(conn, 405, "Method Not Allowed", b"",
                                  extra_headers={"Allow": "POST"})

            else:
                send_http_response(conn, 404, "Not Found", {"success": False, "error": f"Unknown path {path}"})

        elif method == "POST":
            if path == "/mcp":
                mcp = get_mcp_server()
                if mcp is None:
                    send_raw_response(
                        conn, 503, "Service Unavailable",
                        json.dumps({
                            "jsonrpc": "2.0",
                            "error": {
                                "code": -32601,
                                "message": "ida-pro-mcp (ida_mcp package) is not available in IDA's Python environment",
                            },
                            "id": payload.get("id"),
                        }).encode("utf-8"),
                    )
                    return
                try:
                    response = mcp.registry.dispatch(payload)
                except Exception as e:
                    response = {
                        "jsonrpc": "2.0",
                        "error": {"code": -32603, "message": str(e)},
                        "id": payload.get("id"),
                    }
                if response is None:
                    # JSON-RPC notification: no response body (MCP expects 202).
                    send_raw_response(conn, 202, "Accepted", b"")
                else:
                    extra = {}
                    session_id = headers.get("mcp-session-id")
                    if not session_id and payload.get("method") == "initialize":
                        session_id = str(uuid.uuid4())
                    if session_id:
                        extra["Mcp-Session-Id"] = session_id
                    send_raw_response(conn, 200, "OK", json.dumps(response).encode("utf-8"),
                                      extra_headers=extra)
                return

            if path == "/exec":
                code = payload.get("code", "")
                try:
                    res = execute_on_main_thread(handle_exec, code)
                    send_http_response(conn, 200, "OK", {"success": True, "data": res})
                except Exception as e:
                    send_http_response(conn, 500, "Internal Server Error", {"success": False, "error": str(e), "traceback": traceback.format_exc()})

            elif path == "/command":
                cmd_name = payload.get("command", "")
                params = payload.get("params", {})
                if cmd_name not in _command_registry:
                    send_http_response(conn, 400, "Bad Request", {"success": False, "error": f"Unknown command {cmd_name}"})
                    return

                entry = _command_registry[cmd_name]
                func = entry[0]
                needs_sync_wrap = entry[2] if len(entry) > 2 else True

                try:
                    if needs_sync_wrap:
                        res = execute_on_main_thread(func, **params)
                    else:
                        res = func(**params)
                    if cmd_name in _CACHE_INVALIDATING_COMMANDS:
                        _INVENTORY_CACHE.invalidate()
                    limited, output_meta = OUTPUT_STORE.limit(res, download_base_url=get_download_base_url())
                    response = {"success": True, "command": cmd_name, "data": limited}
                    if output_meta:
                        response["_output"] = output_meta
                    send_http_response(conn, 200, "OK", response)
                except Exception as e:
                    send_http_response(conn, 500, "Internal Server Error", {"success": False, "error": str(e), "traceback": traceback.format_exc()})
            else:
                send_http_response(conn, 404, "Not Found", {"success": False, "error": f"Unknown path {path}"})

    except Exception as e:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _accept_loop():
    global SERVER_SOCKET
    while SERVER_SOCKET:
        try:
            conn, _ = SERVER_SOCKET.accept()
            threading.Thread(target=handle_client, args=(conn,), daemon=True).start()
        except socket.timeout:
            continue
        except Exception:
            break


def _heartbeat_callback():
    global _server_port
    if _server_port:
        update_instance_heartbeat(_server_port)
    return HEARTBEAT_INTERVAL_MS


def start_server() -> int:
    global SERVER_SOCKET, _server_thread, _server_port, _heartbeat_timer

    if SERVER_SOCKET is not None:
        print(f"[IDA-CLI] Server already running on port {_server_port}")
        return _server_port

    selected_port = None
    for port in DEFAULT_PORT_RANGE:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sys.platform == "win32":
                SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", -5)
                sock.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", port))
            sock.listen(10)
            sock.settimeout(1.0)
            SERVER_SOCKET = sock
            selected_port = port
            break
        except OSError:
            sock.close()
            continue

    if not SERVER_SOCKET:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sock.listen(10)
        sock.settimeout(1.0)
        SERVER_SOCKET = sock
        selected_port = SERVER_SOCKET.getsockname()[1]

    _server_port = selected_port

    # Point ida-pro-mcp's output-limit download links at this server so
    # tools/call responses reference the right port (default is 13337).
    try:
        from ida_pro_mcp.ida_mcp import rpc as _mcp_rpc
    except Exception:
        try:
            from ida_mcp import rpc as _mcp_rpc
        except Exception:
            _mcp_rpc = None
    if _mcp_rpc is not None:
        try:
            _mcp_rpc.set_download_base_url(f"http://127.0.0.1:{selected_port}")
        except Exception:
            pass

    # Register discovery file
    instance_path = register_instance_file(selected_port)
    print(f"[IDA-CLI] Server started on http://127.0.0.1:{selected_port}")
    print(f"[IDA-CLI] Registered instance descriptor at {instance_path}")

    _server_thread = threading.Thread(target=_accept_loop, daemon=True)
    _server_thread.start()

    if IDA_AVAILABLE:
        _heartbeat_timer = ida_kernwin.register_timer(HEARTBEAT_INTERVAL_MS, _heartbeat_callback)
        # Headless-safe refresh: in idat mode the GUI timer above never fires,
        # so poll the descriptor from a daemon thread until the IDB is known.
        _start_descriptor_refresh_thread()

    return selected_port


def _start_descriptor_refresh_thread(interval: float = 1.0, max_iterations: int = 600) -> None:
    def _loop():
        # Refresh for a bounded window (10 min at 1s). Headless mode has no GUI
        # event loop, so the heartbeat timer never runs; this keeps the
        # descriptor's IDB/input paths and status current until IDA settles.
        # Interactive mode's heartbeat timer takes over the same fields.
        for _ in range(max_iterations):
            if SERVER_SOCKET is None:
                return
            try:
                refresh_instance_info()
            except Exception:
                pass
            time.sleep(interval)

    threading.Thread(target=_loop, daemon=True, name="ida-cli-descriptor-refresh").start()


def stop_server():
    global SERVER_SOCKET, _server_thread, _server_port, _heartbeat_timer

    if _heartbeat_timer and IDA_AVAILABLE:
        ida_kernwin.unregister_timer(_heartbeat_timer)
        _heartbeat_timer = None

    unregister_instance_file()

    if SERVER_SOCKET:
        print("[IDA-CLI] Stopping server...")
        sock = SERVER_SOCKET
        SERVER_SOCKET = None
        try:
            sock.close()
        except Exception:
            pass
        _server_thread = None
        _server_port = None
        print("[IDA-CLI] Server stopped.")
