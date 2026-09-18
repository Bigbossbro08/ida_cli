"""
IDA CLI Connector Server
Runs inside IDA Pro, starts a lightweight socket HTTP server,
manages instance discovery registration, and dispatches incoming
commands onto IDA's main thread via execute_sync safely.
"""

import io
import json
import os
import socket
import sys
import threading
import time
import traceback
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
    input_file = get_input_file_path()
    slug = Path(idb).stem if idb else (Path(input_file).stem if input_file else "nodb")
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
                data["status"] = "busy" if (hasattr(ida_auto, "auto_is_ok") and not ida_auto.auto_is_ok()) else "ready"
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


def execute_on_main_thread(func, *args, _write: bool = False, **kwargs):
    """Executes a callable on IDA's main UI thread safely using execute_sync."""
    if not IDA_AVAILABLE:
        return func(*args, **kwargs)

    result_box = [None, None]
    event = threading.Event()

    def sync_callable():
        try:
            result_box[0] = func(*args, **kwargs)
        except Exception as ex:
            result_box[1] = ex
        finally:
            event.set()
        return 1

    flag = getattr(ida_kernwin, "MFF_WRITE", 0x2) if _write else (getattr(ida_kernwin, "MFF_FAST", 0x4) | getattr(ida_kernwin, "MFF_READ", 0x1))
    ida_kernwin.execute_sync(sync_callable, flag)
    if not event.wait(timeout=8.0):
        # If execute_sync did not run within timeout (e.g. headless idat or modal dialog),
        # execute directly as safe fallback
        try:
            return func(*args, **kwargs)
        except Exception as ex:
            raise ex

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
    """Executes Python code inside IDA, capturing stdout."""
    old_stdout = sys.stdout
    sys.stdout = buffer = io.StringIO()
    ret_val = None
    try:
        globals_dict = {}
        if IDA_AVAILABLE:
            globals_dict.update({
                "ida_auto": ida_auto,
                "ida_funcs": ida_funcs,
                "ida_idaapi": ida_idaapi,
                "ida_kernwin": ida_kernwin,
                "ida_loader": ida_loader,
                "ida_nalt": ida_nalt,
                "idc": idc,
                "idautils": idautils,
            })
        try:
            ret_val = eval(code, globals_dict)
        except SyntaxError:
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
            func = ida_funcs.get_func(ea)
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


def handle_strings_list(filter_str: str = "", limit: int = 50, offset: int = 0):
    """Lists defined strings with substring filtering and pagination."""
    if not IDA_AVAILABLE:
        return {"total": 0, "strings": []}

    filter_lower = filter_str.lower() if filter_str else ""
    results = []
    total = 0

    for s in idautils.Strings():
        text = str(s)
        if filter_lower and filter_lower not in text.lower():
            continue
        total += 1
        if total <= offset:
            continue
        if len(results) < limit:
            results.append({
                "ea": f"0x{s.ea:X}",
                "length": s.length,
                "string": text,
            })

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "count": len(results),
        "strings": results,
    }


def handle_classes_list(filter_str: str = "", limit: int = 50):
    """Lists demangled C++ classes/namespaces with method counts."""
    if not IDA_AVAILABLE:
        return {"total": 0, "classes": []}

    filter_lower = filter_str.lower() if filter_str else ""
    class_map = {}
    inf_short = getattr(idc, "INF_SHORT_DN", 0)

    for ea in idautils.Functions():
        raw_name = idc.get_func_name(ea)
        demangled = (idc.demangle_name(raw_name, inf_short) or raw_name) if hasattr(idc, "demangle_name") else raw_name
        if "::" in demangled:
            parts = demangled.split("::")
            class_name = "::".join(parts[:-1]).strip()
            if " " in class_name:
                class_name = class_name.split()[-1]
            if filter_lower and filter_lower not in class_name.lower():
                continue
            if class_name not in class_map:
                class_map[class_name] = {"name": class_name, "method_count": 0, "sample_methods": []}
            class_map[class_name]["method_count"] += 1
            if len(class_map[class_name]["sample_methods"]) < 5:
                class_map[class_name]["sample_methods"].append(f"0x{ea:X}: {parts[-1]}")

    classes = sorted(class_map.values(), key=lambda c: c["name"])
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


def handle_vtable_list(target: str, limit: int = 128):
    """Dump vtable slots at a given address or by class name (RTTI lookup)."""
    if not IDA_AVAILABLE:
        return {"target": target, "slots": []}

    # Resolve address: try as name first, then hex addr
    ea = idc.BADADDR
    if target.startswith(("0x", "0X")):
        try:
            ea = int(target, 16)
        except ValueError:
            pass
    else:
        ea = idc.get_name_ea_simple(target)
        if ea == idc.BADADDR:
            # Try common vtable name patterns
            for pattern in [f"??_7{target}@@6B@", f"{target}::`vftable'", target]:
                candidate = idc.get_name_ea_simple(pattern)
                if candidate != idc.BADADDR:
                    ea = candidate
                    break

    if ea == idc.BADADDR:
        raise ValueError(f"Could not find vtable for '{target}'")

    # Walk vtable: read pointer-sized values until they stop being function pointers
    ptr_size = 4  # assume 32-bit; IDA provides this
    try:
        import ida_ida
        info = ida_ida.inf_get_cc_size_b() if hasattr(ida_ida, "inf_get_cc_size_b") else 4
        ptr_size = max(4, info)
    except Exception:
        pass

    import ida_bytes
    slots = []
    for i in range(limit):
        slot_ea = ea + i * ptr_size
        if ptr_size == 8:
            fn_ea = ida_bytes.get_qword(slot_ea) if hasattr(ida_bytes, "get_qword") else idc.get_qword(slot_ea)
        else:
            fn_ea = ida_bytes.get_dword(slot_ea) if hasattr(ida_bytes, "get_dword") else idc.get_wide_dword(slot_ea)
        if fn_ea == 0 or fn_ea == idc.BADADDR:
            break
        func = ida_funcs.get_func(fn_ea)
        if not func:
            break  # no longer pointing at code
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
        "slot_count": len(slots),
        "slots": slots,
    }


def handle_names_list(filter_str: str = "", limit: int = 100, offset: int = 0):
    """List all named items in the IDB (functions, globals, labels, imports, etc.)."""
    if not IDA_AVAILABLE:
        return {"total": 0, "names": []}
    filter_lower = filter_str.lower() if filter_str else ""
    results = []
    total = 0
    for ea, name in idautils.Names():
        if filter_lower and filter_lower not in name.lower():
            continue
        total += 1
        if total <= offset:
            continue
        if len(results) >= limit:
            continue
        results.append({"ea": f"0x{ea:X}", "name": name})
    return {"total": total, "offset": offset, "limit": limit, "count": len(results), "names": results}


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


def register_mcp_tools():
    try:
        from .bridge import load_mcp_commands
        mcp_cmds = load_mcp_commands()
        if mcp_cmds:
            _command_registry.update(mcp_cmds)
            print(f"[IDA-CLI] Loaded {len(mcp_cmds)} tools from ida-pro-mcp")
    except Exception as e:
        print(f"[IDA-CLI] Notice: Could not load ida-pro-mcp tools: {e}")


def register_plugins():
    try:
        from .plugins import register_server_plugins
        register_server_plugins(_command_registry)
    except Exception as e:
        print(f"[IDA-CLI] Notice: Could not load server plugins: {e}")


# Register built-ins
_command_registry["status"]         = (handle_status,         "Get active database and IDA status", True)
_command_registry["exec"]           = (handle_exec,           "Execute arbitrary Python code inside IDA", True)
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

register_mcp_tools()
register_plugins()


def send_http_response(conn, status_code: int, status_text: str, data: dict):
    body = json.dumps(data, indent=2).encode("utf-8")
    header = (
        f"HTTP/1.1 {status_code} {status_text}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8")
    try:
        conn.settimeout(None)
        conn.sendall(header + body)
    except Exception:
        pass


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

            else:
                send_http_response(conn, 404, "Not Found", {"success": False, "error": f"Unknown path {path}"})

        elif method == "POST":
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
                    send_http_response(conn, 200, "OK", {"success": True, "command": cmd_name, "data": res})
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

    # Register discovery file
    instance_path = register_instance_file(selected_port)
    print(f"[IDA-CLI] Server started on http://127.0.0.1:{selected_port}")
    print(f"[IDA-CLI] Registered instance descriptor at {instance_path}")

    _server_thread = threading.Thread(target=_accept_loop, daemon=True)
    _server_thread.start()

    if IDA_AVAILABLE:
        _heartbeat_timer = ida_kernwin.register_timer(HEARTBEAT_INTERVAL_MS, _heartbeat_callback)

    return selected_port


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
