"""
IDA-CLI Terminal Interface
Fast, lightweight CLI for controlling IDA Pro via instance discovery, MCP bridge, and plugins.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .client import IdaClient, IdaClientError
from .discovery import find_ida_executable, is_pid_alive, list_instances, resolve_instance
from .plugins import register_cli_plugins, resolve_open_target

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def format_instance_table(instances) -> str:
    if not instances:
        return "No running IDA Pro instances found in ~/.ida-cli/instances/"

    lines = []
    lines.append(f"{'PID':<8} {'PORT':<8} {'STATUS':<10} {'IDB / FILE':<35} {'SCREEN EA':<12} {'LAST SEEN'}")
    lines.append("-" * 90)

    now = time.time()
    for inst in instances:
        diff_s = int(now - inst.last_heartbeat)
        seen_str = f"{diff_s}s ago" if diff_s >= 0 else "just now"
        name = inst.idb_name
        if len(name) > 33:
            name = "..." + name[-30:]
        lines.append(f"{inst.pid:<8} {inst.port:<8} {inst.status:<10} {name:<35} {inst.current_ea:<12} {seen_str}")

    return "\n".join(lines)


def get_client(target=None) -> IdaClient:
    instance = resolve_instance(target=target)
    if not instance:
        print("Error: No active IDA Pro instance found.", file=sys.stderr)
        print("Make sure IDA Pro is running with the ida_cli_plugin loaded.", file=sys.stderr)
        sys.exit(1)
    return IdaClient(instance)


def resolve_target(client: IdaClient, target: Optional[str], prefer_func: bool = True) -> str:
    """Resolves 'here', '.', or empty target to the current GUI cursor/function address."""
    if not target or target.strip().lower() in ("here", ".", "cursor"):
        cursor = client.run_command("cursor_info")
        if prefer_func and cursor.get("func_ea"):
            return cursor["func_ea"]
        if cursor.get("ea"):
            return cursor["ea"]
    return target


def parse_param_value(val_str: str) -> Any:
    lower = val_str.strip().lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower in ("null", "none"):
        return None
    if lower.startswith("0x") or lower.startswith("-0x"):
        return val_str.strip()
    try:
        return int(val_str)
    except ValueError:
        pass
    try:
        return float(val_str)
    except ValueError:
        pass
    return val_str


def parse_key_value_params(params_list: Optional[List[str]]) -> Dict[str, Any]:
    params = {}
    if not params_list:
        return params
    for item in params_list:
        if "=" in item:
            k, v = item.split("=", 1)
            params[k.strip()] = parse_param_value(v)
        else:
            params[item.strip()] = True
    return params


# Subcommand handlers

def cmd_struct(args):
    client = get_client(args.instance)
    params = {
        "name": args.name,
        "include_members": not args.no_members,
        "max_members": args.max_members,
    }
    res = client.run_command("struct_inspect", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not res:
            print(f"Type '{args.name}' not found.")
            return
        print(f"Struct: {res.get('name')}  SIZE: {res.get('size_hex')} ({res.get('size')} bytes)  union={res.get('is_union', False)}")
        members = res.get("members", [])
        if members:
            mc = res.get("member_count", len(members))
            print(f"Members ({len(members)} shown of {mc}):")
            print(f"  {'OFFSET':<10} {'SIZE':<6} {'TYPE':<30} {'NAME'}")
            print("  " + "-" * 70)
            for m in members:
                print(f"  {m.get('offset_hex', ''):<10} {m.get('size', ''):<6} {str(m.get('type', '')):<30} {m.get('name', '')}")


def cmd_structs(args):
    client = get_client(args.instance)
    res = client.run_command("struct_search", {"pattern": args.pattern or "", "limit": args.limit})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        items = res if isinstance(res, list) else []
        print(f"Found {len(items)} struct(s):")
        for s in items:
            print(f"  {s.get('name'):<50}  {s.get('size_hex'):<8} ({s.get('size')} bytes)  {'[union]' if s.get('is_union') else ''}")


def cmd_locals(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    res = client.run_command("locals_list", {"target": target})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        name = res.get("name", target)
        print(f"Stack frame for {name} @ {res.get('target')}  (frame_size={res.get('frame_size')})")
        locals_data = res.get("locals", [])
        if not locals_data:
            print("  (no named locals)")
            return
        print(f"  {'OFFSET':<10} {'SIZE':<6} {'KIND':<6} {'TYPE':<24} {'NAME'}")
        print("  " + "-" * 60)
        for v in locals_data:
            print(f"  {v.get('offset_hex', ''):<10} {v.get('size', ''):<6} {v.get('kind', ''):<6} {str(v.get('type','')):<24} {v.get('name', '')}")


def cmd_vtable(args):
    client = get_client(args.instance)
    res = client.run_command("vtable_list", {"target": args.target, "limit": args.limit})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Vtable @ {res.get('vtable_ea')} for '{res.get('target')}' ({res.get('slot_count')} slots, ptr_size={res.get('ptr_size')})")
        print(f"  {'IDX':<5} {'OFFSET':<10} {'FUNC EA':<14} {'NAME'}")
        print("  " + "-" * 80)
        for s in res.get("slots", []):
            print(f"  {s.get('index'):<5} {s.get('vtable_offset'):<10} {s.get('fn_ea'):<14} {s.get('name')}")


def cmd_names(args):
    client = get_client(args.instance)
    params = {
        "filter_str": args.filter or "",
        "limit": args.limit,
        "offset": args.offset,
    }
    res = client.run_command("names_list", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        names = res.get("names", [])
        print(f"Showing {len(names)} of {res.get('total', 0)} names:")
        for n in names:
            print(f"  {n.get('ea'):<14}  {n.get('name')}")


def cmd_imports(args):
    client = get_client(args.instance)
    params = {"filter_str": args.filter or "", "limit": args.limit}
    res = client.run_command("imports_list", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        imports = res.get("imports", [])
        print(f"Found {res.get('total', len(imports))} imports:")
        for imp in imports:
            print(f"  {imp.get('ea'):<14}  {imp.get('module')}!{imp.get('name')}")


def cmd_exports(args):
    client = get_client(args.instance)
    params = {"filter_str": args.filter or ""}
    res = client.run_command("exports_list", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        exports = res.get("exports", [])
        print(f"Found {res.get('total', len(exports))} exports:")
        for exp in exports:
            print(f"  #{exp.get('ordinal'):<6} {exp.get('ea'):<14}  {exp.get('name')}")


def cmd_goto(args):
    client = get_client(args.instance)
    res = client.run_command("goto_addr", {"target": args.target})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Jumped to {res.get('ea')} [status: {res.get('status')}]")


def cmd_open(args):
    import subprocess

    target = getattr(args, "file", None)
    # Hook from plugins (e.g. rogan2 plugin defaults to age2_x1.exe.i64)
    target = resolve_open_target(target)

    # If target is still None, check if there's a unique .i64 or .idb in CWD
    if not target:
        cwd = Path.cwd()
        local_dbs = list(cwd.glob("*.i64")) + list(cwd.glob("*.idb"))
        if len(local_dbs) == 1:
            target = str(local_dbs[0])

    ida_exe = getattr(args, "ida_path", None)
    if ida_exe:
        ida_path = Path(ida_exe)
    else:
        ida_path = find_ida_executable(headless=getattr(args, "headless", False))

    if not ida_path or not ida_path.exists():
        print("Error: Could not locate IDA Pro executable.", file=sys.stderr)
        print("Set IDA_EXE environment variable or specify --ida-path <path>.", file=sys.stderr)
        sys.exit(1)

    cmd = [str(ida_path)]
    if getattr(args, "headless", False):
        cmd.append("-A")

    resolved_target_path = None
    if target:
        target_p = Path(target).resolve()
        if not target_p.exists():
            print(f"Error: Target file '{target}' does not exist.", file=sys.stderr)
            sys.exit(1)
        cmd.append(str(target_p))
        resolved_target_path = target_p

    # Pass any extra IDA flags if provided
    extra = getattr(args, "extra_args", None)
    if extra:
        cmd.extend(extra)

    # Spawn process detached from console and job object
    creationflags = 0
    if sys.platform == "win32":
        DETACHED_PROCESS = 0x00000008
        CREATE_NEW_PROCESS_GROUP = 0x00000200
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000
        creationflags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB

    proc = None
    try:
        proc = subprocess.Popen(
            cmd,
            creationflags=creationflags,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        try:
            fallback_flags = (0x00000008 | 0x00000200) if sys.platform == "win32" else 0
            proc = subprocess.Popen(
                cmd,
                creationflags=fallback_flags,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"Error launching IDA Pro: {e}", file=sys.stderr)
            sys.exit(1)

    target_disp = str(resolved_target_path) if resolved_target_path else "(no file / quick start)"
    if getattr(args, "detach", False):
        if args.json:
            print(json.dumps({"pid": proc.pid, "target": str(resolved_target_path) if resolved_target_path else None, "status": "launched"}, indent=2), flush=True)
        else:
            print(f"Launched IDA Pro (PID: {proc.pid}) with {target_disp}.", flush=True)
        return

    # Wait for instance to become available
    timeout = getattr(args, "timeout", 30)
    print(f"Launched IDA Pro (PID: {proc.pid}) with {target_disp}.", flush=True)
    print(f"Waiting for IDA-CLI connector to come online (timeout: {timeout}s)...", flush=True)

    start_time = time.time()
    found_instance = None
    while time.time() - start_time < timeout:
        inst = resolve_instance(target=str(proc.pid))
        if not inst and resolved_target_path:
            inst = resolve_instance(target=resolved_target_path.name)
        if inst:
            found_instance = inst
            break
        time.sleep(0.5)

    if found_instance:
        if args.json:
            print(json.dumps({
                "pid": found_instance.pid,
                "port": found_instance.port,
                "status": found_instance.status,
                "idb_path": found_instance.idb_path,
                "target": str(resolved_target_path) if resolved_target_path else None,
            }, indent=2), flush=True)
        else:
            print(f"IDA Pro ready at http://127.0.0.1:{found_instance.port} (PID: {found_instance.pid})", flush=True)
            if found_instance.idb_path:
                print(f"Database: {found_instance.idb_path}", flush=True)
    else:
        print(f"Warning: IDA Pro started (PID: {proc.pid}), but connector did not register within {timeout}s.", file=sys.stderr, flush=True)
        print("It may still be analyzing or loading plugins. Check `ida-cli instances`.", file=sys.stderr, flush=True)


def cmd_close(args):
    target = getattr(args, "target", None) or getattr(args, "instance", None)
    instance = resolve_instance(target=target)
    if not instance:
        print("Error: No active IDA Pro instance found to close.", file=sys.stderr)
        sys.exit(1)

    pid = instance.pid
    port = instance.port
    force = getattr(args, "force", False)
    save = not getattr(args, "no_save", False)

    def _kill(p):
        if sys.platform == "win32":
            try:
                import ctypes
                k32 = ctypes.windll.kernel32
                h = k32.OpenProcess(0x0001, False, p)
                if h:
                    k32.TerminateProcess(h, 1)
                    k32.CloseHandle(h)
                    return True
            except Exception:
                pass
        try:
            os.kill(p, 9)
            return True
        except Exception:
            return False

    def _clean():
        try:
            if instance.file_path and instance.file_path.exists():
                instance.file_path.unlink()
        except Exception:
            pass

    if force:
        if is_pid_alive(pid):
            _kill(pid)
            _clean()
            if args.json:
                print(json.dumps({"pid": pid, "status": "killed", "force": True}, indent=2))
            else:
                print(f"Force-killed IDA Pro instance (PID: {pid}, port: {port}).")
        else:
            _clean()
            if args.json:
                print(json.dumps({"pid": pid, "status": "not_running"}, indent=2))
            else:
                print(f"Instance PID {pid} was not running.")
        return

    # Try graceful close via RPC
    try:
        client = IdaClient(instance, timeout=5.0)
        res = client.run_command("close_ida", {"save": save, "exit_code": 0})
        saved_str = " (database saved)" if res.get("saved") else " (unsaved)"
        if args.json:
            print(json.dumps({"pid": pid, "port": port, "status": "closed", "saved": res.get("saved")}, indent=2))
        else:
            print(f"Closed IDA Pro instance (PID: {pid}, port: {port}){saved_str}.")
    except Exception as e:
        print(f"Notice: Graceful close command failed ({e}).", file=sys.stderr)
        if is_pid_alive(pid):
            print(f"Terminating PID {pid} directly...", file=sys.stderr)
            _kill(pid)
            _clean()
            if args.json:
                print(json.dumps({"pid": pid, "status": "terminated_fallback"}, indent=2))
            else:
                print(f"Terminated IDA Pro instance (PID: {pid}).")
        else:
            _clean()


def cmd_instances(args):
    instances = list_instances(prune_dead=True)
    if args.json:
        data = [
            {
                "pid": i.pid,
                "port": i.port,
                "status": i.status,
                "idb_path": i.idb_path,
                "input_file": i.input_file,
                "current_ea": i.current_ea,
                "last_heartbeat": i.last_heartbeat,
            }
            for i in instances
        ]
        print(json.dumps(data, indent=2))
    else:
        print(format_instance_table(instances))


def cmd_status(args):
    client = get_client(args.instance)
    status = client.get_status()
    if args.json:
        print(json.dumps(status, indent=2))
    else:
        print(f"Target Instance: http://127.0.0.1:{client.instance.port} (PID: {client.instance.pid})")
        print(f"IDA Version:     {status.get('ida_version')}")
        print(f"IDB Path:        {status.get('idb_path')}")
        print(f"Input Binary:    {status.get('input_file')}")
        print(f"Screen Cursor:   {status.get('current_ea')}")
        print(f"Total Functions: {status.get('total_functions')}")
        print(f"Auto Analysis:   {'Complete' if status.get('auto_analysis_complete') else 'In Progress'}")


def cmd_cursor(args):
    client = get_client(args.instance)
    res = client.run_command("cursor_info")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Cursor EA:       {res.get('ea')}")
        if res.get("func_ea"):
            print(f"Active Function: {res.get('func_name')} @ {res.get('func_ea')}")
        else:
            print(f"Active Function: (none)")
        if res.get("disasm"):
            print(f"Disassembly:     {res.get('disasm')}")


def cmd_segments(args):
    client = get_client(args.instance)
    res = client.run_command("segments_list")
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        if not res:
            print("No segments found.")
            return
        print(f"{'NAME':<14} {'START':<12} {'END':<12} {'SIZE':<10} {'PERM'}")
        print("-" * 55)
        for s in res:
            print(f"{s.get('name'):<14} {s.get('start'):<12} {s.get('end'):<12} {s.get('size'):<10} {s.get('permissions')}")


def cmd_strings(args):
    client = get_client(args.instance)
    params = {
        "filter_str": args.filter or "",
        "limit": args.limit,
        "offset": args.offset,
    }
    res = client.run_command("strings_list", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        strings = res.get("strings", [])
        total = res.get("total", 0)
        print(f"Showing {len(strings)} of {total} strings (offset: {res.get('offset', 0)}):")
        for s in strings:
            print(f"  {s.get('ea')}  [{s.get('length')}B]  {s.get('string')}")


def cmd_classes(args):
    client = get_client(args.instance)
    params = {
        "filter_str": args.filter or "",
        "limit": args.limit,
    }
    res = client.run_command("classes_list", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        classes = res.get("classes", [])
        total = res.get("total", 0)
        print(f"Showing {len(classes)} of {total} C++ classes/namespaces:")
        for c in classes:
            print(f"\n  class {c.get('name')} ({c.get('method_count')} methods):")
            for m in c.get("sample_methods", []):
                print(f"    {m}")


def cmd_xrefs_from(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    params = {
        "target": target,
        "limit": args.limit,
    }
    res = client.run_command("xrefs_from", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        xrefs = res.get("xrefs", [])
        print(f"References from {res.get('target', target)} ({len(xrefs)} found):")
        for x in xrefs:
            print(f"  -> {x.get('to')} ({x.get('name')}) [{x.get('type')}] from {x.get('from')}")


def cmd_exec(args):
    client = get_client(args.instance)
    res = client.exec_code(args.code)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        output = res.get("output", "")
        result = res.get("result")
        if output:
            sys.stdout.write(output)
            if not output.endswith("\n"):
                sys.stdout.write("\n")
        if result is not None and result != "None":
            print(result)


def cmd_list(args):
    client = get_client(args.instance)
    commands = client.get_commands()
    if args.json:
        print(json.dumps(commands, indent=2))
    else:
        print("Available IDA-CLI Commands:")
        for name, meta in sorted(commands.items()):
            desc = meta.get("description", "")
            print(f"  {name:<22} - {desc}")


def cmd_run(args):
    client = get_client(args.instance)

    # --describe: show command metadata without running it
    if getattr(args, "describe", False):
        meta = client.describe_command(args.command)
        if not meta:
            print(f"Command '{args.command}' not found.", file=sys.stderr)
            sys.exit(1)
        if args.json:
            print(json.dumps({args.command: meta}, indent=2))
        else:
            print(f"Command: {args.command}")
            print(f"Description: {meta.get('description', '(none)')}")
        return

    params = {}
    if args.json_params:
        try:
            params = json.loads(args.json_params)
        except Exception as e:
            print(f"Error parsing --json-params: {e}", file=sys.stderr)
            sys.exit(1)
    if args.param:
        cli_params = parse_key_value_params(args.param)
        params.update(cli_params)

    res = client.run_command(args.command, params)
    if args.json or isinstance(res, (dict, list)):
        print(json.dumps(res, indent=2))
    else:
        print(res)


def cmd_decompile(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    params = {
        "addr": target,
        "include_addresses": not args.no_addrs,
    }
    res = client.run_command("decompile", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        code = res.get("code")
        if code:
            print(code)
        else:
            print(json.dumps(res, indent=2))


def cmd_disasm(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    params = {
        "addr": target,
        "max_instructions": args.limit,
        "offset": args.offset,
        "include_total": args.total,
    }
    res = client.run_command("disasm", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        asm = res.get("asm", {})
        lines = asm.get("lines", [])
        name = asm.get("name", target)
        print(f"; Disassembly for {name} ({len(lines)} instructions):")
        for line in lines:
            addr = line.get("addr", "")
            insn = line.get("instruction", "")
            label = line.get("label")
            if label:
                print(f"\n{label}:")
            comments = line.get("comments", [])
            cmt_str = f"  ; {comments[0]}" if comments else ""
            print(f"  {addr}:  {insn:<34}{cmt_str}")


def cmd_xrefs(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    res = client.run_command("xrefs_to", {"addrs": [target], "limit": args.limit})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for entry in res:
            target_addr = entry.get("addr", target)
            xrefs = entry.get("xrefs", [])
            print(f"Cross references to {target_addr} ({len(xrefs)} found):")
            for x in xrefs:
                from_addr = str(x.get("addr", ""))
                addr_disp = from_addr if from_addr.startswith("0x") else f"0x{from_addr}"
                xtype = x.get("type", "")
                fn = x.get("fn") or {}
                fname = fn.get("name") or "<unnamed>"
                print(f"  <- {addr_disp} ({fname}) [{xtype}]")


def cmd_callees(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    res = client.run_command("callees", {"addrs": [target], "limit": args.limit})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for entry in res:
            target_addr = entry.get("addr", target)
            callees = entry.get("callees", [])
            print(f"Functions called by {target_addr} ({len(callees)} found):")
            for c in callees:
                print(f"  -> {c.get('addr')}  {c.get('name')}")


def cmd_lookup(args):
    client = get_client(args.instance)
    res = client.run_command("lookup_funcs", {"queries": [args.query]})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for item in res:
            fn = item.get("fn")
            if fn:
                print(f"  {fn.get('addr')}  [{fn.get('size')}B]  {fn.get('name')}")
            else:
                print(f"  {item.get('query')}: Not found ({item.get('error')})")


def cmd_funcs(args):
    client = get_client(args.instance)
    params = {
        "filter_str": args.filter or "",
        "limit": args.limit,
        "offset": args.offset,
        "compact": not args.full,
    }
    res = client.run_command("funcs_list", params)
    data = res.get("data", res)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        funcs = data.get("functions", [])
        total = data.get("total", 0)
        print(f"Showing {len(funcs)} of {total} functions (offset: {data.get('offset', 0)}):")
        for f in funcs:
            if args.full:
                print(f"  {f['ea']} [{f['size']}B] {f['name']} - {f.get('prototype', '')}")
            else:
                print(f"  {f['ea']}  {f['size']:>6}B  {f['name']}")


def cmd_inspect(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    res = client.run_command("func_inspect", {"target": target})
    data = res.get("data", res)

    if args.json:
        print(json.dumps(data, indent=2))
    else:
        print(f"Function:    {data.get('name')} @ {data.get('ea')}")
        print(f"Size:        {data.get('size')} bytes")
        if data.get("prototype"):
            print(f"Prototype:   {data.get('prototype')}")
        print(f"Callers ({data.get('callers_count')} total):")
        for c in data.get("sample_callers", []):
            print(f"  <- {c}")
        print(f"Callees ({data.get('callees_count')} total):")
        for c in data.get("sample_callees", []):
            print(f"  -> {c}")


def cmd_search(args):
    client = get_client(args.instance)
    include_mode = "all"
    if args.comments_only:
        include_mode = "comments"
    elif args.disasm_only:
        include_mode = "disasm"

    params = {
        "pattern": args.pattern,
        "limit": args.limit,
        "regex": args.regex,
        "case_sensitive": args.case_sensitive,
        "include": include_mode,
        "code_only": not args.all_segments,
    }
    res = client.run_command("search_text", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        hits = res.get("hits", [])
        print(f"Found {res.get('n', len(hits))} matches for '{args.pattern}':")
        for hit in hits:
            fn = f" in {hit['function']}" if hit.get("function") else ""
            print(f"  {hit.get('addr')}{fn}:")
            for match in hit.get("matches", []):
                print(f"    [{match.get('kind')}] {match.get('text')}")


def cmd_bytes(args):
    client = get_client(args.instance)
    addr = resolve_target(client, args.addr, prefer_func=False)
    size = int(args.size, 0)
    res = client.run_command("get_bytes", {"regions": [{"addr": addr, "size": size}]})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        for r in res:
            print(f"{r.get('addr')}: {r.get('data')}")


def cmd_patch(args):
    client = get_client(args.instance)
    addr = resolve_target(client, args.addr, prefer_func=False)
    res = client.run_command("patch", {"patches": [{"addr": addr, "data": args.hex_data}]})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Patched {addr}: {res}")


def cmd_rename(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    batch = [{"kind": args.kind, "addr": target, "new_name": args.new_name}]
    res = client.run_command("rename", {"batch": batch})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        summary = res.get("summary", res)
        print(f"Rename result: {summary}")


def cmd_type(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=True)
    edits = [{"kind": args.kind, "addr": target, "type": args.type_decl}]
    res = client.run_command("set_type", {"edits": edits})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Type applied to {target}: {res}")


def cmd_comment(args):
    client = get_client(args.instance)
    target = resolve_target(client, args.target, prefer_func=False)
    items = [{"addr": target, "comment": args.text}]
    res = client.run_command("set_comments", {"items": items})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Comment set at {target}: {res}")


def cmd_survey(args):
    client = get_client(args.instance)
    res = client.run_command("survey_binary", {"detail_level": args.detail})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        meta = res.get("metadata", {})
        stats = res.get("statistics", {})
        print("=== Binary Survey ===")
        print(f"Module / IDB:    {meta.get('module')} ({meta.get('path')})")
        print(f"Architecture:    {meta.get('arch')}-bit  (Base: {meta.get('base_address')}, Size: {meta.get('image_size')})")
        print(f"Hashes:          MD5: {meta.get('md5')}")
        print(f"Total Functions: {stats.get('total_functions')} ({stats.get('named_functions')} named, {stats.get('library_functions')} lib, {stats.get('unnamed_functions')} unnamed)")
        print(f"Total Strings:   {stats.get('total_strings')}")
        print(f"Total Segments:  {stats.get('total_segments')}")
        segs = res.get("segments", [])
        if segs:
            print("Segments:")
            for s in segs:
                print(f"  {s.get('name', ''):<12} {s.get('start', '')} - {s.get('end', '')} ({s.get('size', '')}) [{s.get('permissions', '')}]")


def cmd_save(args):
    client = get_client(args.instance)
    params = {}
    if args.path:
        params["path"] = args.path
    res = client.run_command("idb_save", params)
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"Database saved: {res.get('path', 'OK')}")


def cmd_py(args):
    client = get_client(args.instance)
    res = client.run_command("py_eval", {"code": args.code})
    if args.json:
        print(json.dumps(res, indent=2))
    else:
        stdout = res.get("stdout", "")
        stderr = res.get("stderr", "")
        result = res.get("result")
        if stdout:
            sys.stdout.write(stdout)
            if not stdout.endswith("\n"):
                sys.stdout.write("\n")
        if stderr:
            print(f"Error: {stderr}", file=sys.stderr)
        if result is not None and result != "None":
            print(result)


def main():
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument(
        "-i", "--instance",
        default=argparse.SUPPRESS,
        help="Target specific IDA instance by port, PID, or IDB name.",
    )
    common_parser.add_argument(
        "--json",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Output raw JSON for automation and AI agents.",
    )

    parser = argparse.ArgumentParser(
        prog="ida-cli",
        description="Fast, zero-config CLI for controlling IDA Pro via instance discovery, MCP bridge, and plugins.",
        parents=[common_parser],
    )

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # instances
    p_inst = subparsers.add_parser("instances", parents=[common_parser], help="List active IDA Pro instances")
    p_inst.set_defaults(func=cmd_instances)

    # status
    p_stat = subparsers.add_parser("status", parents=[common_parser], help="Get active IDA database status")
    p_stat.set_defaults(func=cmd_status)

    # cursor
    p_cur = subparsers.add_parser("cursor", parents=[common_parser], help="Inspect active IDA GUI cursor location and function")
    p_cur.set_defaults(func=cmd_cursor)

    # segments
    p_seg = subparsers.add_parser("segments", parents=[common_parser], help="List memory segments, boundaries, and permissions")
    p_seg.set_defaults(func=cmd_segments)

    # strings
    p_str = subparsers.add_parser("strings", parents=[common_parser], help="List defined strings with filtering")
    p_str.add_argument("-f", "--filter", help="Substring filter")
    p_str.add_argument("-l", "--limit", type=int, default=50, help="Max results (default: 50)")
    p_str.add_argument("-o", "--offset", type=int, default=0, help="Offset")
    p_str.set_defaults(func=cmd_strings)

    # classes
    p_cls = subparsers.add_parser("classes", parents=[common_parser], help="List demangled C++ classes/namespaces")
    p_cls.add_argument("-f", "--filter", help="Class name substring filter")
    p_cls.add_argument("-l", "--limit", type=int, default=50, help="Max classes (default: 50)")
    p_cls.set_defaults(func=cmd_classes)

    # xrefs-from
    p_xfrom = subparsers.add_parser("xrefs-from", parents=[common_parser], help="Get outgoing code/data references from address/func")
    p_xfrom.add_argument("target", nargs="?", default="here", help="Address (0x...) or symbol name (default: cursor)")
    p_xfrom.add_argument("-l", "--limit", type=int, default=50, help="Max refs (default: 50)")
    p_xfrom.set_defaults(func=cmd_xrefs_from)

    # exec
    p_exec = subparsers.add_parser("exec", parents=[common_parser], help="Execute Python code in IDA (raw)")
    p_exec.add_argument("code", help="Python code or expression to evaluate")
    p_exec.set_defaults(func=cmd_exec)

    # list
    p_list = subparsers.add_parser("list", parents=[common_parser], help="List all registered IDA and MCP commands")
    p_list.set_defaults(func=cmd_list)

    # run (Universal MCP runner)
    p_run = subparsers.add_parser("run", parents=[common_parser], help="Universal runner for any IDA-CLI / MCP command")
    p_run.add_argument("command", help="Command name (e.g. decompile, xrefs_to, search_text)")
    p_run.add_argument("-p", "--param", action="append", help="Parameter key=value (repeatable)")
    p_run.add_argument("--json-params", help="JSON string representing parameters dictionary")
    p_run.add_argument("--describe", action="store_true", help="Show command description without running it")
    p_run.set_defaults(func=cmd_run)

    # decompile
    p_dec = subparsers.add_parser("decompile", parents=[common_parser], help="Decompile function to C pseudocode")
    p_dec.add_argument("target", nargs="?", default="here", help="Function address (0x...) or symbol name (default: cursor)")
    p_dec.add_argument("--no-addrs", action="store_true", help="Omit /*0xNNNN*/ address markers to save tokens")
    p_dec.set_defaults(func=cmd_decompile)

    # disasm
    p_dis = subparsers.add_parser("disasm", parents=[common_parser], help="Disassemble function instructions")
    p_dis.add_argument("target", nargs="?", default="here", help="Function address (0x...) or symbol name (default: cursor)")
    p_dis.add_argument("-l", "--limit", type=int, default=50, help="Max instructions (default: 50)")
    p_dis.add_argument("-o", "--offset", type=int, default=0, help="Skip first N instructions")
    p_dis.add_argument("--total", action="store_true", help="Include total instruction count")
    p_dis.set_defaults(func=cmd_disasm)

    # xrefs
    p_xref = subparsers.add_parser("xrefs", parents=[common_parser], help="Get cross references to an address")
    p_xref.add_argument("target", nargs="?", default="here", help="Address (0x...) or symbol name (default: cursor)")
    p_xref.add_argument("-l", "--limit", type=int, default=25, help="Max xrefs (default: 25)")
    p_xref.set_defaults(func=cmd_xrefs)

    # callees
    p_call = subparsers.add_parser("callees", parents=[common_parser], help="Get functions called by target")
    p_call.add_argument("target", nargs="?", default="here", help="Function address (0x...) or symbol name (default: cursor)")
    p_call.add_argument("-l", "--limit", type=int, default=25, help="Max callees (default: 25)")
    p_call.set_defaults(func=cmd_callees)

    # lookup
    p_look = subparsers.add_parser("lookup", parents=[common_parser], help="Look up function by symbol name or address")
    p_look.add_argument("query", help="Symbol name or address substring")
    p_look.set_defaults(func=cmd_lookup)

    # funcs
    p_funcs = subparsers.add_parser("funcs", parents=[common_parser], help="List and search functions with pagination")
    p_funcs.add_argument("--filter", "-f", help="Filter by symbol name or address substring")
    p_funcs.add_argument("--limit", "-l", type=int, default=25, help="Max results (default: 25)")
    p_funcs.add_argument("--offset", "-o", type=int, default=0, help="Pagination offset")
    p_funcs.add_argument("--full", action="store_true", help="Include full prototype details")
    p_funcs.set_defaults(func=cmd_funcs)

    # inspect
    p_inspect = subparsers.add_parser("inspect", parents=[common_parser], help="Inspect a function (summary card)")
    p_inspect.add_argument("target", nargs="?", default="here", help="Function address (e.g. 0x401000) or symbol name (default: cursor)")
    p_inspect.set_defaults(func=cmd_inspect)

    # search
    p_search = subparsers.add_parser("search", parents=[common_parser], help="Search text in disassembly or comments")
    p_search.add_argument("pattern", help="Text or regex to search for")
    p_search.add_argument("-l", "--limit", type=int, default=25, help="Max hits (default: 25)")
    p_search.add_argument("--regex", action="store_true", help="Treat pattern as Python regex")
    p_search.add_argument("-c", "--case-sensitive", action="store_true", help="Case-sensitive match")
    p_search.add_argument("--disasm-only", action="store_true", help="Search only instructions")
    p_search.add_argument("--comments-only", action="store_true", help="Search only comments")
    p_search.add_argument("--all-segments", action="store_true", help="Search all segments, not just code")
    p_search.set_defaults(func=cmd_search)

    # bytes
    p_bytes = subparsers.add_parser("bytes", parents=[common_parser], help="Read memory bytes at address")
    p_bytes.add_argument("addr", nargs="?", default="here", help="Memory address (0x...) (default: cursor)")
    p_bytes.add_argument("size", help="Number of bytes (decimal or 0x...)")
    p_bytes.set_defaults(func=cmd_bytes)

    # patch
    p_patch = subparsers.add_parser("patch", parents=[common_parser], help="Patch bytes at memory address")
    p_patch.add_argument("addr", help="Memory address (0x...)")
    p_patch.add_argument("hex_data", help="Hex bytes (e.g. '90 90' or '9090')")
    p_patch.set_defaults(func=cmd_patch)

    # rename
    p_rename = subparsers.add_parser("rename", parents=[common_parser], help="Rename a function, global, or local variable")
    p_rename.add_argument("target", help="Address (0x...) or current symbol name")
    p_rename.add_argument("new_name", help="New name")
    p_rename.add_argument("--kind", choices=["func", "data", "local"], default="func", help="Entity kind")
    p_rename.set_defaults(func=cmd_rename)

    # type
    p_type = subparsers.add_parser("type", parents=[common_parser], help="Apply C type declaration to function or global")
    p_type.add_argument("target", help="Address (0x...) or symbol name")
    p_type.add_argument("type_decl", help="C type declaration (e.g. 'int __thiscall(void*, int)')")
    p_type.add_argument("--kind", choices=["func", "data"], default="func", help="Entity kind")
    p_type.set_defaults(func=cmd_type)

    # comment
    p_comment = subparsers.add_parser("comment", parents=[common_parser], help="Set comment at address")
    p_comment.add_argument("target", help="Address (0x...) or symbol name")
    p_comment.add_argument("text", help="Comment text")
    p_comment.set_defaults(func=cmd_comment)

    # survey
    p_survey = subparsers.add_parser("survey", parents=[common_parser], help="Get high-level binary survey overview")
    p_survey.add_argument("--detail", choices=["summary", "full"], default="summary", help="Detail level")
    p_survey.set_defaults(func=cmd_survey)

    # save
    p_save = subparsers.add_parser("save", parents=[common_parser], help="Save the active IDB database to disk")
    p_save.add_argument("--path", help="Optional target IDB path")
    p_save.set_defaults(func=cmd_save)

    # py
    p_py = subparsers.add_parser("py", parents=[common_parser], help="Evaluate Python expression in IDA via py_eval")
    p_py.add_argument("code", help="Python code to evaluate")
    p_py.set_defaults(func=cmd_py)

    # struct
    p_struct = subparsers.add_parser("struct", parents=[common_parser], help="Inspect a named struct/class type layout")
    p_struct.add_argument("name", help="Struct/class name (e.g. RGE_Base_Game)")
    p_struct.add_argument("--no-members", action="store_true", help="Omit member list (size and count only)")
    p_struct.add_argument("--max-members", type=int, default=200, dest="max_members", help="Max members to return (default: 200)")
    p_struct.set_defaults(func=cmd_struct)

    # structs
    p_structs = subparsers.add_parser("structs", parents=[common_parser], help="Search IDA local types by name pattern")
    p_structs.add_argument("pattern", nargs="?", default="", help="Name substring to filter (empty = all)")
    p_structs.add_argument("-l", "--limit", type=int, default=50, help="Max results (default: 50)")
    p_structs.set_defaults(func=cmd_structs)

    # locals
    p_locals = subparsers.add_parser("locals", parents=[common_parser], help="List local variables (stack frame) of a function")
    p_locals.add_argument("target", nargs="?", default="here", help="Function address or symbol (default: cursor)")
    p_locals.set_defaults(func=cmd_locals)

    # vtable
    p_vtable = subparsers.add_parser("vtable", parents=[common_parser], help="Dump vtable slots for a C++ class or vtable address")
    p_vtable.add_argument("target", help="Class name (e.g. RGE_Player) or vtable address (0x...)")
    p_vtable.add_argument("-l", "--limit", type=int, default=128, help="Max slots (default: 128)")
    p_vtable.set_defaults(func=cmd_vtable)

    # names
    p_names = subparsers.add_parser("names", parents=[common_parser], help="List all named items in the IDB (globals, labels, imports)")
    p_names.add_argument("-f", "--filter", help="Name substring filter")
    p_names.add_argument("-l", "--limit", type=int, default=100, help="Max results (default: 100)")
    p_names.add_argument("-o", "--offset", type=int, default=0, help="Pagination offset")
    p_names.set_defaults(func=cmd_names)

    # imports
    p_imports = subparsers.add_parser("imports", parents=[common_parser], help="List PE import entries")
    p_imports.add_argument("-f", "--filter", help="Name/DLL substring filter")
    p_imports.add_argument("-l", "--limit", type=int, default=200, help="Max results (default: 200)")
    p_imports.set_defaults(func=cmd_imports)

    # exports
    p_exports = subparsers.add_parser("exports", parents=[common_parser], help="List PE export entries")
    p_exports.add_argument("-f", "--filter", help="Name substring filter")
    p_exports.set_defaults(func=cmd_exports)

    # goto
    p_goto = subparsers.add_parser("goto", parents=[common_parser], help="Jump IDA GUI cursor to address or symbol")
    p_goto.add_argument("target", help="Address (0x...) or symbol name")
    p_goto.set_defaults(func=cmd_goto)

    # open / launch
    for sub_name in ("open", "launch"):
        p_op = subparsers.add_parser(
            sub_name,
            parents=[common_parser],
            help="Launch IDA Pro with an IDB, binary, or project target (e.g. age2_x1)",
        )
        p_op.add_argument("file", nargs="?", default=None, help="Path to .i64, .idb, or binary (or project target name)")
        p_op.add_argument("--ida-path", dest="ida_path", help="Path to IDA executable (overrides auto-detection)")
        p_op.add_argument("--headless", action="store_true", help="Launch in headless / batch mode using idat")
        p_op.add_argument("--detach", action="store_true", help="Spawn and return immediately without waiting for connector")
        p_op.add_argument("--timeout", type=int, default=30, help="Seconds to wait for instance to come online (default: 30)")
        p_op.add_argument("-a", "--arg", action="append", dest="extra_args", help="Additional command line argument to pass to IDA (repeatable)")
        p_op.set_defaults(func=cmd_open)

    # close / quit
    for sub_name in ("close", "quit"):
        p_cl = subparsers.add_parser(
            sub_name,
            parents=[common_parser],
            help="Gracefully save and close an active IDA Pro instance",
        )
        p_cl.add_argument("target", nargs="?", default=None, help="Target instance by port, PID, or IDB name (default: auto-detect)")
        p_cl.add_argument("--no-save", action="store_true", dest="no_save", help="Do not save the IDB before closing")
        p_cl.add_argument("--force", action="store_true", help="Force terminate process immediately via OS kill")
        p_cl.set_defaults(func=cmd_close)

    # Discover and register third-party / project plugins
    register_cli_plugins(subparsers, common_parser)

    args = parser.parse_args()
    if not hasattr(args, "instance"):
        args.instance = None
    if not hasattr(args, "json"):
        args.json = False

    if not hasattr(args, "func"):
        parser.print_help()
        sys.exit(0)

    try:
        args.func(args)
    except IdaClientError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
