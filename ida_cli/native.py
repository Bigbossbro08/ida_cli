"""Native (ida-pro-mcp independent) fallback handlers for core read commands.

``bridge.load_mcp_commands()`` registers ida-pro-mcp's richer tools into the
same registry and overrides these when ida-pro-mcp is importable. When it is
not, these keep ``ida-cli decompile / disasm / xrefs / callees / lookup /
bytes`` working. Output shapes intentionally mirror ida-pro-mcp's tools so the
CLI formatters in ``cli.py`` behave identically either way.

IDA modules are imported lazily inside handlers so this module stays importable
(and unit-testable) outside IDA.
"""

import re
from typing import Any, Dict, List, Optional

_KNOWN_PREFIXES = ("sub_",)


class NativeToolError(Exception):
    pass


def _mods():
    """Import and return the IDA modules used by the fallbacks."""
    try:
        import idaapi
        import idautils
        import ida_bytes
        import ida_funcs
        import ida_lines
        import ida_name
        import ida_ua
    except ImportError as exc:  # pragma: no cover - only hit outside IDA
        raise NativeToolError(f"IDA modules are not available: {exc}")
    return {
        "idaapi": idaapi,
        "idautils": idautils,
        "ida_bytes": ida_bytes,
        "ida_funcs": ida_funcs,
        "ida_lines": ida_lines,
        "ida_name": ida_name,
        "ida_ua": ida_ua,
    }


def parse_address(addr) -> int:
    if isinstance(addr, int):
        return addr
    text = str(addr).strip()
    try:
        return int(text, 0)
    except ValueError:
        pass
    mods = _mods()
    idaapi = mods["idaapi"]
    ea = idaapi.get_name_ea(idaapi.BADADDR, text)
    if ea != idaapi.BADADDR:
        return ea
    raise NativeToolError(f"Could not resolve address or symbol: {addr!r}")


def _function_dict(ea: int) -> Optional[Dict[str, Any]]:
    mods = _mods()
    idaapi, ida_funcs = mods["idaapi"], mods["ida_funcs"]
    func = ida_funcs.get_func(ea)
    if func is None:
        return None
    name = ida_funcs.get_func_name(func.start_ea) or f"sub_{func.start_ea:X}"
    return {
        "addr": hex(func.start_ea),
        "name": name,
        "size": hex(func.end_ea - func.start_ea),
    }


def _as_list(value) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def _compact_whitespace(text: str) -> str:
    return " ".join((text or "").split())


def _disasm_line(ea: int) -> str:
    """Render a clean disassembly line across IDA versions.

    IDA 9.x moved ``tag_remove``/``generate_disasm_line`` semantics around; use
    ``ida_lines`` (stable) with an ``idc`` fallback.
    """
    try:
        import ida_lines
        line = ida_lines.generate_disasm_line(ea, 0)
        return ida_lines.tag_remove(line) if line else ""
    except Exception:
        pass
    idc = __import__("idc")
    line = None
    if hasattr(idc, "generate_disasm_line"):
        line = idc.generate_disasm_line(ea, 0)
    if line and hasattr(idc, "tag_remove"):
        line = idc.tag_remove(line)
    return line or ""


def _collect_line_comments(ea: int) -> List[str]:
    mods = _mods()
    idc = __import__("idc")
    comments = []
    try:
        regular = idc.get_cmt(ea, False)
        if regular:
            comments.append(regular)
    except Exception:
        pass
    try:
        repeatable = idc.get_cmt(ea, True)
        if repeatable:
            comments.append(repeatable)
    except Exception:
        pass
    return comments


def _next_head(ea: int) -> int:
    idc = __import__("idc")
    return idc.next_head(ea)


# ---------------------------------------------------------------------------
# decompile
# ---------------------------------------------------------------------------

_ADDR_MARKER_RE = re.compile(r"/\*0x[0-9A-Fa-f]+\*/")


def handle_decompile(addr: str, include_addresses: bool = True) -> Dict[str, Any]:
    try:
        start = parse_address(addr)
    except NativeToolError as exc:
        return {"addr": addr, "code": None, "error": str(exc)}
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return {"addr": addr, "code": None, "error": "Hex-Rays decompiler is not available"}
        cfunc = ida_hexrays.decompile(start)
        if cfunc is None:
            return {"addr": addr, "code": None, "error": "Decompilation failed"}
        code = str(cfunc)
        if not include_addresses:
            code = _ADDR_MARKER_RE.sub("", code)
        return {"addr": addr, "code": code}
    except Exception as exc:
        return {"addr": addr, "code": None, "error": str(exc)}


# ---------------------------------------------------------------------------
# disasm
# ---------------------------------------------------------------------------

def handle_disasm(addr: str, max_instructions: int = 5000, offset: int = 0,
                  include_total: bool = False) -> Dict[str, Any]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        return {"addr": addr, "asm": None, "error": str(exc), "cursor": {"done": True}}
    idaapi, idautils, ida_funcs = mods["idaapi"], mods["idautils"], mods["ida_funcs"]
    idc = __import__("idc")

    if max_instructions <= 0 or max_instructions > 50000:
        max_instructions = 50000
    offset = max(0, int(offset))

    try:
        start = parse_address(addr)
    except NativeToolError as exc:
        return {"addr": addr, "asm": None, "error": str(exc), "cursor": {"done": True}}

    func = ida_funcs.get_func(start)
    seg = idaapi.getseg(start)
    segment_name = idaapi.get_segm_name(seg) if seg else "UNKNOWN"

    lines: List[Dict[str, Any]] = []
    seen = 0
    total_count = 0
    more = False

    def _maybe_add(ea: int) -> bool:
        nonlocal seen, total_count, more
        if include_total:
            total_count += 1
        if seen < offset:
            seen += 1
            return True
        if len(lines) < max_instructions:
            instruction = _disasm_line(ea)
            entry: Dict[str, Any] = {"addr": f"{ea:x}", "instruction": _compact_whitespace(instruction)}
            name = idc.get_name(ea)
            if name:
                entry["label"] = name
            comments = _collect_line_comments(ea)
            if comments:
                entry["comments"] = comments
            lines.append(entry)
            seen += 1
            return True
        more = True
        seen += 1
        return include_total

    if func:
        func_name = ida_funcs.get_func_name(func.start_ea) or "<unnamed>"
        for ea in idautils.FuncItems(func.start_ea):
            if ea == idaapi.BADADDR or ea < start:
                continue
            if not _maybe_add(ea):
                break
    else:
        func_name = "<no function>"
        ea = start
        while seg and ea < seg.end_ea:
            if ea == idaapi.BADADDR:
                break
            if not _maybe_add(ea):
                break
            ea = _next_head(ea)
            if ea in (idaapi.BADADDR, 0):
                break

    if include_total and not more:
        more = total_count > offset + max_instructions

    return {
        "addr": addr,
        "asm": {
            "name": func_name,
            "start_ea": hex(start),
            "segment": segment_name,
            "lines": lines,
        },
        "instruction_count": len(lines),
        "total_instructions": total_count if include_total else None,
        "cursor": ({"next": offset + max_instructions} if more else {"done": True}),
    }


# ---------------------------------------------------------------------------
# xrefs_to
# ---------------------------------------------------------------------------

def handle_xrefs_to(addrs, limit: int = 100) -> List[Dict[str, Any]]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        return [{"addr": a, "xrefs": None, "error": str(exc)} for a in (_as_list(addrs) or [addrs])]
    idautils, ida_bytes = mods["idautils"], mods["ida_bytes"]
    idaapi = mods["idaapi"]

    if limit <= 0 or limit > 1000:
        limit = 1000

    results = []
    for addr in _as_list(addrs):
        try:
            ea = parse_address(addr)
        except NativeToolError as exc:
            results.append({"addr": addr, "xrefs": None, "error": str(exc)})
            continue
        if not ida_bytes.is_mapped(ea):
            results.append({"addr": addr, "xrefs": None, "error": f"Address not mapped: {addr}"})
            continue
        xrefs = []
        more = False
        for xref in idautils.XrefsTo(ea):
            if len(xrefs) >= limit:
                more = True
                break
            fn = _function_dict(xref.frm)
            xrefs.append({
                "addr": hex(xref.frm),
                "type": "code" if xref.iscode else "data",
                "fn": fn,
            })
        entry: Dict[str, Any] = {"addr": addr, "xrefs": xrefs, "more": more, "xref_count": len(xrefs)}
        if not xrefs:
            entry["message"] = "No cross-references to this address"
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# callees
# ---------------------------------------------------------------------------

def handle_callees(addrs, limit: int = 200) -> List[Dict[str, Any]]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        return [{"addr": a, "callees": None, "error": str(exc)} for a in (_as_list(addrs) or [addrs])]
    idaapi, idautils, ida_funcs, ida_ua = (
        mods["idaapi"], mods["idautils"], mods["ida_funcs"], mods["ida_ua"]
    )
    idc = __import__("idc")

    if limit <= 0 or limit > 500:
        limit = 500

    call_itypes = {getattr(idaapi, n) for n in ("NN_call", "NN_callfi", "NN_callni") if hasattr(idaapi, n)}

    results = []
    for fn_addr in _as_list(addrs):
        try:
            start = parse_address(fn_addr)
            func = ida_funcs.get_func(start)
            if func is None:
                results.append({"addr": fn_addr, "callees": None, "error": "No function found"})
                continue
            callees: Dict[int, Dict[str, Any]] = {}
            more = False
            for ea in idautils.FuncItems(func.start_ea):
                if len(callees) >= limit:
                    more = True
                    break
                insn = ida_ua.insn_t()
                if ida_ua.decode_insn(insn, ea) == 0:
                    continue
                if insn.itype not in call_itypes:
                    continue
                op0 = insn.ops[0]
                if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
                    target = op0.addr
                elif op0.type == ida_ua.o_imm:
                    target = op0.value
                else:
                    continue
                if target in callees:
                    continue
                name = idc.get_name(target)
                if not name:
                    continue
                callees[target] = {
                    "addr": hex(target),
                    "name": name,
                    "type": "internal" if ida_funcs.get_func(target) is not None else "external",
                }
            results.append({"addr": fn_addr, "callees": list(callees.values()), "more": more})
        except NativeToolError as exc:
            results.append({"addr": fn_addr, "callees": None, "error": str(exc)})
        except Exception as exc:
            results.append({"addr": fn_addr, "callees": None, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# lookup_funcs
# ---------------------------------------------------------------------------

def _parse_func_query(query: str) -> int:
    mods = _mods()
    idaapi = mods["idaapi"]
    text = str(query).strip()
    if text.startswith(("0x", "0X")):
        try:
            return int(text, 16)
        except ValueError:
            return idaapi.BADADDR
    for prefix in _KNOWN_PREFIXES:
        if text.lower().startswith(prefix):
            try:
                return int(text[len(prefix):], 16)
            except ValueError:
                return idaapi.BADADDR
    return idaapi.BADADDR


def handle_lookup_funcs(queries) -> List[Dict[str, Any]]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        items = _as_list(queries) or [queries]
        return [{"query": q, "fn": None, "error": str(exc)} for q in items]
    idaapi, idautils = mods["idaapi"], mods["idautils"]

    query_list = _as_list(queries)
    if not query_list or (len(query_list) == 1 and str(query_list[0]) in ("*", "")):
        all_funcs = []
        for ea in idautils.Functions():
            fn = _function_dict(ea)
            if fn:
                all_funcs.append(fn)
            if len(all_funcs) >= 1000:
                break
        return [{"query": "*", "fn": fn, "error": None} for fn in all_funcs]

    results = []
    for query in query_list:
        try:
            ea = _parse_func_query(query)
            if ea == idaapi.BADADDR:
                ea = idaapi.get_name_ea(idaapi.BADADDR, str(query).strip())
            if ea == idaapi.BADADDR:
                results.append({"query": query, "fn": None, "error": "Not found"})
                continue
            fn = _function_dict(ea)
            if fn:
                results.append({"query": query, "fn": fn, "error": None})
            else:
                results.append({"query": query, "fn": None, "error": "Not a function"})
        except Exception as exc:
            results.append({"query": query, "fn": None, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# get_bytes
# ---------------------------------------------------------------------------

def handle_get_bytes(regions) -> List[Dict[str, Any]]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        if isinstance(regions, dict):
            regions = [regions]
        return [{"addr": (r or {}).get("addr", ""), "data": None, "error": str(exc)} for r in (regions or [{}])]
    ida_bytes = mods["ida_bytes"]

    if isinstance(regions, dict):
        regions = [regions]

    results = []
    for item in (regions or []):
        addr = item.get("addr", "")
        size = item.get("size", 0)
        try:
            ea = parse_address(addr)
            size = int(size)
            out = bytearray(size)
            for i in range(size):
                if ida_bytes.is_loaded(ea + i):
                    out[i] = ida_bytes.get_byte(ea + i)
            data = " ".join(f"{x:#02x}" for x in out)
            results.append({"addr": addr, "data": data})
        except Exception as exc:
            results.append({"addr": addr, "data": None, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# disasm_chunks (tail-chunk aware; not shadowed by ida-pro-mcp)
# ---------------------------------------------------------------------------

def handle_disasm_chunks(addr: str, max_instructions: int = 5000, include_total: bool = False) -> Dict[str, Any]:
    """Disassemble a function across all its chunks, including `.text$x` tails."""
    try:
        mods = _mods()
    except NativeToolError as exc:
        return {"addr": addr, "chunks": [], "chunk_count": 0, "error": str(exc)}
    idautils, ida_funcs = mods["idautils"], mods["ida_funcs"]
    idc = __import__("idc")

    try:
        start = parse_address(addr)
    except NativeToolError as exc:
        return {"addr": addr, "chunks": [], "chunk_count": 0, "error": str(exc)}
    func = ida_funcs.get_func(start)
    if func is None:
        return {"addr": addr, "chunks": [], "chunk_count": 0, "error": "No function found"}

    try:
        ranges = list(idautils.Chunks(func.start_ea))
    except Exception:
        ranges = [(func.start_ea, func.end_ea)]
    if not ranges:
        ranges = [(func.start_ea, func.end_ea)]

    chunks = []
    for index, (chunk_start, chunk_end) in enumerate(ranges):
        lines = []
        for ea in idautils.Heads(chunk_start, chunk_end):
            entry = {"addr": f"{ea:x}", "instruction": _compact_whitespace(_disasm_line(ea))}
            name = idc.get_name(ea)
            if name:
                entry["label"] = name
            comments = _collect_line_comments(ea)
            if comments:
                entry["comments"] = comments
            lines.append(entry)
            if len(lines) >= max_instructions:
                break
        chunks.append({
            "index": index,
            "start_ea": hex(chunk_start),
            "end_ea": hex(chunk_end),
            "kind": "main" if index == 0 else "tail",
            "lines": lines,
        })

    return {
        "addr": addr,
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "chunk_count": len(chunks),
        "chunks": chunks,
    }


# ---------------------------------------------------------------------------
# analyze_function (composite)
# ---------------------------------------------------------------------------

_DECOMPILE_LINE_CAP = 100
_BORING_CONSTANTS = frozenset({0, 1, -1, 0xFF, 0xFFFF, 0xFFFFFFFF})


def _capped_decompile(ea: int):
    try:
        import ida_hexrays
        if not ida_hexrays.init_hexrays_plugin():
            return None, None, "Hex-Rays decompiler is not available"
        cfunc = ida_hexrays.decompile(ea)
        if cfunc is None:
            return None, None, "Decompilation failed"
        code = str(cfunc)
        lines = code.split("\n")
        if len(lines) > _DECOMPILE_LINE_CAP:
            return "\n".join(lines[:_DECOMPILE_LINE_CAP]), len(lines), None
        return code, None, None
    except Exception as exc:
        return None, None, str(exc)


def _function_strings(idautils, idc, func, limit: int = 10) -> List[str]:
    out: List[str] = []
    seen = set()
    for ea in idautils.FuncItems(func.start_ea):
        for ref in idautils.DataRefsFrom(ea):
            try:
                raw = idc.get_strlit_contents(ref, -1, 0)
            except Exception:
                raw = None
            if not raw:
                continue
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else str(raw)
            if text and text not in seen:
                seen.add(text)
                out.append(text)
                if len(out) >= limit:
                    return out
    return out


def _function_constants(idautils, ida_ua, func, limit: int = 10) -> List[Dict[str, Any]]:
    seen = set()
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0:
            continue
        for op in insn.ops:
            if op.type == ida_ua.o_imm:
                value = op.value
                if value not in _BORING_CONSTANTS and abs(value) >= 0x100:
                    seen.add(value)
    top = sorted(seen, key=abs, reverse=True)[:limit]
    return [{"value": value} for value in top]


def _call_itypes(idaapi) -> set:
    return {getattr(idaapi, n) for n in ("NN_call", "NN_callfi", "NN_callni") if hasattr(idaapi, n)}


def _function_callees(idaapi, idautils, ida_ua, ida_funcs, idc, func, limit: int = 25) -> List[str]:
    call_set = _call_itypes(idaapi)
    out, seen = [], set()
    for ea in idautils.FuncItems(func.start_ea):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, ea) == 0 or insn.itype not in call_set:
            continue
        op0 = insn.ops[0]
        if op0.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
            target = op0.addr
        elif op0.type == ida_ua.o_imm:
            target = op0.value
        else:
            continue
        if target in seen:
            continue
        seen.add(target)
        out.append(idc.get_name(target) or hex(target))
        if len(out) >= limit:
            break
    return out


def _function_callers(idaapi, idautils, func, limit: int = 25) -> List[str]:
    out, seen = [], set()
    for xref in idautils.CodeRefsTo(func.start_ea, 0):
        if xref in seen:
            continue
        seen.add(xref)
        caller = idaapi.get_func(xref)
        name = idaapi.get_func_name(caller.start_ea) if caller else None
        out.append(name or hex(xref))
        if len(out) >= limit:
            break
    return out


def _basic_block_stats(idaapi, func) -> Dict[str, int]:
    try:
        chart = idaapi.FlowChart(func)
        nodes = 0
        edges = 0
        for block in chart:
            nodes += 1
            for _ in block.succs():
                edges += 1
        return {"count": nodes, "cyclomatic_complexity": edges - nodes + 2}
    except Exception:
        return {"count": 0, "cyclomatic_complexity": 0}


def _assembly_lines(idc, idautils, func, limit: int = 100) -> str:
    lines = []
    for ea in idautils.FuncItems(func.start_ea):
        lines.append(_disasm_line(ea))
        if len(lines) >= limit:
            break
    return "\n".join(lines)


def handle_analyze_function(addr: str, include_asm: bool = False) -> Dict[str, Any]:
    """Compact single-function analysis: pseudocode, strings, constants, callers/callees, blocks."""
    try:
        mods = _mods()
    except NativeToolError as exc:
        return {"addr": addr, "error": str(exc)}
    idaapi, idautils, ida_funcs, ida_ua = (
        mods["idaapi"], mods["idautils"], mods["ida_funcs"], mods["ida_ua"]
    )
    idc = __import__("idc")

    try:
        ea = parse_address(addr)
    except NativeToolError as exc:
        return {"addr": addr, "error": str(exc)}
    func = ida_funcs.get_func(ea)
    if func is None:
        return {"addr": addr, "error": f"No function at {addr}"}

    code, total_lines, decompile_error = _capped_decompile(func.start_ea)
    result: Dict[str, Any] = {
        "addr": hex(func.start_ea),
        "name": ida_funcs.get_func_name(func.start_ea) or "",
        "prototype": idc.get_type(func.start_ea) or None,
        "size": func.end_ea - func.start_ea,
        "decompiled": code,
        "decompile_error": decompile_error,
        "strings": _function_strings(idautils, idc, func),
        "constants": _function_constants(idautils, ida_ua, func),
        "callees": _function_callees(idaapi, idautils, ida_ua, ida_funcs, idc, func),
        "callers": _function_callers(idaapi, idautils, func),
        "basic_blocks": _basic_block_stats(idaapi, func),
        "error": None,
    }
    if total_lines is not None:
        result["decompile_truncated"] = total_lines
    if include_asm:
        result["assembly"] = _assembly_lines(idc, idautils, func)
    return result


# ---------------------------------------------------------------------------
# insn_query
# ---------------------------------------------------------------------------

def handle_insn_query(queries) -> List[Dict[str, Any]]:
    """Scan instructions by mnemonic/operand regex and/or immediate value."""
    try:
        mods = _mods()
    except NativeToolError as exc:
        return [{"query": q, "matches": [], "error": str(exc)} for q in (_as_list(queries) or [queries])]
    idaapi, idautils, ida_funcs, ida_ua = (
        mods["idaapi"], mods["idautils"], mods["ida_funcs"], mods["ida_ua"]
    )
    idc = __import__("idc")

    results = []
    for query in (_as_list(queries) or []):
        # Accept flat scalar form or ida-pro-mcp's query shape (mnem/op0/op_any...).
        q = query if isinstance(query, dict) else {"mnem": str(query)}
        pattern = q.get("mnem") or q.get("mnemonic") or q.get("pattern") or ""
        operand_pattern = q.get("op_any") or q.get("operand")
        imm = q.get("imm")
        count = int(q.get("count", 200) or 200)
        regex = re.compile(pattern, re.IGNORECASE) if pattern else None
        operand_re = re.compile(operand_pattern, re.IGNORECASE) if operand_pattern else None

        matches = []
        for ea in idautils.Functions():
            func = ida_funcs.get_func(ea)
            for head in idautils.FuncItems(ea):
                line = _disasm_line(head)
                ok = True
                if regex and not regex.search(line):
                    ok = False
                if ok and operand_re and not operand_re.search(line):
                    ok = False
                if ok and imm is not None:
                    insn = ida_ua.insn_t()
                    ok = bool(ida_ua.decode_insn(insn, head)) and any(
                        op.type == ida_ua.o_imm and op.value == imm for op in insn.ops
                    )
                if ok:
                    matches.append({
                        "addr": hex(head),
                        "function": ida_funcs.get_func_name(func.start_ea) if func else None,
                        "instruction": _compact_whitespace(line),
                    })
                    if len(matches) >= count:
                        break
            if len(matches) >= count:
                break
        results.append({"query": q, "matches": matches, "count": len(matches)})
    return results


# ---------------------------------------------------------------------------
# force_recompile
# ---------------------------------------------------------------------------

def handle_force_recompile(items) -> List[Dict[str, Any]]:
    """Invalidate the Hex-Rays decompilation cache for one or more functions."""
    try:
        mods = _mods()
    except NativeToolError as exc:
        return [{"addr": str(i), "ok": False, "error": str(exc)} for i in _as_list(items)]
    try:
        import ida_hexrays
    except Exception as exc:
        return [{"addr": str(i), "ok": False, "error": str(exc)} for i in _as_list(items)]
    ida_funcs = mods["ida_funcs"]

    results = []
    for item in _as_list(items):
        target = (item.get("addr") or item.get("func")) if isinstance(item, dict) else item
        try:
            ea = parse_address(target)
            func = ida_funcs.get_func(ea)
            if func is None:
                results.append({"addr": str(target), "ok": False, "error": "No function found"})
                continue
            ida_hexrays.mark_cfunc_dirty(func.start_ea)
            results.append({"addr": hex(func.start_ea), "ok": True, "error": None})
        except Exception as exc:
            results.append({"addr": str(target), "ok": False, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# type_apply_batch
# ---------------------------------------------------------------------------

def handle_type_apply_batch(batch) -> List[Dict[str, Any]]:
    """Apply multiple C type declarations (idc.set_type) in one call."""
    try:
        _mods()
    except NativeToolError as exc:
        return [{"addr": "", "ok": False, "error": str(exc)}]
    idc = __import__("idc")

    results = []
    for edit in _as_list(batch):
        if isinstance(edit, str):
            edit = {"addr": edit, "type": ""}
        target = edit.get("addr") or edit.get("ea")
        decl = edit.get("type") or edit.get("decl") or ""
        try:
            ea = parse_address(target)
            ok = idc.set_type(ea, decl)
            results.append({"addr": hex(ea), "ok": bool(ok), "error": None if ok else "set_type failed"})
        except Exception as exc:
            results.append({"addr": str(target), "ok": False, "error": str(exc)})
    return results


# ---------------------------------------------------------------------------
# survey_binary
# ---------------------------------------------------------------------------

def handle_survey_binary(detail_level: str = "summary") -> Dict[str, Any]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        return {"error": str(exc)}
    idaapi, idautils = mods["idaapi"], mods["idautils"]
    idc = __import__("idc")

    named = 0
    lib = 0
    func_eas = list(idautils.Functions())
    for ea in func_eas:
        name = idc.get_name(ea) or ""
        if name and not name.startswith(("sub_", "loc_", "nullsub_")):
            named += 1
        if name.startswith("__") or name.endswith("_0") or "rt_" in name:
            lib += 1

    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        perms = ""
        if seg.perm & idaapi.SEGPERM_READ:
            perms += "r"
        if seg.perm & idaapi.SEGPERM_WRITE:
            perms += "w"
        if seg.perm & idaapi.SEGPERM_EXEC:
            perms += "x"
        segments.append({
            "name": idaapi.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.size()),
            "permissions": perms or "-",
        })

    return {
        "metadata": {
            "module": idaapi.get_root_filename(),
            "path": idc.get_idb_path(),
            "arch": 64 if getattr(idaapi, "inf_is_64bit", lambda: False)() else 32,
            "base_address": hex(idaapi.get_imagebase()),
        },
        "statistics": {
            "total_functions": len(func_eas),
            "named_functions": named,
            "library_functions": lib,
            "unnamed_functions": len(func_eas) - named,
            "total_segments": len(segments),
        },
        "segments": segments,
    }


# ---------------------------------------------------------------------------
# search_text
# ---------------------------------------------------------------------------

def handle_search_text(pattern: str, limit: int = 25, start: int = None, end: int = None,
                       regex: bool = False, case_sensitive: bool = False,
                       include: str = "all", code_only: bool = True) -> Dict[str, Any]:
    try:
        mods = _mods()
    except NativeToolError as exc:
        return {"n": 0, "hits": [], "error": str(exc)}
    idaapi, idautils, ida_funcs = mods["idaapi"], mods["idautils"], mods["ida_funcs"]
    idc = __import__("idc")

    import re as _re
    flags = 0 if case_sensitive else _re.IGNORECASE
    matcher = _re.compile(pattern, flags) if regex else None

    def _matches(text: str) -> bool:
        if not text:
            return False
        if matcher:
            return bool(matcher.search(text))
        return pattern in text if case_sensitive else pattern.lower() in text.lower()

    def _bounds():
        if start is not None and end is not None:
            yield (start, end)
            return
        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if not seg:
                continue
            if code_only and not (seg.perm & idaapi.SEGPERM_EXEC):
                continue
            yield (seg.start_ea, seg.end_ea)

    hits = []
    for lo, hi in _bounds():
        ea = lo
        while ea < hi:
            if idc.is_head(idc.get_full_flags(ea)) if hasattr(idc, "is_head") else False:
                line = _disasm_line(ea)
                if line:
                    fn = ida_funcs.get_func(ea)
                    hits.append({
                        "addr": hex(ea),
                        "function": ida_funcs.get_func_name(fn.start_ea) if fn else None,
                        "matches": [{"kind": "disasm", "text": _compact_whitespace(line)}],
                    })
                    if len(hits) >= limit:
                        return {"n": len(hits), "hits": hits}
            ea = idc.next_head(ea) if hasattr(idc, "next_head") else ea + 1
            if ea in (idaapi.BADADDR, 0):
                break
    return {"n": len(hits), "hits": hits}


# ---------------------------------------------------------------------------
# struct_inspect
# ---------------------------------------------------------------------------

def handle_struct_inspect(name: str, include_members: bool = True, max_members: int = 200) -> Dict[str, Any]:
    try:
        import ida_typeinf
    except ImportError as exc:
        return {"error": f"IDA modules are not available: {exc}"}
    tif = ida_typeinf.tinfo_t()
    til = ida_typeinf.get_idati()
    if not tif.get_named_type(til, name):
        return {"error": f"Type '{name}' not found in IDA type system"}
    size = tif.get_size()
    result: Dict[str, Any] = {
        "name": name,
        "size": size,
        "size_hex": f"0x{size:X}",
        "is_union": tif.is_union(),
    }
    if include_members and tif.is_struct():
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            members = []
            for i, member in enumerate(udt):
                if i >= max_members:
                    break
                moff = member.offset // 8
                members.append({
                    "name": member.name,
                    "offset": moff,
                    "offset_hex": f"0x{moff:X}",
                    "size": member.size // 8,
                    "type": str(member.type) if member.type else "",
                })
            result["members"] = members
            result["member_count"] = len(udt)
    return result


# ---------------------------------------------------------------------------
# struct_search
# ---------------------------------------------------------------------------

def handle_struct_search(pattern: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    try:
        import ida_typeinf
    except ImportError as exc:
        return []
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
