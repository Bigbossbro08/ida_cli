"""Full IDAPython execution context for ``ida-cli exec`` / ``exec-file``.

Builds the same broad ``ida_*`` namespace that ida-pro-mcp's ``py_eval`` /
``py_exec_file`` use, so project scripts can run through ida-cli instead of the
manual IDA "File -> Script file..." / MCP ``py_exec_file`` path.

Importable outside IDA: unavailable modules resolve to ``None`` (lazy import),
which keeps the module unit-testable.
"""

import ast
import builtins
import io
import os
import sys
import traceback
from typing import Any, Dict, Optional

# ida-pro-mcp's module set, plus a few extras seen in the wild.
_MODULE_NAMES = [
    "idaapi", "idc", "idautils", "ida_allins", "ida_auto", "ida_bitrange",
    "ida_bytes", "ida_dbg", "ida_dirtree", "ida_diskio", "ida_entry", "ida_enum",
    "ida_expr", "ida_fixup", "ida_fpro", "ida_frame", "ida_funcs", "ida_gdl",
    "ida_graph", "ida_hexrays", "ida_ida", "ida_idd", "ida_idp", "ida_ieee",
    "ida_kernwin", "ida_libfuncs", "ida_lines", "ida_loader", "ida_merge",
    "ida_mergemod", "ida_moves", "ida_nalt", "ida_name", "ida_netnode",
    "ida_offset", "ida_pro", "ida_problems", "ida_range", "ida_regfinder",
    "ida_registry", "ida_search", "ida_segment", "ida_segregs", "ida_srclang",
    "ida_strlist", "ida_struct", "ida_tryblks", "ida_typeinf", "ida_ua",
    "ida_undo", "ida_xref",
]


def _lazy_import(name: str):
    try:
        return __import__(name)
    except Exception:
        try:
            import importlib
            return importlib.import_module(name)
        except Exception:
            return None


def make_exec_globals() -> Dict[str, Any]:
    """Return an execution namespace with all available IDA modules.

    Prefers ida-pro-mcp's implementation when importable (identical semantics),
    otherwise builds an equivalent namespace with lazy imports.
    """
    for mod_name in ("ida_pro_mcp.ida_mcp.api_python", "ida_mcp.api_python"):
        try:
            module = __import__(mod_name, fromlist=["_make_exec_globals"])
            return module._make_exec_globals()
        except Exception:
            continue

    namespace: Dict[str, Any] = {"__builtins__": builtins}
    for name in _MODULE_NAMES:
        namespace[name] = _lazy_import(name)
    return namespace


def run_code(code: str, globals_dict: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Execute ``code`` in an IDAPython context.

    Jupyter-style: a lone trailing expression is evaluated and returned. Returns
    ``{"result", "stdout", "stderr"}``; errors are captured in ``stderr`` as a
    traceback (never raised) so the server can report them cleanly.
    """
    stdout_capture = io.StringIO()
    stderr_capture = io.StringIO()
    old_stdout, old_stderr = sys.stdout, sys.stderr
    result_value: Any = None

    try:
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        namespace = globals_dict if globals_dict is not None else make_exec_globals()

        try:
            tree = ast.parse(code)
        except SyntaxError:
            exec(code, namespace)
            result_value = namespace.get("result")
        else:
            if not tree.body:
                pass
            elif len(tree.body) == 1 and isinstance(tree.body[0], ast.Expr):
                result_value = eval(code, namespace)
            elif isinstance(tree.body[-1], ast.Expr):
                if len(tree.body) > 1:
                    head = ast.Module(body=tree.body[:-1], type_ignores=[])
                    exec(compile(head, "<ida-cli>", "exec"), namespace)
                expr = ast.Expression(body=tree.body[-1].value)
                result_value = eval(compile(expr, "<ida-cli>", "eval"), namespace)
            else:
                exec(code, namespace)
                result_value = namespace.get("result")
    except Exception:
        stderr_capture.write(traceback.format_exc())
        result_value = None
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr

    return {
        "result": "" if result_value is None else str(result_value),
        "stdout": stdout_capture.getvalue(),
        "stderr": stderr_capture.getvalue(),
    }


def run_file(path: str) -> Dict[str, str]:
    """Execute a Python script file in an IDAPython context."""
    if not os.path.isfile(path):
        return {"result": "", "stdout": "", "stderr": f"File not found: {path}"}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            code = handle.read()
    except OSError as exc:
        return {"result": "", "stdout": "", "stderr": f"Could not read {path}: {exc}"}

    namespace = make_exec_globals()
    namespace["__file__"] = path
    namespace["__name__"] = "__main__"
    namespace["__package__"] = None
    result = run_code(code, globals_dict=namespace)
    if not result["result"] and namespace.get("result") is not None:
        result["result"] = str(namespace["result"])
    return result


def has_ida() -> bool:
    return _lazy_import("idaapi") is not None
