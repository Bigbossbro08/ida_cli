"""
IDA-CLI Bridge for ida-pro-mcp Tools
Discovers and loads all @tool functions from ida_pro_mcp.ida_mcp into ida-cli command registry.
"""

from typing import Any, Callable, Dict, Tuple


def load_mcp_commands() -> Dict[str, Tuple[Callable[..., Any], str, bool]]:
    """Discover and register all tools from ida_pro_mcp.ida_mcp.

    Returns:
        A dict mapping tool_name -> (callable, description, needs_sync_wrap)
        needs_sync_wrap is False because ida_mcp tools are decorated with @idasync,
        which internally handles IDA main-thread synchronization via execute_sync.
    """
    mcp_mod = None
    try:
        import ida_pro_mcp.ida_mcp as mcp_mod
    except ImportError:
        try:
            import ida_mcp as mcp_mod
        except ImportError:
            return {}

    if not hasattr(mcp_mod, "MCP_SERVER") or not hasattr(mcp_mod.MCP_SERVER, "tools"):
        return {}

    commands: Dict[str, Tuple[Callable[..., Any], str, bool]] = {}
    for name, func in mcp_mod.MCP_SERVER.tools.methods.items():
        doc = (func.__doc__ or "").strip().split("\n")[0]
        if not doc:
            doc = f"MCP tool: {name}"
        # MCP tools manage their own main-thread synchronization with @idasync
        commands[name] = (func, doc, False)

    return commands
