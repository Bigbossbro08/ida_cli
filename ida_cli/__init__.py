"""
ida-cli package

A zero-config CLI and in-IDA connector for driving IDA Pro, with a built-in
MCP endpoint, project plugin support, and matcher integration.

Public API::

    from ida_cli import install, uninstall, get_ida_user_plugins_dir

``install``/``uninstall`` are safe to import outside IDA (they only touch the
filesystem). The server and native modules import IDA lazily.
"""

__version__ = "0.1.0"

__all__ = ["__version__", "install", "uninstall", "get_ida_user_plugins_dir"]


def __getattr__(name):
    # Lazy re-export so `import ida_cli` stays cheap and dependency-free.
    if name in ("install", "uninstall", "get_ida_user_plugins_dir"):
        from . import installer
        return getattr(installer, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
