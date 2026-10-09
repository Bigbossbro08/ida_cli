"""
IDA CLI Plugin
Automatically starts the IDA-CLI HTTP server and registers the instance with ~/.ida-cli/instances/
when an IDB is opened. Cleans up cleanly on database close or IDA termination.
"""

import sys
import os
from pathlib import Path

try:
    import ida_idaapi
    import ida_idp

    try:
        from ida_cli import server as ida_cli_server
    except ImportError:
        # Fallback: add candidate roots to sys.path then retry. Avoids any
        # machine-specific hardcoding; `ida-cli install` also drops a .pth.
        candidates = []
        if os.environ.get("IDA_CLI_ROOT"):
            candidates.append(os.environ["IDA_CLI_ROOT"])
        try:
            candidates.append(str(Path(__file__).resolve().parents[1]))
        except Exception:
            pass
        candidates.append(str(Path.home() / ".ida-cli" / "repo"))
        for root in candidates:
            if root and str(root) not in sys.path:
                sys.path.insert(0, str(root))
        from ida_cli import server as ida_cli_server

    class IdaCliIDBHooks(ida_idp.IDB_Hooks):
        def closebase(self):
            ida_cli_server.unregister_instance_file()

        def savebase(self):
            if ida_cli_server._server_port:
                ida_cli_server.update_instance_heartbeat(ida_cli_server._server_port)

        # The descriptor is first written before the IDB is named. In headless
        # (idat) mode no GUI event loop runs, so the heartbeat timer never
        # fires; these hooks refresh the descriptor once the IDB/input is known.
        def renamed(self, *_args):
            ida_cli_server.refresh_instance_info()

        def updated(self, *_args):
            ida_cli_server.refresh_instance_info()

    class IdaCliPlugin(ida_idaapi.plugin_t):
        flags = ida_idaapi.PLUGIN_KEEP | ida_idaapi.PLUGIN_FIX
        comment = "IDA CLI HTTP connector & instance discovery server"
        help = "Provides CLI control and discovery for IDA Pro"
        wanted_name = "IDA-CLI Connector"
        wanted_hotkey = ""

        def __init__(self):
            super().__init__()
            self.idb_hooks = None

        def init(self):
            try:
                port = ida_cli_server.start_server()
                self.idb_hooks = IdaCliIDBHooks()
                self.idb_hooks.hook()
                print(f"[IDA-CLI] Plugin initialized on port {port}")
                return ida_idaapi.PLUGIN_KEEP
            except Exception as e:
                print(f"[IDA-CLI] Failed to initialize plugin: {e}")
                return ida_idaapi.PLUGIN_SKIP

        def run(self, arg):
            if ida_cli_server._server_port:
                print(f"[IDA-CLI] Server is currently running on port {ida_cli_server._server_port}")
            else:
                port = ida_cli_server.start_server()
                print(f"[IDA-CLI] Started server on port {port}")

        def term(self):
            if self.idb_hooks:
                self.idb_hooks.unhook()
                self.idb_hooks = None
            ida_cli_server.stop_server()

    def PLUGIN_ENTRY():
        return IdaCliPlugin()

except ImportError as e:
    def PLUGIN_ENTRY():
        raise RuntimeError(f"IDA API not available: {e}")
