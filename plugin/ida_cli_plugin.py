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
        # Fallback if ida_cli is not in global sys.path
        repo_path = Path("D:/repos/ida_cli")
        if str(repo_path) not in sys.path:
            sys.path.insert(0, str(repo_path))
        from ida_cli import server as ida_cli_server

    class IdaCliIDBHooks(ida_idp.IDB_Hooks):
        def closebase(self):
            ida_cli_server.unregister_instance_file()

        def savebase(self):
            if ida_cli_server._server_port:
                ida_cli_server.update_instance_heartbeat(ida_cli_server._server_port)

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
