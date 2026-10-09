# ida-cli

Fast, lightweight CLI for controlling IDA Pro directly from the terminal or AI agents.

Modeled after **`unity-cli`**:
- **Zero-config auto-discovery**: Automatically detects open IDA Pro instances and routes commands to the right database via `~/.ida-cli/instances/*.json`.
- **Active Cursor Navigation (`here` / `.`)**: Target arguments default to the current IDA GUI cursor (`here`), eliminating manual address copying.
- **Full ida-pro-mcp & Ghidra parity**: Seamlessly bridges all 97+ commands including decompilation, inspection, cross-references, segments, classes, and strings.
- **Extensible Plugin System**: Projects can add their own workflow commands without modifying `ida-cli` core.
- **Token-conscious**: Paged queries, compact output modes, server-side filtering, and token-saving flags (`--no-addrs`, `--limit`) designed to minimize LLM token overhead.
- **Cross-platform**: Pure standard library HTTP transport without POSIX-only forks or Unix domain socket dependencies.

## Architecture

```
Terminal / Agent CLI                     IDA Pro (GUI / idat)
────────────────────                     ────────────────────
$ ida-cli decompile here
     │
     ├─ Scans ~/.ida-cli/instances/*.json
     │  (Auto-matches active IDB by CWD, PID, or port)
     │
     ├─ Resolves 'here' -> Active GUI screen EA (e.g. 0x401000)
     │
     ├─ Sends HTTP POST to http://127.0.0.1:<port>/command
     │  Payload: { "command": "decompile", "params": { "addr": "0x401000" } }
     │                                    │
     │                               ida_cli.server (bridge)
     │                                    │
     │                               ida_mcp tool handler (@idasync)
     │                                    │
     ├─ Receives JSON response  ←─────────┘
     │
     └─ Formats clean C pseudocode / JSON output
```

## Install the IDA-side connector

```powershell
pip install -e .
ida-cli install          # copies the plugin into IDA's user plugins dir
ida-cli doctor           # verify: check for "instances" after restarting IDA
```

`ida-cli install` copies `plugin/ida_cli_plugin.py` + `plugin/ida_cli_server.py`
into `%APPDATA%\Hex-Rays\IDA Pro\plugins` and writes an `ida_cli_path.pth` so
the `ida_cli` package is importable from inside IDA. Restart IDA afterward.

## Quick Start

```powershell
# Check status of active IDA database
ida-cli status

# Inspect active IDA GUI cursor location & current function
ida-cli cursor

# Decompile the function currently under the cursor (omit address or use 'here')
ida-cli decompile --no-addrs

# Inspect summary card (size, prototype, callers, callees) for cursor function
ida-cli inspect

# Disassemble 20 instructions around cursor
ida-cli disasm --limit 20

# List memory segments and permissions
ida-cli segments

# Search defined strings
ida-cli strings -f "Game" --limit 10

# List demangled C++ classes and member functions
ida-cli classes -f "CMemory"

# Incoming and outgoing cross-references
ida-cli xrefs 0x401070
ida-cli xrefs-from 0x401070

# Search disassembly text or comments
ida-cli search "operator new" --limit 10

# Read memory bytes
ida-cli bytes 0x401000 16

# Execute Python inside IDA
ida-cli py "ida_kernwin.get_screen_ea()"

# Machine-readable output for scripts and AI agents
ida-cli decompile 0x401000 --json
```

## Available Subcommands

| Subcommand | Description |
|---|---|
| `instances` | List active IDA Pro instances and ports |
| `status` | Get active database metadata and IDA status |
| `cursor` | Inspect active IDA GUI cursor location, function, and disassembly line |
| `segments` | List memory segments, boundaries, and permissions (`rx`, `rw`, `r`) |
| `strings` | List defined strings with filtering and pagination (`-f`, `-l`, `-o`) |
| `classes` | List demangled C++ classes/namespaces with method counts and signatures |
| `xrefs-from` | Get outgoing code and data references from an address or function |
| `exec` | Execute arbitrary multi-line Python code in IDA (raw) |
| `list` | List all 97+ registered IDA-CLI and MCP commands |
| `run` | Universal runner for any command with `-p` or `--json-params` |
| `decompile` | Decompile function to C pseudocode (`--no-addrs` for token savings; defaults to `here`) |
| `disasm` | Disassemble function instructions with pagination (defaults to `here`) |
| `xrefs` | Get incoming cross-references to an address/symbol (defaults to `here`) |
| `callees` | Get functions called by target (defaults to `here`) |
| `lookup` | Look up functions by name pattern or address |
| `funcs` | List and search functions with pagination and filtering |
| `inspect` | High-density function inspection summary card (defaults to `here`; `--chunks` for `.text$x` tails) |
| `analyze` | Composite function analysis: pseudocode, strings, constants, callers/callees, blocks |
| `search` | Search text/regex in disassembly or comments |
| `bytes` | Read raw bytes from memory (defaults to `here`) |
| `patch` | Patch memory bytes at address |
| `rename` | Rename a function, global, or local variable |
| `type` | Apply C type declaration to function or global |
| `comment` | Set comment at address or function |
| `survey` | High-level binary survey overview |
| `save` | Save active IDB database |
| `py` | Evaluate Python expression via `py_eval` |
| `exec-file` | Execute a Python script file inside IDA (full IDAPython namespace) |
| `serve` | Run an MCP transport bridge to IDA (`--stdio` for Claude Desktop/Cursor) |
| `doctor` | Diagnose environment, dependencies, and live instances |
| `mcp-config` | Emit an MCP client config (`--mode stdio` native, or `--mode proxy`) |
| `install` | Install the connector plugin into IDA Pro's plugins directory |
| `uninstall` | Remove the connector plugin from IDA Pro |
| `install-paths` | Show resolved plugin install paths |

## Plugin Architecture

`ida-cli` core remains strictly project-agnostic. Projects (like reverse-engineering or decompilation codebases) can supply custom subcommands and server handlers via plugins.

### Plugin Discovery Locations
Plugins are discovered from:
1. `.ida-cli/plugins/*.py` in the current working directory or any parent directory up to repository root.
2. `~/.ida-cli/plugins/*.py` (user-wide plugins).
3. Python `entry_points` registered under the `ida_cli.plugins` group.

### Writing a Project Plugin

Create a file in your project: `.ida-cli/plugins/my_plugin.py`:

```python
"""Example project plugin for ida-cli."""

def register_cli(subparsers, common_parser):
    """Called by ida-cli to register client-side subcommands."""
    p = subparsers.add_parser("my-cmd", parents=[common_parser], help="Custom project action")
    p.add_argument("target", nargs="?", default="here")
    p.set_defaults(func=cmd_my_action)

def cmd_my_action(args):
    from ida_cli.cli import get_client, resolve_target
    client = get_client(args.instance)
    ea = resolve_target(client, args.target)
    print(f"Executing custom project logic on {ea}...")

def register_server(command_registry):
    """Optional: Called inside IDA Pro to register custom server-side RPC handlers."""
    pass
```

### Real-World Example: `rogan2` Plugin

The `rogan2` decompilation project uses `.ida-cli/plugins/rogan2_plugin.py` to add `ida-cli hook-decl`:
```powershell
# In the rogan2 directory:
$ ida-cli hook-decl here
// HOOK: addr=0x00401000 tramp=5 disabled=false sym=?initialize@CMemoryBlock@@QAE_NKK@Z trampoline=?initialize@CMemoryBlock@@QAE_NKK@Z_tramp thiscall=true
```

## Universal MCP Command Runner

Any of the 97+ tools from `ida-pro-mcp` can also be invoked directly through the universal `run` command:

```powershell
# List all registered commands (built-ins + MCP tools)
ida-cli list

# Run any command with parameter key-value pairs
ida-cli run int_convert -p inputs=0x401000
ida-cli run basic_blocks -p addrs=0x401000 -p max_blocks=10

# Or pass complex parameters as raw JSON
ida-cli run rename --json-params '{"batch": [{"kind": "func", "addr": "0x401000", "new_name": "MyFunc"}]}'
```

## MCP Endpoint

The connector also exposes a JSON-RPC MCP endpoint so MCP clients can use ida-cli
directly (full tool schemas, resources, and cancellation were added in Phase 2):

```powershell
# stdio bridge for Claude Desktop / Cursor (add as an MCP server command)
ida-cli serve --stdio
```

- `POST /mcp` — JSON-RPC MCP (`initialize`, `tools/list`, `tools/call`,
  `resources/list|templates|read`, `notifications/*`). Replies carry an
  `Mcp-Session-Id` header.
- `GET /output/<id>.<ext>` — downloads the full payload when a response was
  size-limited (the CLI prints a hint with this URL).
- Matcher-compatible routes (same API as the legacy `:28000` matcher server):
  `GET /func`, `/funcs`, `/data`, `/datas`, `/all_names`, `/baseline`,
  `/refresh`, `/synthetic_obj`. The matcher resolves this connector
  automatically (`IDA_MATCHER_URL` to pin an instance).

### Note on the name

There is an unrelated project also called `ida-cli` (cpkt9762/ida-cli) that
uses `--path` / `raw` / `pipe` / `serve-http`. This tool is the rogan2/ida_cli
connector and rejects those flags with a clear error.

Large responses are truncated shape-preservingly (default >50,000 chars; tune
with `IDA_CLI_OUTPUT_LIMIT_CHARS`). Set `IDA_CLI_QUIET=1` to silence the hint.
`exec-file` runs project IDAPython scripts with the full `ida_*` namespace.
