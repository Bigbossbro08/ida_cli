# ida-cli Phase Notes (running log)

Purpose: track cross-phase refinements, caveats, and deferred work so each
phase starts with full context. Update after every phase.

## Ground rules / constraints (apply to every phase)
- **Stdlib only** on the client. No new hard dependencies (`psutil`, `httpx`,
  `semver` are out — use ctypes/env/tuple compares).
- **Never call IDA APIs off the main thread.** A timed-out call must error,
  not fall back to a request-thread call.
- **Preserve response shapes** for existing CLI subcommands unless a phase
  explicitly changes them; agents depend on stable JSON.
- **Live-IDB behaviour cannot be unit-tested here.** Unit-test everything that
  does not import `ida_*`; gate anything else behind `IDA_AVAILABLE` or a lazy
  import inside a try/except.
- **Three transports still coexist** until later phases: ida-cli (28100-28149),
  the matcher's port 28000, and ida-pro-mcp's 13337. Do not add a fourth.
- **Naming collision**: the global `ida-cli` skill refers to a *different*
  project (`--path`, `raw`, `pipe`, `serve-http`). Keep this tool's commands
  distinct and documented.

## Phase 1 — discovery + safety (DONE)
Changes: atomic descriptor writes + heartbeat self-heal; TCP-probe liveness in
`list_instances`; corrupt/dead descriptors pruned; `AmbiguousInstanceError`
instead of silently picking `instances[0]`; `execute_on_main_thread` timeout via
watchdog + `set_cancelled`; removed off-thread fallback; client timeout 120s;
`IDA_CLI_INSTANCES_DIR` override for tests.
Verified: `pytest tests/` 19 passed; five corrupt all-NUL descriptors pruned.

Caveats / refinements deferred:
- **C1.1** Watchdog only frees C-level IDA calls that poll cancellation. A hung
  *pure-Python* handler (e.g. `exec "while True: pass"`) still blocks
  `execute_sync`. Refinement: port `ida_mcp/sync.py`'s `sys.setprofile` deadline.
- **C1.2** TCP-probe failure *skips but keeps* a descriptor (does not delete).
  Good for a busy IDA; means `ida-cli instances` may hide a briefly-unreachable
  instance. Revisit if this confuses users.
- **C1.3** Ambiguity now exits code 2. Scripts that relied on the old
  "most-recent instance" fallback must pass `-i`.
- **C1.4** Timeout default 60s (`IDA_CLI_TOOL_TIMEOUT_SEC`); client 120s
  (`IDA_CLI_HTTP_TIMEOUT_SEC`). Tune per project.

## Phase 2 — output limiter + MCP parity (DONE)
Changes:
- `ida_cli/output.py`: thread-safe LRU `OutputStore` + shape-preserving
  `truncate_value`; env knobs `IDA_CLI_OUTPUT_LIMIT_CHARS` (50k),
  `IDA_CLI_OUTPUT_PREVIEW_STR_LEN` (1000), `IDA_CLI_OUTPUT_PREVIEW_ITEMS` (10),
  `IDA_CLI_OUTPUT_CACHE_SIZE` (100).
- `/command` responses are limited; when truncated the response carries a
  sibling `_output = {truncated, total_chars, output_id, download_url}` while
  `data` keeps its shape with long strings/lists cut down.
- `POST /mcp`: JSON-RPC delegated to `ida_mcp.rpc.MCP_SERVER.registry.dispatch`
  → `initialize`/`ping`/`tools/list` (schemas)/`tools/call`/`resources/list`/
  `resources/templates/list`/`resources/read`/`notifications/*`; allocates/echoes
  `Mcp-Session-Id`. Notifications → HTTP 202 empty body.
- `GET /output/<id>.<ext>`: serves from ida-cli's store **or** ida-pro-mcp's
  tools/call cache; `Content-Disposition: attachment`.
- `start_server` points ida-pro-mcp's download base URL at ida-cli's port.
- Client prints a one-line stderr hint when truncated (suppress with
  `IDA_CLI_QUIET=1`); `last_output_meta` exposed for programmatic callers.
Verified: `pytest tests/` 29 passed (10 new).

Caveats / refinements:
- **C2.1** `/mcp` is JSON-only. Proper SSE / `text/event-stream` streaming and
  the full streamable-HTTP session lifecycle are deferred (Phase 3).
- **C2.2** `/mcp` requires `ida_pro_mcp.ida_mcp` importable inside IDA's Python.
  If absent it returns HTTP 503 + JSON-RPC `-32601`; `/command` still works.
  (Outside IDA this is the tested path.)
- **C2.3** `/mcp` bypasses ida-pro-mcp's Host/Origin/CORS and session checks.
  Safe while bound to `127.0.0.1`; revisit before any remote binding.
- **C2.4** Truncation is shape-preserving but lossy; consumers must follow
  `_output.download_url` to get the full payload. `run_command` surfaces the
  hint but does not auto-fetch.
- **C2.5** ida-pro-mcp stays installed and its own 13337 server is untouched;
  it is not yet a pure proxy to ida-cli.
- **C2.6** `OutputStore` full payloads are in-process and lost on IDA restart;
  the download URL intentionally says "not found or expired" afterwards.
- **C2.7** Bodies must be `Content-Length`-delimited (no chunked transfer);
  fine for MCP HTTP clients, relevant if a proxy switches to chunked.

## Phase 3 — full IDAPython exec + stdio MCP transport (DONE)
Changes:
- `ida_cli/idapython.py`: `make_exec_globals()` (reuses ida-pro-mcp's namespace
  when importable, else a lazy `ida_*` namespace), Jupyter-style `run_code()`
  with stdout/stderr capture and traceback-in-stderr, and `run_file()`.
- `handle_exec` upgraded to the full namespace; new `exec_file` server command
  and `ida-cli exec-file <path>` subcommand (replaces manual
  `File -> Script file...` / MCP `py_exec_file`).
- `ida_cli/mcp_stdio.py`: `run_stdio_proxy()` — newline-delimited JSON-RPC on
  stdin forwarded to `POST /mcp`; handles JSON and `text/event-stream`
  responses, echoes/session-reuses `Mcp-Session-Id`, emits parse-error and
  unreachable errors. stdout carries protocol only.
- `ida-cli serve --stdio [--port]` (subcommand); `GET /mcp` returns 405.
Verified: `pytest tests/` 41 passed (12 new); end-to-end proxy against a real
connector returned the expected JSON-RPC error line (ida_mcp absent outside IDA).

Caveats / refinements:
- **C3.1** stdio proxy is synchronous and single-threaded: one in-flight request
  at a time, forwarded serially. Fine for MCP clients; not for concurrent calls.
- **C3.2** No server-initiated SSE stream (`GET /mcp` = 405). A client that
  *requires* `text/event-stream` for responses is tolerated on POST, but
  unsolicited notifications/progress are not pushed.
- **C3.3** `run_code`/`run_file` still cannot interrupt a hung pure-Python loop
  (see C1.1); the watchdog only frees C-level IDA calls.
- **C3.4** `ida-cli py` still routes through MCP `py_eval` (from the bridge); if
  `ida_mcp` is unavailable it fails, whereas `exec`/`exec-file` work via
  `idapython.py`. Consider unifying `py` onto `idapython.run_code`.
- **C3.5** stdio proxy has no reconnect/retry: if the connector restarts, the
  next request errors. Re-resolve instance on failure would help.

## Phase 4 — perf & safety hardening (DONE)
Changes:
- `ida_cli/deadline.py`: `run_with_deadline()` installs a `sys.setprofile` hook
  that raises `DeadlineExceeded` past a wall-clock deadline (with a 5s grace once
  `set_cancelled` has fired). Wired into `execute_on_main_thread`, mapped to
  `IdaSyncTimeoutError`. Completes C1.1/C3.3.
- `ida_cli/cache.py`: thread-safe `TTLCache` (`IDA_CLI_CACHE_TTL_SEC`, default 60).
- `funcs_list` / `names_list` / `strings_list` / `classes_list` now cache the
  **full unfiltered scan** and filter/paginate in memory (prototype fetch for
  `funcs --full` stays per-page).
- New server commands `cache_invalidate` and `cache_stats`; caches auto-invalidate
  after mutating commands (`rename`, `set_type`, `set_comment(s)`, `patch`,
  `define_*`, `undefine`, `make_data`, `set_op_type`, `force_recompile`,
  `declare_type`, `enum_upsert`, stack ops, `exec`/`exec_file`, `idb_save`).
- `vtable_list` is now MSVC-aware: correct pointer size (`inf_is_64bit`), reports
  the RTTI complete-object-locator pointer preceding the vftable, and `--scan`
  walks past nulls into secondary/base vtables.
Verified: `pytest tests/` 50 passed (9 new); `/commands` exposes the new commands.

Caveats / refinements:
- **C4.1** The profile hook fires on call events; a tight arithmetic loop with no
  calls may still run to completion (best-effort, as in ida-pro-mcp).
- **C4.2** Cache TTL is the only staleness guard for mutations performed outside
  ida-cli (e.g. in the IDA GUI). Use `cache_invalidate` / TTL.
- **C4.3** `vtable --scan` can cross into adjacent vtables; it stops at
  `--limit` and reports null/non-code slots as `fn_ea: None`, `name: "<null>"`.
- **C4.4** `vtable` still assumes contiguous `ptr` slots; MSVC `vtordisp` /
  virtual-base adjustments are not specially decoded.

### Architectural finding (important)
**Most CLI subcommands are provided by the ida-pro-mcp bridge, not by core.**
`decompile`, `disasm`, `xrefs_to`, `callees`, `lookup_funcs`, `get_bytes`,
`set_type`, `set_comments`, `patch`, `rename`, `survey_binary`, `py_eval`, etc.
are registered into `_command_registry` by `bridge.load_mcp_commands()` — they do
NOT exist as ida-cli built-ins. So `ida-cli decompile` fails unless
`ida_pro_mcp.ida_mcp` is importable inside IDA's Python. Core owns only:
status, exec, exec_file, funcs_list, func_inspect, cursor_info, segments_list,
strings_list, classes_list, xrefs_from, struct_inspect, struct_search,
locals_list, vtable_list, names_list, imports_list, exports_list, goto_addr,
close_ida, cache_*.

## Phase 5 — native read-command fallbacks (DONE)
Changes:
- `ida_cli/native.py`: self-sufficient handlers for `decompile`, `disasm`,
  `xrefs_to`, `callees`, `lookup_funcs`, `get_bytes`, mirroring ida-pro-mcp's
  output shapes so `cli.py` formatters work identically.
- Registered as core built-ins **before** `register_mcp_tools()`, so
  ida-pro-mcp's richer tools override them when importable; without it, the
  commands still work. IDA modules are imported lazily; outside IDA every
  handler returns its correct-shaped error result.
- Mitigates the Phase 4 architectural finding: the connector is no longer
  wholly dependent on ida-pro-mcp for core reversing reads.
Verified: `pytest tests/` 57 passed (7 new); `/commands` reports all six
fallbacks present (35 commands with no ida-pro-mcp loaded).

Caveats / refinements:
- **C5.1** Fallbacks are shadowed whenever ida-pro-mcp is importable, so their
  live-IDB paths are only exercised in a no-ida_mcp IDB (offline shapes tested).
- **C5.2** `disasm` fallback omits MCP extras (`stack_frame`, `return_type`,
  `arguments`, per-line `refs`) but matches the `asm.lines` shape the CLI reads.
- **C5.3** `decompile` `include_addresses=False` strips `/*0x…*/` markers with a
  regex rather than Hex-Rays' CLF flags (equivalent for the CLI).
- **C5.4** `callees` fallback skips unnamed external thunks; `lookup_funcs`
  empty/`*` query returns up to 1000 functions.
- **C5.5** `disasm` fallback has no `.text$x` tail-chunk handling yet (still a
  backlog item); a multi-chunk function shows only its main chunk.

## Phase 6 — RE tools + tail-chunk support (DONE)
Changes (all in `ida_cli/native.py` unless noted):
- `disasm_chunks` (new command, NOT shadowed by ida-pro-mcp): disassembles every
  chunk of a function, including distant `.text$x` EH funclets, as
  `{"name","chunk_count","chunks":[{index,start_ea,end_ea,kind,lines}]}`.
- `func_inspect` (core) gained `chunks=True`: reports chunk ranges
  (`{index,start_ea,end_ea,size,kind}`). CLI `inspect --chunks`.
- `analyze_function` composite fallback: capped pseudocode, strings, constants,
  callers/callees, basic-block/complexity stats (mirrors ida-pro-mcp's shape).
  CLI `ida-cli analyze [--asm]`.
- `insn_query` fallback: scan by mnemonic/operand regex and/or immediate.
- `force_recompile` fallback: `ida_hexrays.mark_cfunc_dirty` per function.
- `type_apply_batch` fallback: batch `idc.set_type`.
- CLI `disasm --chunks` routes to `disasm_chunks`.
Verified: `pytest tests/` 62 passed (5 new); `/commands` = 40 with no
ida-pro-mcp (disasm_chunks/analyze_function/insn_query/force_recompile/
type_apply_batch present); new CLI flags/subcommand parse.

Caveats / refinements:
- **C6.1** `analyze_function`, `insn_query`, `force_recompile`,
  `type_apply_batch` are shadowed by ida-pro-mcp when present (native paths only
  used without it), so their live-IDB behaviour is lightly exercised.
- **C6.2** `analyze_function` string extraction uses data-ref string literals
  only; constants skip values < 0x100 and the boring set.
- **C6.3** `type_apply_batch` fallback uses `idc.set_type` (declaration string),
  not ida-pro-mcp's richer type-edit interpreter; complex edits may be rejected.
- **C6.4** `disasm_chunks`/`func_inspect --chunks` rely on `idautils.Chunks`;
  chunk `kind` is a heuristic (index 0 = main; `.text$x` = tail).
- **C6.5** `insn_query` native scans whole functions linearly; no anchored
  range/segment scoping and no per-line refs (unlike ida-pro-mcp's version).

## Phase 7 — matcher migration (DONE, cross-repo)
ida-cli side (`D:\repos\ida_cli\ida_cli\server.py`):
- Added matcher-compatible HTTP routes matching the legacy `:28000` API:
  `GET /func`, `/funcs`, `/data`, `/datas`, `/all_names`, `/baseline`,
  `/refresh`, `/synthetic_obj`. They honour plugin-registered `match_*`
  commands when present, else lazily call `ida_matcher.matcher.ida_logic`
  (which self-synchronizes). Batch routes normalize `{"results": ...}` shapes.
Matcher side (`D:\repos\ida_live_matching_diff`):
- New `ida_matcher/matcher/transport.py`: resolves the endpoint as
  `IDA_MATCHER_URL` → newest live ida-cli instance (`~/.ida-cli/instances`,
  PID + TCP probe) → legacy `:28000`. 5s cache + `base_url(force_refresh=True)`.
- `match_core.py`: removed the `IDA_SERVER_URL` constant and 8 hardcoded
  `127.0.0.1:28000` URLs; all fetches/messages now go through `transport`.
- Versioned the previously untracked user-home plugin into
  `plugins/ida_matcher_plugin.py` + `plugins/README.md`.
Verified: ida-cli `pytest tests/` 69 passed (7 new `test_matcher_routes.py`);
matcher `pytest ida_matcher/matcher/tests` 187 passed (5 new `test_transport.py`);
cross-repo end-to-end — matcher `transport` resolved the ida-cli port,
`server_alive()`, `fetch_from_ida` and `fetch_data_from_ida` all succeeded via
the new routes.

Caveats / refinements:
- **C7.1** The matcher routes need `ida_matcher` importable in IDA's Python (or
  the plugin's `match_*` commands); otherwise `/func` etc. return 404 gracefully.
- **C7.2** `transport` picks the newest live ida-cli instance when several run
  (no ambiguity error, unlike the CLI). Pin with `IDA_MATCHER_URL`.
- **C7.3** Discovery cache TTL is 5s; a connector restart is picked up within it.
- **C7.4** The legacy `ida_server.py` (`:28000`) is retained as a fallback and
  not deleted; the vendored plugin keeps its client monkey-patch (now optional).
- **C7.5** `/baseline` is served raw (no output limiter), matching legacy.

## Phase 8 — protocol cleanup (DONE)
Changes:
- `ida-cli doctor` — prints version, package path, python, availability of
  `ida_pro_mcp`/`ida_matcher`, instances dir + live instances, and env knobs.
- `ida-cli mcp-config [--mode stdio|proxy]` — emits an MCP client config.
  `stdio` = native `ida-cli serve --stdio`; `proxy` = runs
  `python -m ida_pro_mcp.server --ida-rpc http://127.0.0.1:<port>` so
  ida-pro-mcp's proven stdio transport forwards JSON-RPC to ida-cli's `/mcp`
  (docs the thin-proxy migration path, C2.5).
- Name-collision guard: `main()` rejects foreign flags (`--path`, `--compact`,
  `--streamable-http`) with a clear error + exit 2 (these belong to
  cpkt9762/ida-cli). README documents the distinction.
- Matcher `ida_server.py` marked DEPRECATED (docstring + startup notice); the
  file is retained as the documented fallback (C7.4).
Verified: ida-cli `pytest tests/` 74 passed (5 new `test_protocol_cleanup.py`);
`ida-cli doctor` and `mcp-config --json` produce the expected output; the
collision guard exits 2 for `--path`.

Caveats / refinements:
- **C8.1** The guard only catches flags that are used somewhere before
  argparse; a foreign flag used as a positional value is not intercepted.
- **C8.2** `mcp-config --mode proxy` needs ida-pro-mcp installed on PATH/env;
  it emits the command but does not verify it.
- **C8.3** The matcher's legacy `:28000` `ida_server.py` is deprecated but not
  deleted; removal is a follow-up once ida-cli serving is proven in daily use.
- **C8.4** ida-pro-mcp is not literally rewritten to a proxy; the migration is
  expressed as the `proxy` mcp-config mode (upstream owns the ida-pro-mcp code).

## Phase 9 — packaging + extra fallbacks (DONE)
Changes:
- `ida_cli/installer.py` (new): `install()`/`uninstall()` copy
  `plugin/ida_cli_plugin.py` + `plugin/ida_cli_server.py` into IDA's user
  plugins dir (`%APPDATA%\Hex-Rays\IDA Pro\plugins`, override
  `IDA_CLI_IDA_PLUGINS_DIR`) and write an `ida_cli_path.pth` pointing at the
  repo root so `ida_cli` is importable inside IDA.
- CLI: `ida-cli install`, `ida-cli uninstall`, `ida-cli install-paths`
  (all `--json`-capable, `--ida-plugins-dir` override).
- `plugin/ida_cli_plugin.py`: removed the hardcoded `D:/repos/ida_cli` fallback;
  now tries `IDA_CLI_ROOT` → plugin's own repo root → `~/.ida-cli/repo`.
- Extra native fallbacks (`native.py`): `survey_binary`, `search_text`,
  `struct_inspect`, `struct_search` — shadowed by ida-pro-mcp when present.
- README: install section + new subcommand rows.
Verified: `pytest tests/` 81 passed (7 new); `ida-cli install-paths --json`
resolves correctly; registry has 42 entries pre-bridge.

Caveats / refinements:
- **C9.1** Installer copies files; it does not detect an existing IDA install
  (IDA plugins are user-level, so this is intentional and portable).
- **C9.2** No hot-reload: IDA must be restarted (or the plugin reloaded) after
  install.
- **C9.3** `.pth` points at the repo root (editable/dev). A wheel install would
  instead rely on the package being importable in IDA's Python.
- **C9.4** Native `search_text`/`survey_binary`/`struct_*` are simplified vs
  ida-pro-mcp (linear scan; no refs/templates); shapes approximate, not exact.
- **C9.5** The plugin still registers only a subset of handlers when running
  without the `ida_cli` package (the vendored `plugin/ida_cli_server.py` is the
  lean fallback; the full server is `ida_cli/server.py`).

## Phase 10 — packaging & robustness (DONE)
Changes:
- `ida_cli/__init__.py`: lazy public API (`install`, `uninstall`,
  `get_ida_user_plugins_dir`) via module `__getattr__`; `import ida_cli` stays
  cheap and dependency-free (safe to import outside IDA).
- Matcher `fetch_many_data_from_ida` now chunks the ``/datas`` URL (4000 chars)
  and retries stragglers per-name, matching ``/funcs`` — fixes the unguarded
  long-URL path (C7 batch).
- Matcher `transport.base_url` warns once on stderr when it falls back to the
  legacy ``:28000`` (no live ida-cli discovered), so a silent dead fallback is
  visible.
Tests:
- ida-cli `tests/test_package_api.py` (public API + `--help` coverage of every
  phase command). Matcher `test_transport.py` gained a fallback-warning test and
  a `/datas` chunking test.
Verified: ida-cli `pytest tests/` 85 passed; matcher
`pytest ida_matcher/matcher/tests` 189 passed.

Caveats / refinements:
- **C10.1** `.pth` remains dev-oriented (points at repo root); a true wheel would
  vendor `ida_cli` into IDA's Python. Not shipped here.
- **C10.2** The legacy matcher `ida_server.py` + plugin monkey-patch are still
  present (documented fallback, C8.3); removal is deferred.
- **C10.3** Native fallback shapes remain approximate (C9.4); exact parity with
  ida-pro-mcp output is not attempted.
- **C10.4** The fallback warning fires only when discovery fails; it is not
  emitted when `IDA_MATCHER_URL` is explicitly set.

## Summary — phases 1-10 complete
ida-cli: durable/atomic discovery + ambiguity errors; timeout + hard-deadline
cancellation; output limiter + `/output` downloads; MCP endpoint + stdio bridge;
full IDAPython exec + `exec-file`; native fallbacks for decompile/disasm/xrefs/
callees/lookup/bytes/survey/search/structs; RE tools (analyze_function,
insn_query, force_recompile, type_apply_batch, disasm_chunks, MSVC vtable);
inventory TTL caches; installer for IDA; doctor/mcp-config. Matcher: discovery-
based transport (no hardcoded 28000), versioned plugin, chunked batch fetches.

## Live test session — IDA Pro 9.1 (J:\Software\IDA Professional 9.1)

Setup:
- IDA 9.1 x64, IDAPython bound to **E:\Software\Python313** (confirmed via
  `idapyswitch --dry-run`). `ida_cli` + `ida_matcher` are **editable** installs
  from `D:\repos\ida_cli` / `D:\repos\ida_live_matching_diff`, so all phase
  changes are live inside IDA (verified `ida_cli.server.__file__`).
- Test database: `E:\Games\Age of Empires II\age2_x1_ida\age2_x1.exe.i64`
  (66 MB, 7,406 functions). Launch: `idat.exe -A "<idb>"`.
- The plugin was synced to `J:\...\plugins\ida_cli_plugin.py`; a stale 0-byte
  `%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp.py` was renamed to
  `ida_mcp.py.corrupt-bak` so ida-pro-mcp does not half-load.
- Post-plugin-load warnings seen in `ida_gui.log` are ida-pro-mcp's own and do
  not affect ida-cli.

### Bugs found and fixed during live testing
1. **Off-thread IDA path APIs return empty.** The headless descriptor-refresh
   thread called `ida_loader.get_path`/`ida_nalt.get_input_file_path` directly;
   these are main-thread-only and silently returned `""`, so headless
   descriptors stayed `nodb` with `ea=0x0`. Fixed: `refresh_instance_info()`
   now gathers fields via `execute_on_main_thread(_collect_instance_fields)`.
   Also added `_start_descriptor_refresh_thread` (bounded, headless-safe) since
   the GUI heartbeat timer never fires under `idat`.
2. **`idc.tag_remove` does not exist in IDA 9.x** (`AttributeError`). Added
   `native._disasm_line()` using `ida_lines` with an `idc` fallback; routed all
   native disassembly renderers through it.
3. **`insn_query` param mismatch.** The native fallback read `mnemonic`/`operand`;
   ida-pro-mcp's schema uses `mnem`/`op_any`. Now accepts both.
4. **Bogus RTTI COL.** `vtable` reported the raw word before a vftable as the
   RTTI locator even when it was padding (e.g. `0x80000000`). Now only reported
   when the pointer is loaded and not code.
5. **`instances` showed "Untitled"/`nodb`.** `idb_name` now falls back to the
   descriptor slug when `idb_path`/`input_file` are empty (headless window).

### Verified working against the live IDB
- Discovery/status: `instances`, `status` (correct IDB path, 7,406 funcs, EA).
- `inspect --chunks` on `??0RGE_Scenario@@...` → 2 chunks (main 0x531750 +
  `.text$x` tail 0x625240). `disasm --chunks` renders both.
- `decompile` (native fallback) of the ctor; `analyze` (blocks/callers/callees/
  pseudocode); `vtable` (MSVC, COL); `struct RGE_Scenario` (0x19FC, 42 members);
  `survey --detail full`; `segments`/`strings`/`classes`/`xrefs`/`callees`/
  `lookup`/`names`/`imports`/`locals`; `exec-file` ran a real script (7406).
- **Matcher via ida-cli (Phase 7 payoff):** `ida-match vector.obj` with no
  `IDA_MATCHER_URL` — `transport.base_url()` resolved to
  `http://127.0.0.1:28100`, `server_alive()==True`, and it scored real
  `BVector` symbols (93.90%, `_$E2` 100%). `point.obj` → `connected: true`.

### Environment notes for future agents
- Launch command for headless testing:
  `Start-Process "J:\Software\IDA Professional 9.1\idat.exe" -ArgumentList @('-A','"<path>.i64"')`
  (quote the `.i64`; an unquoted path silently opens a **new empty** DB).
- The descriptor becomes meaningful within ~8s of the IDB finishing load.
- Kill with `Get-Process idat | Stop-Process -Force`; stale descriptors are
  pruned automatically by `list_instances`.

### Remaining known limitations (consolidated)
- Hang-in-pure-Python: hard deadline is best-effort (C1.1/C3.3/C4.1).
- `/mcp` is JSON-only; no server-initiated SSE stream (C2.1/C3.2).
- Ambiguity errors and output-download URLs are the main behavioural changes
  consumers must handle (C1.3/C2.4).
- Fallbacks are shadowed when ida-pro-mcp is present; their live paths are
  lightly exercised (C5.1/C6.1).
- Legacy matcher `:28000` server/monkey-patch still present (C8.3/C10.2).
- Global `ida-cli` skill-name collision is mitigated, not removed (Phase 8).

## Phase 11 — independent audit (Claude via WebRelay) + follow-ups (DONE)

Repo audit snapshot (all uncommitted):
- `ida_cli` (main, e157352): 7 modified, 7 new modules, 10 test files, 85 tests.
- `ida_live_matching_diff` (master, 4c85c90): 3 modified, `transport.py`,
  `test_transport.py`, `plugins/`, 191 tests.
- `rogan2`: untouched consumer / test corpus.
Checks run: residual-hardcoded-path scan (only intentional legacy `:28000`
fallbacks + one back-compat test), bare-`except:` scan (none in ida_cli), full
test suites green.

Independent review: `docs/PHASE_NOTES.md` (this file) was sent to Claude via
WebRelay (`--claude --new --topic idacli-audit`) with a request to attack the
design. Its report mixed valid findings with claims that were **already
addressed or inapplicable on Windows**. Assessment, with verification:

Confirmed-and-fixed (this phase):
- **Fallback activation warning** (Claude Rec 3): `register_mcp_tools()` now
  returns whether MCP tools loaded; the server prints an explicit warning when
  the approximate native fallbacks are what callers will hit. Registry without
  ida-pro-mcp = 42 commands (verified by import simulation).
- **Matcher ambiguity guard** (Claude Rec 2 / Risk B): `transport` now
  enumerates all live instances; default = newest + one-time warning, and
  `IDA_MATCHER_AMBIGUITY_ERROR=1` raises `AmbiguousInstanceError`. New tests.
- **`/baseline` size guard** (Claude Rec 6): logs a warning for >10 MB payloads.
- **`export_baseline` still hardcoded `:28000`** (found in this audit, not by
  Claude): now resolves via `transport`; explicit `--host/--port` still honoured.

Rejected — factually wrong or inapplicable:
- Bug 1 "descriptor corruption window / no atomicity": **false**; writes go
  through `_atomic_write_json` (temp file + `os.replace`, server.py:73-84).
  Concurrent writers are safe by construction.
- Bug 2 "OutputStore missing synchronization": **false**; guarded by
  `threading.Lock` (output.py:69/75/82).
- Rec 4 "`fcntl.flock`": **inapplicable** — `fcntl` is Unix-only; the target is
  Windows and atomic replace already covers it.
- Rec 5 "`signal.SIGALRM` timeout": **inapplicable** — `SIGALRM` does not exist
  on Windows (verified). The existing `sys.setprofile` deadline + watchdog is the
  correct mechanism; the pure-Python-loop limitation stands (C4.1) and is
  documented, not silently ignored.
- "Bug 5 no round-trip test / Bug 4 matcher race" — the former is now covered by
  the ambiguity tests plus the already-live-verified fallbacks; the latter is the
  same multi-instance concern addressed by the new guard.

Accepted, still open (documented, not blocking):
- **CV4 / Gap 1**: native fallbacks' live paths are only exercised when
  ida-pro-mcp is absent; a dedicated live test with ida-pro-mcp forcibly hidden
  is not yet added (now partially mitigated by the explicit warning).
- **CV3**: `.pth` install is dev-oriented; a true wheel that vendors `ida_cli`
  into IDA's Python is not shipped (C9.3/C10.1).
- **CV1**: off-thread IDA-call audit — the one offending path (descriptor
  refresh) was fixed; no lint rule enforces this class of bug.
- **Multi-IDB CI correctness**: default remains "newest wins" (now with a
  warning + opt-in strict mode), matching the recommended default.

Net effect: 4 real improvements landed (3 from the audit, 1 found while
verifying), 4 spurious/inapplicable recommendations documented as rejected, and
2 accepted gaps recorded. Suites: ida-cli 85, matcher 191.
