"""
IDA-CLI Plugin System
Enables external projects (like rogan2 or custom reversing toolchains)
to register custom CLI subcommands and server-side IDA command handlers.
"""

import importlib.util
import os
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from importlib.metadata import entry_points
except ImportError:
    entry_points = None


def get_plugin_search_paths() -> List[Path]:
    """Returns directory paths where .ida-cli/plugins/ may reside."""
    paths: List[Path] = []

    # 1. Current working directory: ./.ida-cli/plugins
    cwd = Path.cwd().resolve()
    p_cwd = cwd / ".ida-cli" / "plugins"
    if p_cwd.is_dir():
        paths.append(p_cwd)

    # 2. Walk parent directories up to root or .git (to find repo root when in a subdirectory)
    parent = cwd.parent
    while parent != parent.parent:
        p_parent = parent / ".ida-cli" / "plugins"
        if p_parent.is_dir() and p_parent not in paths:
            paths.append(p_parent)
        if (parent / ".git").exists():
            break
        parent = parent.parent

    # 3. User home directory: ~/.ida-cli/plugins
    home_p = Path.home() / ".ida-cli" / "plugins"
    if home_p.is_dir() and home_p not in paths:
        paths.append(home_p)

    return paths


def load_plugin_module(file_path: Path):
    """Dynamically loads a Python file as a module."""
    try:
        module_name = f"ida_cli_plugin_{file_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, str(file_path))
        if spec and spec.loader:
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            return mod
    except Exception as e:
        print(f"[IDA-CLI] Warning: Failed to load plugin {file_path.name}: {e}", file=sys.stderr)
    return None


def register_cli_plugins(subparsers, common_parser):
    """Discovers and invokes register_cli(subparsers, common_parser) on all found plugins."""
    loaded_modules = []

    # 1. File-based plugins from .ida-cli/plugins/
    for search_dir in get_plugin_search_paths():
        for py_file in sorted(search_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            mod = load_plugin_module(py_file)
            if mod:
                loaded_modules.append((py_file.stem, mod))

    # 2. Package entry_points (group="ida_cli.plugins")
    if entry_points:
        try:
            eps = entry_points(group="ida_cli.plugins")
            for ep in eps:
                try:
                    mod = ep.load()
                    loaded_modules.append((ep.name, mod))
                except Exception as e:
                    print(f"[IDA-CLI] Warning: Failed to load entrypoint plugin {ep.name}: {e}", file=sys.stderr)
        except Exception:
            pass

    # Call register_cli on loaded modules
    for name, mod in loaded_modules:
        if hasattr(mod, "register_cli"):
            try:
                mod.register_cli(subparsers, common_parser)
            except Exception as e:
                print(f"[IDA-CLI] Warning: Plugin {name}.register_cli failed: {e}", file=sys.stderr)


def register_server_plugins(command_registry: Dict[str, Any]):
    """Discovers and registers server-side command handlers into command_registry."""
    loaded_modules = []

    for search_dir in get_plugin_search_paths():
        for py_file in sorted(search_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            mod = load_plugin_module(py_file)
            if mod:
                loaded_modules.append((py_file.stem, mod))

    for name, mod in loaded_modules:
        if hasattr(mod, "register_server"):
            try:
                mod.register_server(command_registry)
            except Exception as e:
                print(f"[IDA-CLI] Warning: Plugin {name}.register_server failed: {e}", file=sys.stderr)


def resolve_open_target(target: Optional[str]) -> Optional[str]:
    """Allows loaded plugins to resolve or provide a default target for `ida-cli open`."""
    for search_dir in get_plugin_search_paths():
        for py_file in sorted(search_dir.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            mod = load_plugin_module(py_file)
            if mod and hasattr(mod, "resolve_open_target"):
                try:
                    res = mod.resolve_open_target(target)
                    if res:
                        return res
                except Exception as e:
                    print(f"[IDA-CLI] Warning: Plugin {py_file.stem}.resolve_open_target failed: {e}", file=sys.stderr)
    return target
