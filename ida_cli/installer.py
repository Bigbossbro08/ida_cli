"""Install / uninstall the ida-cli connector plugin into IDA Pro.

Copies ``plugin/ida_cli_plugin.py`` and ``plugin/ida_cli_server.py`` into IDA's
user ``plugins`` directory (``%APPDATA%\\Hex-Rays\\IDA Pro\\plugins`` on Windows,
``~/.idapro/plugins`` elsewhere) and ensures the ``ida_cli`` package is
importable from inside IDA's Python.

Dependency-free (stdlib only) so it works without installing anything first.
"""

import os
import shutil
import sys
from pathlib import Path

PLUGIN_FILES = ("ida_cli_plugin.py", "ida_cli_server.py")
_PLUGIN_DIR_MARKER = "# ida-cli plugin installer"


def _repo_root() -> Path:
    # ida_cli/installer.py -> repo root is two levels up.
    return Path(__file__).resolve().parents[1]


def get_ida_user_plugins_dir() -> Path:
    override = os.environ.get("IDA_CLI_IDA_PLUGINS_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else (Path.home() / "AppData" / "Roaming")
        return base / "Hex-Rays" / "IDA Pro" / "plugins"
    return Path.home() / ".idapro" / "plugins"


def _write_pth(pth_path: Path, repo_root: Path) -> Path:
    pth_path.parent.mkdir(parents=True, exist_ok=True)
    pth_path.write_text(f"{_PLUGIN_DIR_MARKER}\n{repo_root}\n", encoding="utf-8")
    return pth_path


def install(ida_plugins_dir: Path = None) -> dict:
    """Install the connector plugin. Returns a report dict."""
    if ida_plugins_dir is None:
        ida_plugins_dir = get_ida_user_plugins_dir()
    ida_plugins_dir = Path(ida_plugins_dir)
    ida_plugins_dir.mkdir(parents=True, exist_ok=True)

    repo_root = _repo_root()
    plugin_src = repo_root / "plugin"

    copied = []
    for name in PLUGIN_FILES:
        src = plugin_src / name
        if not src.is_file():
            raise FileNotFoundError(f"plugin source not found: {src}")
        dst = ida_plugins_dir / name
        shutil.copy2(src, dst)
        copied.append(str(dst))

    try:
        pth = _write_pth(ida_plugins_dir / "ida_cli_path.pth", repo_root)
        pth_path = str(pth)
    except Exception:
        pth_path = None

    return {
        "ida_plugins_dir": str(ida_plugins_dir),
        "copied": copied,
        "pth": pth_path,
        "repo_root": str(repo_root),
    }


def uninstall(ida_plugins_dir: Path = None) -> dict:
    if ida_plugins_dir is None:
        ida_plugins_dir = get_ida_user_plugins_dir()
    ida_plugins_dir = Path(ida_plugins_dir)

    removed = []
    for name in (*PLUGIN_FILES, "ida_cli_path.pth"):
        target = ida_plugins_dir / name
        if target.exists():
            target.unlink()
            removed.append(str(target))
    return {"ida_plugins_dir": str(ida_plugins_dir), "removed": removed}


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m ida_cli.installer",
        description="Install/uninstall the ida-cli connector into IDA Pro's plugins directory.",
    )
    parser.add_argument("action", choices=["install", "uninstall", "paths"], help="Action to perform")
    parser.add_argument("--ida-plugins-dir", default=None,
                        help="Override IDA's user plugins directory")
    args = parser.parse_args(argv)

    if args.action == "paths":
        print(f"repo root        : {_repo_root()}")
        print(f"plugin source    : {_repo_root() / 'plugin'}")
        print(f"IDA plugins dir  : {get_ida_user_plugins_dir()}")
        return 0

    target = Path(args.ida_plugins_dir) if args.ida_plugins_dir else None
    report = install(target) if args.action == "install" else uninstall(target)
    for key, value in report.items():
        print(f"{key}: {value}")
    if args.action == "install":
        print("Restart IDA (or reload the plugin) to start the connector.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
