"""
IDA Instance Discovery Module
Scans ~/.ida-cli/instances/*.json, prunes stale or dead instances,
and matches instances based on PID, port, or current working directory.
"""

import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class IdaInstance:
    pid: int
    port: int
    idb_path: str
    input_file: str
    root_dir: str
    status: str
    ida_version: str
    current_ea: str
    started_at: int
    last_heartbeat: int
    file_path: Path

    @property
    def is_stale(self) -> bool:
        # If heartbeat hasn't been updated for > 30 seconds
        return (time.time() - self.last_heartbeat) > 30

    @property
    def idb_name(self) -> str:
        if self.idb_path:
            return Path(self.idb_path).name
        if self.input_file:
            return Path(self.input_file).name
        return "Untitled"


def is_pid_alive(pid: int) -> bool:
    """Checks if a process ID is currently running."""
    if pid <= 0:
        return False

    if sys.platform == "win32":
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if handle:
            exit_code = ctypes.c_ulong()
            if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                kernel32.CloseHandle(handle)
                # STILL_ACTIVE = 259 (0x103)
                return exit_code.value == 259
            kernel32.CloseHandle(handle)
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True


def get_instances_dir() -> Path:
    instances_dir = Path.home() / ".ida-cli" / "instances"
    instances_dir.mkdir(parents=True, exist_ok=True)
    return instances_dir


def list_instances(prune_dead: bool = True) -> List[IdaInstance]:
    """Scans ~/.ida-cli/instances/ and returns active instances."""
    instances_dir = get_instances_dir()
    instances = []

    for file_path in instances_dir.glob("*.json"):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            pid = data.get("pid", 0)
            port = data.get("port", 0)

            # Check if process is still alive
            if not is_pid_alive(pid):
                if prune_dead:
                    try:
                        file_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                continue

            instance = IdaInstance(
                pid=pid,
                port=port,
                idb_path=data.get("idb_path", ""),
                input_file=data.get("input_file", ""),
                root_dir=data.get("root_dir", ""),
                status=data.get("status", "unknown"),
                ida_version=data.get("ida_version", "unknown"),
                current_ea=data.get("current_ea", "0x0"),
                started_at=data.get("started_at", 0),
                last_heartbeat=data.get("last_heartbeat", 0),
                file_path=file_path,
            )
            instances.append(instance)
        except Exception:
            # Malformed JSON or read error
            continue

    # Deduplicate by (pid, port): keep newest, prune older descriptor files for the same process
    instances.sort(key=lambda inst: inst.last_heartbeat, reverse=True)
    seen_endpoints = set()
    deduped = []
    for inst in instances:
        key = (inst.pid, inst.port)
        if key in seen_endpoints:
            if prune_dead and inst.file_path:
                try:
                    inst.file_path.unlink(missing_ok=True)
                except Exception:
                    pass
            continue
        seen_endpoints.add(key)
        deduped.append(inst)

    return deduped


def resolve_instance(target: Optional[str] = None, cwd: Optional[Path] = None) -> Optional[IdaInstance]:
    """
    Resolves the target IDA instance.
    Order of resolution:
    1. Direct match by port (e.g. "28100")
    2. Direct match by PID (e.g. "37000")
    3. Match by IDB filename or stem (e.g. "age2_x1")
    4. Match by current working directory (CWD matches IDB root_dir)
    5. Single active instance fallback
    """
    instances = list_instances(prune_dead=True)
    if not instances:
        return None

    # 1-3: Explicit target specified
    if target:
        target_str = str(target).strip().lower()

        # Try match by port
        for inst in instances:
            if str(inst.port) == target_str:
                return inst

        # Try match by PID
        for inst in instances:
            if str(inst.pid) == target_str:
                return inst

        # Try match by IDB / input filename
        for inst in instances:
            if target_str in inst.idb_name.lower() or (inst.idb_path and target_str in Path(inst.idb_path).stem.lower()):
                return inst

        return None

    # 4: Auto-detect by current working directory
    if cwd is None:
        cwd = Path.cwd().resolve()
    else:
        cwd = Path(cwd).resolve()

    cwd_str = str(cwd).lower()
    for inst in instances:
        if inst.root_dir:
            inst_root = str(Path(inst.root_dir).resolve()).lower()
            if cwd_str == inst_root or cwd_str.startswith(inst_root + os.sep) or inst_root.startswith(cwd_str + os.sep):
                return inst

    # 5: Single active instance fallback
    if len(instances) == 1:
        return instances[0]

    # If multiple instances exist and none matched CWD, return the most recently updated one
    return instances[0]


def find_ida_executable(headless: bool = False) -> Optional[Path]:
    """Finds the IDA Pro executable on the system.

    Checks:
      1. Environment variables (IDA_EXE, IDA_DIR, IDADIR)
      2. System PATH
      3. Standard / known installation directories (including workspace J:/Software/IDA Professional 9.1)
      4. Windows App Paths registry
    """
    import shutil

    exe_names = ["idat.exe", "idat64.exe", "idat"] if headless else ["ida.exe", "ida64.exe", "ida"]

    # 1. Direct environment variable IDA_EXE
    env_exe = os.environ.get("IDA_EXE")
    if env_exe:
        p = Path(env_exe)
        if p.is_file():
            return p

    # 1b. Environment variable IDA_DIR / IDADIR
    for env_var in ("IDA_DIR", "IDADIR"):
        dir_val = os.environ.get(env_var)
        if dir_val:
            p_dir = Path(dir_val)
            for name in exe_names:
                cand = p_dir / name
                if cand.is_file():
                    return cand

    # 2. System PATH
    for name in exe_names:
        found = shutil.which(name)
        if found:
            return Path(found)

    # 3. Known install directories
    search_dirs = [
        Path("J:/Software/IDA Professional 9.1"),
        Path("C:/Program Files/IDA Professional 9.1"),
        Path("C:/Program Files/IDA Pro 9.1"),
        Path("C:/Program Files/IDA Pro 9.0"),
        Path("C:/Program Files/IDA Pro 8.4"),
        Path("C:/Program Files/IDA Pro 8.3"),
        Path("D:/Software/IDA Professional 9.1"),
        Path("E:/Software/IDA Professional 9.1"),
    ]

    for d in search_dirs:
        if d.is_dir():
            for name in exe_names:
                cand = d / name
                if cand.is_file():
                    return cand

    # 4. Windows App Paths registry
    if sys.platform == "win32":
        try:
            import winreg
            for name in exe_names:
                for root in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
                    try:
                        key_path = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{name}"
                        with winreg.OpenKey(root, key_path) as k:
                            val, _ = winreg.QueryValueEx(k, "")
                            if val and Path(val).is_file():
                                return Path(val)
                    except Exception:
                        pass
        except Exception:
            pass

    return None

