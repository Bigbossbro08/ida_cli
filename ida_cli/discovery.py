"""
IDA Instance Discovery Module
Scans ~/.ida-cli/instances/*.json, prunes stale or dead instances,
and matches instances based on PID, port, or current working directory.
"""

import json
import os
import socket
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


class AmbiguousInstanceError(Exception):
    """Raised when several IDA instances are reachable and no target was given."""


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
        # Prefer the IDB path; else derive from the input binary; else the
        # descriptor's slug (works in headless mode where idb_path is empty).
        for candidate in (self.idb_path, self.input_file):
            if candidate:
                return Path(candidate).name
        if self.file_path is not None:
            stem = Path(self.file_path).stem
            parts = stem.split("_")
            if len(parts) > 3:
                return "_".join(parts[3:])
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


def probe_instance(host: str, port: int, timeout: float = 0.5) -> bool:
    """Return True if a TCP connection to host:port can be established quickly.

    Used as a secondary liveness check so a descriptor whose process is alive
    (or whose PID was recycled) but whose connector crashed is not trusted.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _safe_unlink(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except Exception:
        pass


def get_instances_dir() -> Path:
    override = os.environ.get("IDA_CLI_INSTANCES_DIR")
    instances_dir = Path(override) if override else (Path.home() / ".ida-cli" / "instances")
    instances_dir.mkdir(parents=True, exist_ok=True)
    return instances_dir


def list_instances(prune_dead: bool = True) -> List[IdaInstance]:
    """Scans ~/.ida-cli/instances/ and returns reachable, live instances.

    A descriptor is discarded (and its file removed when ``prune_dead``) when it
    cannot be parsed or its PID is no longer alive. A descriptor whose PID is
    alive but whose connector port does not accept connections is skipped but
    left on disk, so a temporarily busy IDA is not forgotten.
    """
    instances_dir = get_instances_dir()
    instances = []

    for file_path in instances_dir.glob("*.json"):
        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("descriptor is not a JSON object")
            pid = int(data.get("pid", 0) or 0)
            port = int(data.get("port", 0) or 0)
            if pid <= 0 or port <= 0:
                raise ValueError("descriptor missing pid/port")
        except Exception:
            # Corrupt or malformed descriptor (e.g. zero-filled after a crash):
            # remove it so it can never poison instance resolution.
            if prune_dead:
                _safe_unlink(file_path)
            continue

        # Dead process: the descriptor is stale.
        if not is_pid_alive(pid):
            if prune_dead:
                _safe_unlink(file_path)
            continue

        # Alive process but the connector is not accepting connections: skip it
        # (do not delete) so the instance can recover once it is responsive.
        if not probe_instance("127.0.0.1", port):
            continue

        instances.append(IdaInstance(
            pid=pid,
            port=port,
            idb_path=data.get("idb_path", ""),
            input_file=data.get("input_file", ""),
            # Note: root_dir here is the descriptor's stored value; callers that
            # need the input-file directory should use input_file.
            root_dir=data.get("root_dir", ""),
            status=data.get("status", "unknown"),
            ida_version=data.get("ida_version", "unknown"),
            current_ea=data.get("current_ea", "0x0"),
            started_at=data.get("started_at", 0),
            last_heartbeat=data.get("last_heartbeat", 0),
            file_path=file_path,
        ))

    # Deduplicate by (pid, port): keep newest, prune older descriptor files for the same process
    instances.sort(key=lambda inst: inst.last_heartbeat, reverse=True)
    seen_endpoints = set()
    deduped = []
    for inst in instances:
        key = (inst.pid, inst.port)
        if key in seen_endpoints:
            if prune_dead and inst.file_path:
                _safe_unlink(inst.file_path)
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
    5. Single reachable instance fallback
    6. Otherwise raise AmbiguousInstanceError (never silently pick one).
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

    # 5: Single reachable instance fallback
    if len(instances) == 1:
        return instances[0]

    # 6: Several reachable instances and nothing matched the CWD. Refuse to
    # guess: silently targeting the wrong database is worse than failing.
    candidates = ", ".join(
        f"{inst.idb_name} (pid={inst.pid}, port={inst.port})" for inst in instances
    )
    raise AmbiguousInstanceError(
        "Multiple IDA instances are running and none matches the current "
        "directory. Select one with -i/--instance by port, PID, or IDB name. "
        f"Candidates: {candidates}"
    )


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

