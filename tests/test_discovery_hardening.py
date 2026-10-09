"""Phase 1 hardening tests: atomic descriptors, TCP-probe validation, ambiguity."""

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from ida_cli import server
from ida_cli.discovery import (
    AmbiguousInstanceError,
    list_instances,
    probe_instance,
    resolve_instance,
)


class _Listener:
    """A minimal live TCP endpoint so probe_instance() succeeds."""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class TestDiscoveryHardening(unittest.TestCase):
    def setUp(self):
        self._old_env = os.environ.get("IDA_CLI_INSTANCES_DIR")
        self.tmp = Path(tempfile.mkdtemp(prefix="idacli_disc_"))
        self.inst_dir = self.tmp / "instances"
        self.inst_dir.mkdir(parents=True, exist_ok=True)
        os.environ["IDA_CLI_INSTANCES_DIR"] = str(self.inst_dir)
        self._listeners = []

    def tearDown(self):
        for listener in self._listeners:
            listener.close()
        if self._old_env is None:
            os.environ.pop("IDA_CLI_INSTANCES_DIR", None)
        else:
            os.environ["IDA_CLI_INSTANCES_DIR"] = self._old_env
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _listener(self):
        listener = _Listener()
        self._listeners.append(listener)
        return listener

    def _descriptor(self, name, pid, port, root_dir=None):
        path = self.inst_dir / name
        path.write_text(json.dumps({
            "pid": pid,
            "port": port,
            "idb_path": str(self.tmp / "sample.i64"),
            "input_file": str(self.tmp / "sample.exe"),
            "root_dir": root_dir if root_dir is not None else str(self.tmp / "root"),
            "status": "ready",
            "ida_version": "9.1",
            "current_ea": "0x401000",
            "started_at": 1,
            "last_heartbeat": 1,
        }), encoding="utf-8")
        return path

    def test_atomic_write_json_is_complete_and_leaves_no_temp(self):
        target = self.inst_dir / "atomic.json"
        server._atomic_write_json(target, {"pid": 1, "port": 2, "nested": {"a": 1}})
        self.assertEqual(json.loads(target.read_text(encoding="utf-8"))["nested"]["a"], 1)
        self.assertEqual(list(self.inst_dir.glob(".tmp_*")), [])

    def test_corrupt_descriptor_is_pruned(self):
        corrupt = self.inst_dir / "ida_1_28100_nodb.json"
        corrupt.write_bytes(b"\x00" * 245)
        self.assertEqual(list_instances(prune_dead=True), [])
        self.assertFalse(corrupt.exists())

    def test_dead_pid_descriptor_is_pruned(self):
        dead = self._descriptor("ida_999999_28101_x.json", pid=999999, port=28101)
        self.assertEqual(list_instances(prune_dead=True), [])
        self.assertFalse(dead.exists())

    def test_unreachable_port_is_skipped_but_kept(self):
        # Alive PID (us) but nothing listening on the descriptor port.
        free = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        free.bind(("127.0.0.1", 0))
        dead_port = free.getsockname()[1]
        free.close()
        path = self._descriptor(
            "ida_%d_%d_x.json" % (os.getpid(), dead_port), pid=os.getpid(), port=dead_port
        )
        self.assertEqual(list_instances(prune_dead=True), [])
        self.assertTrue(path.exists(), "unreachable instance must not be deleted")

    def test_probe_instance_true_false(self):
        listener = self._listener()
        self.assertTrue(probe_instance("127.0.0.1", listener.port))
        listener.close()
        self.assertFalse(probe_instance("127.0.0.1", listener.port))

    def test_single_instance_resolves(self):
        listener = self._listener()
        self._descriptor(
            "ida_%d_%d_a.json" % (os.getpid(), listener.port),
            pid=os.getpid(),
            port=listener.port,
        )
        resolved = resolve_instance(cwd=self.tmp / "other")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.port, listener.port)

    def test_multiple_instances_raise_ambiguity(self):
        a = self._listener()
        b = self._listener()
        self._descriptor("ida_%d_%d_a.json" % (os.getpid(), a.port), os.getpid(), a.port)
        self._descriptor("ida_%d_%d_b.json" % (os.getpid(), b.port), os.getpid(), b.port)
        with self.assertRaises(AmbiguousInstanceError):
            resolve_instance(cwd=self.tmp / "other")

    def test_explicit_target_disambiguates(self):
        a = self._listener()
        b = self._listener()
        self._descriptor("ida_%d_%d_a.json" % (os.getpid(), a.port), os.getpid(), a.port)
        self._descriptor("ida_%d_%d_b.json" % (os.getpid(), b.port), os.getpid(), b.port)
        resolved = resolve_instance(target=str(b.port), cwd=self.tmp / "other")
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved.port, b.port)

    def test_tool_timeout_env(self):
        with mock.patch.dict(os.environ, {"IDA_CLI_TOOL_TIMEOUT_SEC": "123"}):
            self.assertEqual(server.get_tool_timeout_seconds(), 123.0)
        with mock.patch.dict(os.environ, {"IDA_CLI_TOOL_TIMEOUT_SEC": "bogus"}):
            self.assertEqual(server.get_tool_timeout_seconds(), server._DEFAULT_TOOL_TIMEOUT_SEC)


if __name__ == "__main__":
    unittest.main()
