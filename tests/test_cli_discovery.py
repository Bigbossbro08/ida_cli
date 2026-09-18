"""
Automated unit and integration test for IDA-CLI discovery and server communication.
"""

import json
import subprocess
import sys
import time
import unittest
from pathlib import Path

from ida_cli import server
from ida_cli.client import IdaClient
from ida_cli.discovery import list_instances, resolve_instance


class TestIdaCliDiscovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start server
        cls.port = server.start_server()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        server.stop_server()
        time.sleep(0.5)

    def test_01_instance_registered(self):
        instances = list_instances(prune_dead=True)
        self.assertTrue(len(instances) >= 1)
        inst = resolve_instance(target=str(self.port))
        self.assertIsNotNone(inst)
        self.assertEqual(inst.port, self.port)
        self.assertEqual(inst.pid, server.os.getpid())

    def test_02_client_status(self):
        inst = resolve_instance(target=str(self.port))
        self.assertIsNotNone(inst)
        client = IdaClient(inst)
        status = client.get_status()
        self.assertEqual(status.get("pid"), server.os.getpid())

    def test_03_client_exec(self):
        inst = resolve_instance(target=str(self.port))
        client = IdaClient(inst)
        res = client.exec_code("10 * 42")
        self.assertEqual(res.get("result"), "420")

    def test_04_client_list_commands(self):
        inst = resolve_instance(target=str(self.port))
        client = IdaClient(inst)
        cmds = client.get_commands()
        self.assertIn("status", cmds)
        self.assertIn("exec", cmds)
        self.assertIn("funcs_list", cmds)
        self.assertIn("func_inspect", cmds)

    def test_05_cli_subprocess(self):
        # Test running the CLI script via python -m ida_cli.cli
        res = subprocess.run(
            [sys.executable, "-m", "ida_cli.cli", "instances", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(res.stdout)
        ports = [i["port"] for i in data]
        self.assertIn(self.port, ports)

        # Test CLI status with -i before subcommand
        res_stat = subprocess.run(
            [sys.executable, "-m", "ida_cli.cli", "-i", str(self.port), "status", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        stat_data = json.loads(res_stat.stdout)
        self.assertEqual(stat_data.get("pid"), server.os.getpid())

        # Test CLI status with -i after subcommand
        res_stat2 = subprocess.run(
            [sys.executable, "-m", "ida_cli.cli", "status", "-i", str(self.port), "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        stat_data2 = json.loads(res_stat2.stdout)
        self.assertEqual(stat_data2.get("pid"), server.os.getpid())

        # Test CLI exec
        res_exec = subprocess.run(
            [sys.executable, "-m", "ida_cli.cli", "-i", str(self.port), "exec", "123 + 456", "--json"],
            capture_output=True,
            text=True,
            check=True,
        )
        exec_data = json.loads(res_exec.stdout)
        self.assertEqual(exec_data.get("result"), "579")


if __name__ == "__main__":
    unittest.main()
