#!/usr/bin/env python3
"""Exercise real subprocesses and loopback sockets used by GENEVE readiness."""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "test/e2e/lib/geneve_readiness.py"
spec = importlib.util.spec_from_file_location("geneve_readiness", HELPER)
readiness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(readiness)


@contextmanager
def child(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        yield process
    finally:
        readiness.reap(process)
        process.communicate()
        process.stdout.close()
        process.stderr.close()


def python(code):
    return [sys.executable, "-B", "-c", code]


@contextmanager
def receiver(payload="hello-geneve", timeout=2.0):
    command = [sys.executable, "-B", str(HELPER), "_receive",
               "--port", "0", "--payload", payload, "--timeout", str(timeout)]
    with child(command) as process:
        port = readiness.wait_tcp_ready(process, 0, 2.0)
        yield process, port


class GeneveReadinessTests(unittest.TestCase):
    def test_complete_tcp_exchange_and_owned_wait(self):
        readiness.tcp_transfer(None, None, "127.0.0.1", 0, "complete-marker", 2.0)

    def test_receiver_reads_fragments_until_eof(self):
        with receiver() as (process, port):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(b"hello-")
                connection.sendall(b"geneve\n")
                connection.shutdown(socket.SHUT_WR)
            output, error = process.communicate(timeout=2)
            self.assertEqual(process.returncode, 0, error.decode())
            self.assertEqual(output, b"")

    def test_receiver_rejects_short_extra_and_wrong_payload(self):
        for payload in (b"hello-geneve", b"hello-geneve\nextra", b"wrong-marker\n"):
            with self.subTest(payload=payload), receiver() as (process, port):
                with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                    connection.sendall(payload)
                    connection.shutdown(socket.SHUT_WR)
                _, error = process.communicate(timeout=2)
                self.assertNotEqual(process.returncode, 0)
                self.assertIn(b"TCP payload", error)

    def test_receiver_requires_eof_after_complete_marker(self):
        with receiver(timeout=0.15) as (process, port):
            with socket.create_connection(("127.0.0.1", port), timeout=2) as connection:
                connection.sendall(b"hello-geneve\n")
                # A matching prefix without EOF does not complete the assertion.
                _, error = process.communicate(timeout=2)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn(b"TimeoutError", error)

    def test_readiness_waits_for_complete_delayed_line(self):
        code = ("import os,time; os.write(1,b'REA'); time.sleep(.1); "
                "os.write(1,b'DY 9000\\n'); time.sleep(10)")
        with child(python(code)) as process:
            self.assertEqual(readiness.wait_tcp_ready(process, 9000, 2), 9000)

    def test_readiness_rejects_eof_wrong_port_garbage_and_partial_timeout(self):
        controls = [
            ("pass", RuntimeError),
            ("import os,time; os.write(1,b'READY 9001\\n'); time.sleep(10)", RuntimeError),
            ("import os,time; os.write(1,b'NOT READY\\n'); time.sleep(10)", RuntimeError),
            ("import os,time; os.write(1,b'READY 9000'); time.sleep(10)", TimeoutError),
        ]
        for code, expected in controls:
            with self.subTest(code=code), child(python(code)) as process:
                with self.assertRaises(expected):
                    readiness.wait_tcp_ready(process, 9000, 0.15)

    def test_real_client_failure_is_propagated_and_receiver_is_reaped(self):
        original_namespace = readiness.namespace_command
        original_popen = subprocess.Popen
        processes = []

        def command(namespace, argv):
            if namespace == "failing-source":
                return python("raise SystemExit(23)")
            return original_namespace(namespace, argv)

        def record(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        with mock.patch.object(readiness, "namespace_command", side_effect=command), \
                mock.patch.object(subprocess, "Popen", side_effect=record):
            with self.assertRaises(subprocess.CalledProcessError) as error:
                readiness.tcp_transfer("failing-source", None, "127.0.0.1",
                                       0, "client-error", 2)
        self.assertEqual(error.exception.returncode, 23)
        self.assertEqual(len(processes), 2)
        self.assertTrue(all(process.poll() is not None for process in processes))

    def test_udp_readiness_waits_for_owned_bind(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        code = ("import socket,time; time.sleep(.1); "
                "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                f"s.bind(('127.0.0.1',{port})); time.sleep(10)")
        with child(python(code)) as process:
            readiness.wait_udp_bound(process.pid, port, 2.0)
            self.assertTrue(readiness.udp_bound_by_process(
                process.pid, readiness.process_starttime(process.pid), port))

    def test_udp_foreign_socket_is_not_owned_readiness(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign:
            foreign.bind(("127.0.0.1", 0))
            with child(python("import time; time.sleep(10)")) as process:
                with self.assertRaises(TimeoutError):
                    readiness.wait_udp_bound(process.pid, foreign.getsockname()[1], 0.15)

    def test_udp_rejects_dead_process_and_changed_identity(self):
        with child(python("import time; time.sleep(10)")) as process:
            token = readiness.process_starttime(process.pid)
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                readiness.udp_bound_by_process(process.pid, token + 1, 67)
            process.terminate()
            process.wait(timeout=2)
            with self.assertRaisesRegex(RuntimeError, "exited"):
                readiness.wait_udp_bound(process.pid, 67, 0.15)


if __name__ == "__main__":
    unittest.main(verbosity=2)
