#!/usr/bin/env python3
"""The wire fixture keeps traffic live until its observer releases it."""
import importlib.util
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('egress_wire', ROOT / 'test/e2e/lib/egress/wire.py')
WIRE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WIRE)


class KeepaliveObservationTests(unittest.TestCase):
    def test_real_echo_traffic_runs_until_observation_then_returns_early(self):
        with tempfile.TemporaryDirectory() as temporary, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            signal = Path(temporary) / 'observed'
            server.bind(('127.0.0.1', 0))
            server.settimeout(0.05)
            client.settimeout(1)
            stop = threading.Event()
            errors = []

            def echo_and_observe():
                count = 0
                try:
                    while not stop.is_set():
                        try:
                            data, address = server.recvfrom(1024)
                        except socket.timeout:
                            continue
                        server.sendto(data, address)
                        count += 1
                        if count == 100:
                            signal.touch(exist_ok=False)
                except Exception as error:
                    errors.append(error)

            worker = threading.Thread(target=echo_and_observe)
            worker.start()
            try:
                calls = 0

                def exchange(request):
                    nonlocal calls
                    self.assertEqual(request, {'slot': 1})
                    data = str(calls).encode()
                    client.sendto(data, server.getsockname())
                    self.assertEqual(client.recv(1024), data)
                    calls += 1

                started = time.monotonic()
                result = WIRE.keepalive_until_observed(exchange, 1, 15, signal)
                self.assertLess(time.monotonic() - started, 5)
                self.assertEqual(result, dict(ok=True, echoed=calls, observation_confirmed=True))
                self.assertGreaterEqual(calls, 100)
                self.assertFalse(errors)
            finally:
                stop.set()
                worker.join(timeout=1)
            self.assertFalse(worker.is_alive())

    def test_missing_observer_is_a_failure_not_success_at_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []

            def exchange(request):
                calls.append(request)
                time.sleep(0.005)

            with self.assertRaisesRegex(TimeoutError, 'not both completed'):
                WIRE.keepalive_until_observed(exchange, 1, 0.03, Path(temporary) / 'absent')
            self.assertGreater(len(calls), 0)

    def test_early_observation_still_requires_100_exchanges(self):
        with tempfile.TemporaryDirectory() as temporary:
            signal = Path(temporary) / 'observed'
            calls = 0

            def exchange(request):
                nonlocal calls
                calls += 1
                if calls == 1:
                    signal.touch(exist_ok=False)

            result = WIRE.keepalive_until_observed(exchange, 1, 15, signal)
            self.assertEqual(calls, 100)
            self.assertEqual(result, dict(ok=True, echoed=100, observation_confirmed=True))

    def test_failed_traffic_is_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            calls = []

            def exchange(request):
                calls.append(request)
                raise RuntimeError('traffic failed')

            with self.assertRaisesRegex(RuntimeError, 'traffic failed'):
                WIRE.keepalive_until_observed(exchange, 1, 15, Path(temporary) / 'absent')
            self.assertEqual(calls, [{'slot': 1}])

    def test_stale_signal_cannot_skip_traffic(self):
        with tempfile.TemporaryDirectory() as temporary:
            signal = Path(temporary) / 'stale'
            signal.touch()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                WIRE.keepalive_until_observed(lambda _: self.fail('unexpected traffic'), 1, 15, signal)


if __name__ == '__main__':
    unittest.main()
