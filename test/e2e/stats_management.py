#!/usr/bin/env python3
"""Check management counters against one real service-NAT datagram each way."""

import json
import selectors
import shlex
import subprocess
import sys
import time


def main():
    switch_command, switch, vip, vport, target, target_port = sys.argv[1:]

    def stats():
        result = subprocess.check_output(
            shlex.split(switch_command) + ["stats", switch, "--port=1"],
            text=True, timeout=5,
        )
        return json.loads(result)["ports"][0]

    server_code = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.bind((sys.argv[1], int(sys.argv[2])))
print('READY', flush=True)
data, peer = s.recvfrom(4096)
assert data == b't' * 1201, len(data)
assert peer[0] == '100.100.96.0', peer
s.sendto(b'r' * 137, peer)
s.close()
"""
    server = subprocess.Popen(
        ["ip", "netns", "exec", "mgmt_ns", "python3", "-c", server_code, target, target_port],
        stdout=subprocess.PIPE, text=True,
    )
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(server.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=5), "UDP service did not start"
            assert server.stdout.readline().strip() == "READY", "UDP service failed"
        before = stats()
        client_code = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(5)
s.connect((sys.argv[1], int(sys.argv[2])))
s.send(b't' * 1201)
assert s.recv(4096) == b'r' * 137
s.close()
"""
        subprocess.run(
            ["ip", "netns", "exec", "sandbox1", "python3", "-c", client_code, vip, vport],
            check=True, timeout=8,
        )
        assert server.wait(timeout=5) == 0, "UDP service failed"
        after = stats()
        # These IPv4 UDP frames include Ethernet + IPv4 + UDP (14 + 20 + 8).
        # Distinct payload lengths prove sandbox TX/RX direction independently.
        expected = {"mgmt_tx_packets": 1, "mgmt_tx_bytes": 1243,
                    "mgmt_rx_packets": 1, "mgmt_rx_bytes": 179,
                    "transit_tx_packets": 0, "transit_tx_bytes": 0,
                    "transit_rx_packets": 0, "transit_rx_bytes": 0}
        delta = {key: after[key] - before[key] for key in expected}
        assert delta == expected, (delta, expected)
        print("PASS: real FloatingIP service NAT, sandbox TX/RX packet/byte direction and transit isolation", delta)
    finally:
        if server.poll() is None:
            server.kill()
        server.wait(timeout=5)
        server.stdout.close()

    check_reuse_with_traffic(shlex.split(switch_command), switch, vip, vport, target, target_port)


def check_reuse_with_traffic(command, switch, vip, vport, target, target_port):
    server_code = """
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
print('READY', flush=True)
while True:
    data, peer = s.recvfrom(4096)
    assert data == b't' * 1201, len(data)
    assert peer[0] == '100.100.96.0', peer
    s.sendto(b'r' * 137, peer)
"""
    client_code = """
import socket, sys, threading

def traffic():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.05)
    s.connect((sys.argv[1], int(sys.argv[2])))
    ready = False
    while True:
        s.send(b't' * 1201)
        try:
            assert s.recv(4096) == b'r' * 137
            if not ready:
                print('READY', flush=True)
                ready = True
        except socket.timeout:
            pass

threads = [threading.Thread(target=traffic) for _ in range(4)]
for t in threads: t.start()
for t in threads: t.join()
"""
    server = subprocess.Popen(
        ["ip", "netns", "exec", "mgmt_ns", "python3", "-c", server_code, target, target_port],
        stdout=subprocess.PIPE, text=True,
    )
    client = None
    try:
        with selectors.DefaultSelector() as ready:
            ready.register(server.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=5), "reuse UDP service did not start"
            assert server.stdout.readline().strip() == "READY"
        client = subprocess.Popen(
            ["ip", "netns", "exec", "sandbox1", "python3", "-c", client_code, vip, vport],
            stdout=subprocess.PIPE, text=True,
        )
        with selectors.DefaultSelector() as ready:
            ready.register(client.stdout, selectors.EVENT_READ)
            assert ready.select(timeout=5), "continuous real traffic never became reachable"
            assert client.stdout.readline().strip() == "READY"
        observed = 0
        for _ in range(20):
            subprocess.run(command + ["detach", switch, "--port=1", "--skip-device"], check=True, stdout=subprocess.PIPE, timeout=5)
            subprocess.run(command + ["attach", switch, "--port=1", "--inner-ip=169.254.1.1", "--skip-device"], check=True, stdout=subprocess.PIPE, timeout=5)
            deadline = time.monotonic() + 5
            while True:
                row = json.loads(subprocess.check_output(command + ["stats", switch, "--port=1"], text=True, timeout=5))["ports"][0]
                assert row["inner_ip"] == "169.254.1.1"
                assert row["mgmt_tx_bytes"] == row["mgmt_tx_packets"] * 1243, row
                assert row["mgmt_rx_bytes"] == row["mgmt_rx_packets"] * 179, row
                assert all(row[key] == 0 for key in ("transit_rx_packets", "transit_rx_bytes", "transit_tx_packets", "transit_tx_bytes")), row
                if row["mgmt_rx_packets"] > 0 and row["mgmt_tx_packets"] > 0:
                    observed += row["mgmt_rx_packets"] + row["mgmt_tx_packets"]
                    break
                assert time.monotonic() < deadline, ("real UDP traffic did not resume after reuse", row)
                time.sleep(0.02)
        assert observed > 0, "reuse checks saw no actual traffic"
        assert server.poll() is None and client.poll() is None, "traffic process exited"
        print("PASS: 20 slot detach/reuses with four live FloatingIP UDP streams; current packet/byte pairs verified after every reuse")
    finally:
        for process in (client, server):
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=5)
                process.stdout.close()


if __name__ == "__main__":
    main()
