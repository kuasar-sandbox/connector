#!/usr/bin/env python3
"""Check management counters against one real service-NAT datagram each way."""

import json
import selectors
import shlex
import subprocess
import sys


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


if __name__ == "__main__":
    main()
