#!/usr/bin/env python3
"""Bounded readiness and exact TCP transfer for the GENEVE E2E case."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import selectors
import socket
import subprocess
import sys
import time


def process_starttime(pid: int) -> int:
    if pid <= 0:
        raise RuntimeError("expected an owned positive PID")
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
    except FileNotFoundError as exc:
        raise RuntimeError(f"owned process {pid} exited") from exc
    if len(fields) < 20 or fields[0] in {"Z", "X"}:
        raise RuntimeError(f"owned process {pid} is not running")
    return int(fields[19])


def socket_inodes(pid: int) -> set[str]:
    result = set()
    try:
        descriptors = list(Path(f"/proc/{pid}/fd").iterdir())
    except FileNotFoundError as exc:
        raise RuntimeError(f"owned process {pid} exited") from exc
    for descriptor in descriptors:
        try:
            target = os.readlink(descriptor)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            result.add(match.group(1))
    return result


def udp_bound_by_process(pid: int, starttime: int, port: int) -> bool:
    if process_starttime(pid) != starttime:
        raise RuntimeError(f"owned process {pid} identity changed")
    owned = socket_inodes(pid)
    try:
        rows = Path(f"/proc/{pid}/net/udp").read_text().splitlines()[1:]
    except FileNotFoundError as exc:
        raise RuntimeError(f"owned process {pid} exited") from exc
    for row in rows:
        fields = row.split()
        if len(fields) < 10:
            continue
        address, encoded_port = fields[1].split(":")
        if len(address) == 8 and int(encoded_port, 16) == port and fields[9] in owned:
            if process_starttime(pid) != starttime:
                raise RuntimeError(f"owned process {pid} identity changed")
            # Do not accept a descriptor closed between the two observations.
            return fields[9] in socket_inodes(pid)
    if process_starttime(pid) != starttime:
        raise RuntimeError(f"owned process {pid} identity changed")
    return False


def wait_udp_bound(pid: int, port: int, timeout: float = 5.0) -> None:
    starttime = process_starttime(pid)
    deadline = time.monotonic() + timeout
    while True:
        if udp_bound_by_process(pid, starttime, port):
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(f"owned process {pid} did not bind IPv4 UDP/{port}")
        time.sleep(min(0.02, remaining))


def wait_tcp_ready(process: subprocess.Popen, port: int, timeout: float) -> int:
    """Read a whole readiness line without blocking on a partial line."""
    assert process.stdout is not None
    deadline = time.monotonic() + timeout
    data = b""
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("owned TCP receiver did not become ready")
            if not selector.select(remaining):
                raise TimeoutError("owned TCP receiver did not become ready")
            chunk = os.read(process.stdout.fileno(), 128)
            if not chunk:
                raise RuntimeError("owned TCP receiver exited before readiness")
            data += chunk
            if len(data) > 64:
                raise RuntimeError("invalid TCP readiness record")
            if b"\n" in data:
                match = re.fullmatch(rb"READY ([0-9]{1,5})\n", data)
                if not match:
                    raise RuntimeError("invalid TCP readiness record")
                bound_port = int(match.group(1))
                if not 1 <= bound_port <= 65535 or (port and bound_port != port):
                    raise RuntimeError("TCP receiver reported the wrong port")
                if process.poll() is not None:
                    raise RuntimeError("owned TCP receiver exited after readiness")
                return bound_port


def reap(process: subprocess.Popen) -> None:
    """Stop and wait for this child only, including when readiness/send failed."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)
    else:
        process.wait()


def namespace_command(namespace: str | None, command: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command] if namespace else command


def receive(port: int, payload: str, timeout: float) -> None:
    expected = (payload + "\n").encode()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.settimeout(timeout)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)
        print(f"READY {listener.getsockname()[1]}", flush=True)
        connection, _ = listener.accept()
        with connection:
            deadline = time.monotonic() + timeout
            received = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("TCP payload did not end before the deadline")
                connection.settimeout(remaining)
                chunk = connection.recv(max(1, len(expected) + 1 - len(received)))
                if not chunk:
                    break
                received.extend(chunk)
                if len(received) > len(expected):
                    raise RuntimeError("TCP payload contains extra bytes")
            if received != expected:
                raise RuntimeError("TCP payload does not match the complete marker")


def send(host: str, port: int, payload: str, timeout: float) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.settimeout(timeout)
        connection.connect((host, port))
        connection.sendall((payload + "\n").encode())
        connection.shutdown(socket.SHUT_WR)


def tcp_transfer(source_netns: str | None, target_netns: str | None,
                 target_ip: str, port: int, payload: str, timeout: float = 5.0) -> None:
    helper = str(Path(__file__).resolve())
    common = ["--payload", payload, "--timeout", str(timeout)]
    receiver = namespace_command(target_netns, [
        sys.executable, "-B", helper, "_receive", "--port", str(port), *common])
    process = subprocess.Popen(receiver, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        bound_port = wait_tcp_ready(process, port, timeout)
        client = namespace_command(source_netns, [
            sys.executable, "-B", helper, "_send", "--host", target_ip,
            "--port", str(bound_port), *common])
        subprocess.run(client, check=True, timeout=timeout)
        output, error = process.communicate(timeout=timeout)
        if process.returncode != 0:
            raise RuntimeError(f"TCP receiver failed ({process.returncode}): "
                               f"{error.decode(errors='replace')}")
        if output:
            raise RuntimeError("unexpected output after TCP readiness")
    finally:
        reap(process)
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    udp = commands.add_parser("udp-bound")
    udp.add_argument("--pid", type=int, required=True)
    udp.add_argument("--port", type=int, required=True)
    udp.add_argument("--timeout", type=float, default=5.0)
    for name in ("tcp", "_receive", "_send"):
        command = commands.add_parser(name)
        command.add_argument("--port", type=int, default=9000)
        command.add_argument("--payload", required=True)
        command.add_argument("--timeout", type=float, default=5.0)
        if name == "tcp":
            command.add_argument("--source-netns", required=True)
            command.add_argument("--target-netns", required=True)
            command.add_argument("--target-ip", required=True)
        if name == "_send":
            command.add_argument("--host", required=True)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("port or timeout is outside its allowed range")
    if args.command == "udp-bound":
        if args.port == 0:
            parser.error("UDP readiness requires a concrete port")
        wait_udp_bound(args.pid, args.port, args.timeout)
    elif args.command == "tcp":
        tcp_transfer(args.source_netns, args.target_netns, args.target_ip,
                     args.port, args.payload, args.timeout)
    elif args.command == "_receive":
        receive(args.port, args.payload, args.timeout)
    else:
        send(args.host, args.port, args.payload, args.timeout)


if __name__ == "__main__":
    main()
