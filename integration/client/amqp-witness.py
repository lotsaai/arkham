#!/usr/bin/env python3

import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

_FLOW_NAME = re.compile(
    r"^(?P<s0>\d{1,3})\.(?P<s1>\d{1,3})\.(?P<s2>\d{1,3})\.(?P<s3>\d{1,3})\.(?P<sp>\d+)"
    r"-"
    r"(?P<d0>\d{1,3})\.(?P<d1>\d{1,3})\.(?P<d2>\d{1,3})\.(?P<d3>\d{1,3})\.(?P<dp>\d+)$"
)


def pack(to_broker: bytes, to_client: bytes) -> bytes:
    return b"".join(
        (
            bytes((1,)),
            len(to_broker).to_bytes(4, "big"),
            to_broker,
            len(to_client).to_bytes(4, "big"),
            to_client,
        )
    )


def streams_from_tcpflow(flow_dir: str, port: int) -> tuple[bytes, bytes] | None:
    to_broker: list[bytes] = []
    to_client: list[bytes] = []
    try:
        names = os.listdir(flow_dir)
    except FileNotFoundError:
        return None
    for name in names:
        parsed = _FLOW_NAME.fullmatch(name)
        if parsed is None:
            continue
        src_port = int(parsed.group("sp"))
        dst_port = int(parsed.group("dp"))
        with open(os.path.join(flow_dir, name), "rb") as handle:
            payload = handle.read()
        if src_port == port and dst_port == port:
            return None
        if dst_port == port:
            to_broker.append(payload)
        elif src_port == port:
            to_client.append(payload)
        else:
            return None
    if len(to_broker) != 1 or len(to_client) != 1:
        print(
            f"amqp splice tcpflow unpaired files={sorted(names)} broker={len(to_broker)} client={len(to_client)}",
            file=sys.stderr,
        )
        return None
    return to_broker[0], to_client[0]


def next_armed(root: str) -> str | None:
    try:
        names = os.listdir(root)
    except FileNotFoundError:
        return None
    for name in sorted(names):
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if os.path.isfile(os.path.join(path, "arm")) and not os.path.isfile(os.path.join(path, "listening")):
            return path
    return None


def signal_listening(attempt: str) -> None:
    if not os.path.isdir(attempt):
        return
    fd = os.open(os.path.join(attempt, "listening"), os.O_CREAT | os.O_WRONLY, 0o644)
    os.close(fd)


def publish(attempt: str, body: bytes) -> None:
    if not os.path.isdir(attempt):
        return
    tmp = os.path.join(attempt, "done.tmp")
    final = os.path.join(attempt, "done")
    with open(tmp, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    if not os.path.isdir(attempt):
        return
    os.replace(tmp, final)


def flow_alive(proc: subprocess.Popen[bytes]) -> bool:
    deadline = time.monotonic() + 0.2
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        time.sleep(0.05)
    return proc.poll() is None


def stop_flow(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def wait_for_closed(attempt: str) -> bool:
    closed = os.path.join(attempt, "closed")
    while os.path.isdir(attempt):
        if os.path.isfile(closed):
            return True
        time.sleep(0.05)
    return False


def capture_one(attempt: str, port: int, port_text: str) -> None:
    try:
        with open(os.path.join(attempt, "arm"), "r", encoding="ascii") as handle:
            armed = handle.read()
    except FileNotFoundError:
        return
    if armed != port_text:
        signal_listening(attempt)
        publish(attempt, pack(b"", b""))
        return
    flow_dir = tempfile.mkdtemp(prefix="amqp-splice-")
    proc: subprocess.Popen[bytes] | None = None
    try:
        proc = subprocess.Popen(
            ["tcpflow", "-i", "any", "-o", flow_dir, "tcp", "port", str(port)],
            stdout=subprocess.DEVNULL,
        )
        if not flow_alive(proc):
            signal_listening(attempt)
            publish(attempt, pack(b"", b""))
            return
        signal_listening(attempt)
        if not wait_for_closed(attempt):
            return
        stop_flow(proc)
        proc = None
        if not os.path.isdir(attempt):
            return
        streams = streams_from_tcpflow(flow_dir, port)
        body = pack(b"", b"") if streams is None else pack(streams[0], streams[1])
        publish(attempt, body)
    finally:
        if proc is not None:
            stop_flow(proc)
        shutil.rmtree(flow_dir, ignore_errors=True)


def dial_once(port: int) -> None:
    with socket.create_connection(("127.0.0.1", port), timeout=5):
        return


def main() -> None:
    port_text = os.environ.get("AMQP_SPLICE_PORT", "")
    root = os.environ.get("AMQP_SPLICE_DIR", "")
    if port_text == "" or root == "":
        print("AMQP_SPLICE_PORT or AMQP_SPLICE_DIR is missing", file=sys.stderr)
        raise SystemExit(1)
    if not port_text.isascii() or not port_text.isdecimal():
        print("AMQP_SPLICE_PORT is not a port", file=sys.stderr)
        raise SystemExit(1)
    port = int(port_text)
    if port < 1 or port > 65535:
        print("AMQP_SPLICE_PORT is not a port", file=sys.stderr)
        raise SystemExit(1)
    try:
        dial_once(port)
    except OSError as err:
        print(f"amqp splice port dial failed: {err}", file=sys.stderr)
        raise SystemExit(1) from err
    os.makedirs(root, exist_ok=True)
    uid_text = os.environ.get("HOST_UID", "")
    gid_text = os.environ.get("HOST_GID", "") or uid_text
    if uid_text.isdecimal() and gid_text.isdecimal():
        os.chown(root, int(uid_text), int(gid_text))
    ready_tmp = os.path.join(root, "ready.tmp")
    with open(ready_tmp, "w", encoding="ascii") as handle:
        handle.write("ready\n")
    os.replace(ready_tmp, os.path.join(root, "ready"))
    while True:
        attempt = next_armed(root)
        if attempt is None:
            time.sleep(0.05)
            continue
        try:
            capture_one(attempt, port, port_text)
        except OSError as err:
            print(f"amqp splice capture failed: {err}", file=sys.stderr)
            if os.path.isdir(attempt) and not os.path.isfile(os.path.join(attempt, "done")):
                signal_listening(attempt)
                publish(attempt, pack(b"", b""))


if __name__ == "__main__":
    main()
