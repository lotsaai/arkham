#!/usr/bin/env python3

import os
import re
import select
import signal
import subprocess
import sys
import time

_FLOW = re.compile(r"^(?:\d{1,3}\.){4}(?P<sp>\d+)-(?:\d{1,3}\.){4}(?P<dp>\d+)$")


def note(path: str, text: str) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def iface() -> str:
    try:
        names = [name for name in os.listdir("/sys/class/net") if name != "lo"]
    except FileNotFoundError as err:
        raise RuntimeError(f"amqp splice iface lookup failed: {err}") from err
    if len(names) != 1:
        raise RuntimeError(f"amqp splice iface count {len(names)}: {names}")
    return names[0]


def flows(directory: str, port: int) -> tuple[str, str] | None:
    to_broker: list[str] = []
    to_client: list[str] = []
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return None
    for name in names:
        parsed = _FLOW.fullmatch(name)
        if parsed is None:
            continue
        if int(parsed.group("dp")) == port:
            to_broker.append(name)
        elif int(parsed.group("sp")) == port:
            to_client.append(name)
    if len(to_broker) != 1 or len(to_client) != 1:
        return None
    return to_broker[0], to_client[0]


def drain(proc: subprocess.Popen[bytes], timeout: float) -> bytes:
    stderr = proc.stderr
    if stderr is None:
        return b""
    ready, _, _ = select.select([stderr], [], [], timeout)
    if not ready:
        return b""
    try:
        return os.read(stderr.fileno(), 65536)
    except OSError:
        return b""


def stop(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def capture(attempt: str, port: int, dev: str) -> None:
    proc = subprocess.Popen(
        ["tcpflow", "-p", "-i", dev, "-o", attempt, "tcp", "port", str(port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        banner = b""
        heard = time.monotonic() + 5
        while time.monotonic() < heard and b"listening on " not in banner:
            if proc.poll() is not None:
                break
            banner += drain(proc, 0.2)
        if b"listening on " not in banner:
            note(os.path.join(attempt, "error"), "amqp splice tcpflow not listening\n")
            return
        note(os.path.join(attempt, "listening"), "")
        end = time.monotonic() + 20
        last: tuple[str, str, int, int] | None = None
        stable = 0
        found: tuple[str, str] | None = None
        while time.monotonic() < end and os.path.isdir(attempt):
            drain(proc, 0)
            if not os.path.isfile(os.path.join(attempt, "closed")):
                time.sleep(0.05)
                continue
            seen = flows(attempt, port)
            if seen is None:
                last = None
                stable = 0
                time.sleep(0.05)
                continue
            try:
                sizes = (
                    os.path.getsize(os.path.join(attempt, seen[0])),
                    os.path.getsize(os.path.join(attempt, seen[1])),
                )
            except OSError:
                last = None
                stable = 0
                time.sleep(0.05)
                continue
            current = (seen[0], seen[1], sizes[0], sizes[1])
            if sizes[0] > 0 and sizes[1] > 0 and current == last:
                stable += 1
                if stable >= 3:
                    found = seen
                    break
            else:
                last = current
                stable = 0
            time.sleep(0.05)
        if found is None:
            if os.path.isdir(attempt):
                note(os.path.join(attempt, "error"), "amqp splice flow pairing failed\n")
            return
        note(os.path.join(attempt, "done"), f"{found[0]}\n{found[1]}\n")
    finally:
        stop(proc)


def pending(root: str) -> str | None:
    try:
        names = sorted(os.listdir(root))
    except FileNotFoundError:
        return None
    for name in names:
        path = os.path.join(root, name)
        if not os.path.isdir(path):
            continue
        if os.path.isfile(os.path.join(path, "listening")) or os.path.isfile(os.path.join(path, "error")):
            continue
        return path
    return None


def main() -> None:
    port_text = os.environ.get("AMQP_SPLICE_PORT", "")
    root = os.environ.get("AMQP_SPLICE_DIR", "")
    if not port_text.isdecimal() or not 1 <= int(port_text) <= 65535 or root == "":
        print("AMQP_SPLICE_PORT or AMQP_SPLICE_DIR is invalid", file=sys.stderr)
        raise SystemExit(1)
    port = int(port_text)
    fault = ""
    dev = ""
    try:
        dev = iface()
    except RuntimeError as err:
        fault = str(err)
    os.makedirs(root, exist_ok=True)
    uid = os.environ.get("HOST_UID", "")
    gid = os.environ.get("HOST_GID", "") or uid
    if uid.isdecimal() and gid.isdecimal():
        os.chown(root, int(uid), int(gid))
    note(os.path.join(root, "ready"), "")
    while True:
        attempt = pending(root)
        if attempt is None:
            time.sleep(0.05)
            continue
        if fault != "":
            note(os.path.join(attempt, "error"), fault + "\n")
            continue
        try:
            capture(attempt, port, dev)
        except OSError as err:
            if os.path.isdir(attempt):
                note(os.path.join(attempt, "error"), f"amqp splice capture failed: {err}\n")


if __name__ == "__main__":
    main()
