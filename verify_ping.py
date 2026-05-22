#!/usr/bin/env python3
import argparse
import hashlib
import os
import selectors
import socket
import struct
import sys
import time


ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
MAGIC = b"vpng1\x00\x00\x00"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def expand(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out.extend(hashlib.sha256(seed + struct.pack("!I", counter)).digest())
        counter += 1
    return bytes(out[:size])


def make_payload(size, ident, seq, index, send_ns, run_nonce):
    prefix = MAGIC + struct.pack("!HHIQ16s", ident, seq, index, send_ns, run_nonce)
    if size <= len(prefix):
        return prefix[:size]
    filler = expand(prefix, size - len(prefix))
    return prefix + filler


def make_packet(ident, seq, payload):
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, 0, ident, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", ICMP_ECHO_REQUEST, 0, csum, ident, seq)
    return header + payload


def strip_ipv4_header(packet):
    if len(packet) >= 20 and packet[0] >> 4 == 4:
        header_len = (packet[0] & 0x0F) * 4
        if len(packet) >= header_len + 8:
            return packet[header_len:]
    return packet


def parse_reply(packet):
    icmp = strip_ipv4_header(packet)
    if len(icmp) < 8:
        return None
    typ, code, _csum, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    return typ, code, ident, seq, icmp[8:]


def fmt_bytes(value):
    units = ["B", "KB", "MB", "GB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024


def parse_args():
    parser = argparse.ArgumentParser(
        description="ICMP echo tester with unique payload verification per packet."
    )
    parser.add_argument("host", help="IPv4 destination")
    parser.add_argument("-c", "--count", type=int, default=3000, help="packet count")
    parser.add_argument("-i", "--interval", type=float, default=0.08, help="send interval in seconds")
    parser.add_argument("-s", "--size", type=int, default=1200, help="ICMP payload size in bytes")
    parser.add_argument("-W", "--timeout", type=float, default=3.0, help="seconds to wait after last send")
    parser.add_argument("--progress", type=int, default=100, help="print progress every N verified replies")
    parser.add_argument("-v", "--verbose", action="store_true", help="print every verified reply")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.count < 1:
        raise SystemExit("count must be positive")
    if args.count > 65535:
        raise SystemExit("count must be <= 65535 because ICMP sequence is 16-bit")
    if args.interval < 0:
        raise SystemExit("interval must be non-negative")
    if args.size < 0:
        raise SystemExit("size must be non-negative")

    dest_ip = socket.gethostbyname(args.host)
    ident = os.getpid() & 0xFFFF
    run_nonce = os.urandom(16)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        raise SystemExit("permission denied: run with sudo")

    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)

    pending = {}
    completed = {}
    bad = []
    unexpected = 0
    duplicates = 0
    sent = 0
    verified = 0
    next_send = time.monotonic()
    started = next_send
    last_send = None

    print(
        f"verify_ping {dest_ip}: {args.count} packets, {args.size} data bytes, "
        f"interval {args.interval}s, id 0x{ident:04x}"
    )

    while sent < args.count or pending:
        now = time.monotonic()

        while sent < args.count and now >= next_send:
            seq = (sent + 1) & 0xFFFF
            send_ns = time.monotonic_ns()
            payload = make_payload(args.size, ident, seq, sent + 1, send_ns, run_nonce)
            packet = make_packet(ident, seq, payload)
            sock.sendto(packet, (dest_ip, 0))

            pending[seq] = {
                "index": sent + 1,
                "hash": hashlib.sha256(payload).digest(),
                "size": len(payload),
                "sent_at": time.monotonic(),
            }
            sent += 1
            last_send = pending[seq]["sent_at"]
            next_send += args.interval
            now = time.monotonic()

        wait_until_send = max(0.0, next_send - now) if sent < args.count else args.timeout
        wait_until_timeout = args.timeout
        if pending and last_send is not None and sent >= args.count:
            wait_until_timeout = max(0.0, last_send + args.timeout - now)
        timeout = min(wait_until_send, wait_until_timeout, 0.2)

        events = selector.select(timeout)
        for _key, _mask in events:
            while True:
                try:
                    packet, src = sock.recvfrom(65535)
                except BlockingIOError:
                    break

                parsed = parse_reply(packet)
                if not parsed:
                    continue
                typ, code, reply_ident, seq, payload = parsed
                if typ != ICMP_ECHO_REPLY or code != 0 or reply_ident != ident:
                    continue

                rec = pending.get(seq)
                digest = hashlib.sha256(payload).digest()
                if rec is None:
                    old = completed.get(seq)
                    if old and old == digest:
                        duplicates += 1
                    else:
                        unexpected += 1
                    continue

                rtt_ms = (time.monotonic() - rec["sent_at"]) * 1000.0
                if len(payload) != rec["size"] or digest != rec["hash"]:
                    bad.append((rec["index"], seq, src[0], len(payload), rec["size"]))
                    del pending[seq]
                    continue

                verified += 1
                completed[seq] = digest
                del pending[seq]
                if args.verbose or (args.progress and verified % args.progress == 0):
                    print(f"ok={verified}/{args.count} seq={seq} from={src[0]} rtt={rtt_ms:.3f} ms")

        if sent >= args.count and pending and last_send is not None:
            if time.monotonic() - last_send >= args.timeout:
                break

    elapsed = time.monotonic() - started
    lost = len(pending)
    checked_bytes = verified * args.size

    print()
    print(f"--- {dest_ip} verified ping statistics ---")
    print(f"sent={sent} verified={verified} lost={lost} bad_payload={len(bad)} duplicates={duplicates} unexpected={unexpected}")
    print(f"checked_payload={fmt_bytes(checked_bytes)} elapsed={elapsed:.3f}s")

    if pending:
        missed = ", ".join(str(pending[seq]["index"]) for seq in sorted(pending)[:20])
        suffix = " ..." if len(pending) > 20 else ""
        print(f"missing request indexes: {missed}{suffix}")

    if bad:
        for index, seq, src, got_size, expected_size in bad[:20]:
            print(f"bad payload: index={index} seq={seq} from={src} got_size={got_size} expected_size={expected_size}")
        if len(bad) > 20:
            print(f"bad payload: ... {len(bad) - 20} more")

    return 0 if sent == verified and not pending and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
