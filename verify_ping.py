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


def make_payload(size, ident, stream, seq, index, send_ns, run_nonce):
    prefix = MAGIC + struct.pack("!HHHIQ16s", ident, stream, seq, index, send_ns, run_nonce)
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
    parser.add_argument("-c", "--count", type=int, default=3000, help="packet count per stream")
    parser.add_argument("-i", "--interval", type=float, default=0.08, help="send interval in seconds")
    parser.add_argument("-s", "--size", type=int, default=1200, help="ICMP payload size in bytes")
    parser.add_argument(
        "-P",
        "--parallel",
        "--threads",
        type=int,
        default=1,
        help="parallel measurement streams to run",
    )
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
    if args.parallel < 1:
        raise SystemExit("parallel must be positive")
    if args.parallel > 65535:
        raise SystemExit("parallel must be <= 65535 because ICMP identifiers are 16-bit")

    dest_ip = socket.gethostbyname(args.host)
    base_ident = os.getpid() & 0xFFFF

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        raise SystemExit("permission denied: run with sudo")

    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)

    streams = []
    used_idents = set()
    started = time.monotonic()
    for stream_no in range(1, args.parallel + 1):
        ident = (base_ident + stream_no - 1) & 0xFFFF
        if ident in used_idents:
            raise SystemExit("parallel produced duplicate ICMP identifiers")
        used_idents.add(ident)
        streams.append(
            {
                "stream": stream_no,
                "ident": ident,
                "nonce": os.urandom(16),
                "sent": 0,
                "verified": 0,
                "bad": 0,
                "next_send": started,
                "last_send": None,
            }
        )

    streams_by_ident = {stream["ident"]: stream for stream in streams}
    target_total = args.count * args.parallel
    pending = {}
    completed = {}
    bad = []
    unexpected = 0
    duplicates = 0
    sent_total = 0
    verified_total = 0

    def ident_range():
        if args.parallel == 1:
            return f"0x{streams[0]['ident']:04x}"
        if args.parallel <= 4:
            return ", ".join(f"0x{stream['ident']:04x}" for stream in streams)
        return f"0x{streams[0]['ident']:04x}..0x{streams[-1]['ident']:04x}"

    print(
        f"verify_ping {dest_ip}: {args.count} packets/stream, {args.parallel} streams, "
        f"{target_total} total packets, {args.size} data bytes, interval {args.interval}s, "
        f"ids {ident_range()}"
    )

    def send_one(stream):
        nonlocal sent_total

        seq = stream["sent"] + 1
        send_ns = time.monotonic_ns()
        payload = make_payload(
            args.size,
            stream["ident"],
            stream["stream"],
            seq,
            seq,
            send_ns,
            stream["nonce"],
        )
        packet = make_packet(stream["ident"], seq, payload)
        sock.sendto(packet, (dest_ip, 0))

        sent_at = time.monotonic()
        pending[(stream["ident"], seq)] = {
            "stream": stream["stream"],
            "index": seq,
            "hash": hashlib.sha256(payload).digest(),
            "size": len(payload),
            "sent_at": sent_at,
        }
        stream["sent"] += 1
        stream["last_send"] = sent_at
        stream["next_send"] += args.interval
        sent_total += 1

    while sent_total < target_total or pending:
        now = time.monotonic()

        sent_any = True
        while sent_any:
            sent_any = False
            for stream in streams:
                while stream["sent"] < args.count and now >= stream["next_send"]:
                    send_one(stream)
                    sent_any = True
                    now = time.monotonic()
                    if args.interval == 0:
                        break

        pending_send_times = [
            stream["next_send"] for stream in streams if stream["sent"] < args.count
        ]
        if pending_send_times:
            wait_until_send = max(0.0, min(pending_send_times) - now)
        else:
            wait_until_send = args.timeout

        timeout = min(wait_until_send, args.timeout, 0.2)
        if timeout == 0 and pending:
            timeout = 0.001

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
                if (
                    typ != ICMP_ECHO_REPLY
                    or code != 0
                    or reply_ident not in streams_by_ident
                ):
                    continue

                key = (reply_ident, seq)
                rec = pending.get(key)
                digest = hashlib.sha256(payload).digest()
                if rec is None:
                    old = completed.get(key)
                    if old and old == digest:
                        duplicates += 1
                    else:
                        unexpected += 1
                    continue

                rtt_ms = (time.monotonic() - rec["sent_at"]) * 1000.0
                if len(payload) != rec["size"] or digest != rec["hash"]:
                    streams_by_ident[reply_ident]["bad"] += 1
                    bad.append(
                        (
                            rec["stream"],
                            rec["index"],
                            seq,
                            src[0],
                            len(payload),
                            rec["size"],
                        )
                    )
                    del pending[key]
                    continue

                verified_total += 1
                streams_by_ident[reply_ident]["verified"] += 1
                completed[key] = digest
                del pending[key]
                if args.verbose or (args.progress and verified_total % args.progress == 0):
                    print(
                        f"ok={verified_total}/{target_total} stream={rec['stream']} "
                        f"seq={seq} from={src[0]} rtt={rtt_ms:.3f} ms"
                    )

        if sent_total >= target_total and pending:
            last_sent_times = [
                stream["last_send"] for stream in streams if stream["last_send"] is not None
            ]
            if last_sent_times and time.monotonic() - max(last_sent_times) >= args.timeout:
                break

    elapsed = time.monotonic() - started
    lost = len(pending)
    checked_bytes = verified_total * args.size

    print()
    print(f"--- {dest_ip} verified ping statistics ---")
    print(
        f"streams={args.parallel} count_per_stream={args.count} sent={sent_total} "
        f"verified={verified_total} lost={lost} bad_payload={len(bad)} "
        f"duplicates={duplicates} unexpected={unexpected}"
    )
    print(f"checked_payload={fmt_bytes(checked_bytes)} elapsed={elapsed:.3f}s")

    if args.parallel > 1:
        pending_by_stream = {stream["stream"]: 0 for stream in streams}
        for rec in pending.values():
            pending_by_stream[rec["stream"]] += 1
        for stream in streams:
            print(
                f"stream={stream['stream']} sent={stream['sent']} "
                f"verified={stream['verified']} lost={pending_by_stream[stream['stream']]} "
                f"bad_payload={stream['bad']}"
            )

    if pending:
        missed_items = sorted((rec["stream"], rec["index"]) for rec in pending.values())
        if args.parallel == 1:
            missed = ", ".join(str(index) for _stream, index in missed_items[:20])
        else:
            missed = ", ".join(f"{stream}:{index}" for stream, index in missed_items[:20])
        suffix = " ..." if len(pending) > 20 else ""
        print(f"missing request indexes: {missed}{suffix}")

    if bad:
        for stream, index, seq, src, got_size, expected_size in bad[:20]:
            print(
                f"bad payload: stream={stream} index={index} seq={seq} from={src} "
                f"got_size={got_size} expected_size={expected_size}"
            )
        if len(bad) > 20:
            print(f"bad payload: ... {len(bad) - 20} more")

    return 0 if sent_total == verified_total and not pending and not bad else 1


if __name__ == "__main__":
    sys.exit(main())
