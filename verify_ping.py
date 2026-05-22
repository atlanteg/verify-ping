#!/usr/bin/env python3
import argparse
import hashlib
import os
import random
import selectors
import socket
import struct
import sys
import time


ICMP_ECHO_REPLY = 0
ICMP_ECHO_REQUEST = 8
MAGIC = b"vpng2\x00\x00\x00"
PAYLOAD_HEADER = "!HHHIQ16s"
PAYLOAD_HEADER_SIZE = len(MAGIC) + struct.calcsize(PAYLOAD_HEADER)
TCP_FRAME_HEADER_SIZE = 4
UDP_MAX_PAYLOAD = 65507


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
    prefix = MAGIC + struct.pack(PAYLOAD_HEADER, ident, stream, seq, index, send_ns, run_nonce)
    if size <= len(prefix):
        return prefix[:size]
    return prefix + expand(prefix, size - len(prefix))


def parse_payload(payload):
    if len(payload) < PAYLOAD_HEADER_SIZE or not payload.startswith(MAGIC):
        return None
    start = len(MAGIC)
    ident, stream, seq, index, send_ns, nonce = struct.unpack(
        PAYLOAD_HEADER, payload[start:PAYLOAD_HEADER_SIZE]
    )
    return {
        "ident": ident,
        "stream": stream,
        "seq": seq,
        "index": index,
        "send_ns": send_ns,
        "nonce": nonce,
    }


def make_icmp_packet(ident, seq, payload):
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


def parse_icmp_reply(packet):
    icmp = strip_ipv4_header(packet)
    if len(icmp) < 8:
        return None
    typ, code, _csum, ident, seq = struct.unpack("!BBHHH", icmp[:8])
    return typ, code, ident, seq, icmp[8:]


def fmt_bytes(value):
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{value}B"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Payload-verifying ICMP/UDP/TCP echo tester."
    )
    parser.add_argument("host", nargs="?", help="destination host for client mode")
    parser.add_argument(
        "--protocol",
        choices=("icmp", "udp", "tcp"),
        default="icmp",
        help="transport to test",
    )
    parser.add_argument(
        "--server",
        "--listen",
        action="store_true",
        help="run UDP/TCP echo server instead of a client",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="server bind address for UDP/TCP",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,
        help="UDP/TCP port; server uses a random free port when omitted",
    )
    parser.add_argument("-c", "--count", type=int, default=3000, help="packet count per stream")
    parser.add_argument("-i", "--interval", type=float, default=0.08, help="send interval in seconds")
    parser.add_argument("-s", "--size", type=int, default=1200, help="payload size in bytes")
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


def validate_args(args):
    if args.server and args.protocol == "icmp":
        raise SystemExit("ICMP echo replies are provided by the OS; --server is only for UDP/TCP")
    if not args.server and not args.host:
        raise SystemExit("host is required in client mode")
    if args.count < 1:
        raise SystemExit("count must be positive")
    if args.count > 65535:
        raise SystemExit("count must be <= 65535 because sequence numbers are 16-bit")
    if args.interval < 0:
        raise SystemExit("interval must be non-negative")
    if args.size < 0:
        raise SystemExit("size must be non-negative")
    if not args.server and args.size < PAYLOAD_HEADER_SIZE:
        raise SystemExit(f"payload size must be at least {PAYLOAD_HEADER_SIZE} bytes")
    if not args.server and args.protocol == "udp" and args.size > UDP_MAX_PAYLOAD:
        raise SystemExit(f"udp payload size must be <= {UDP_MAX_PAYLOAD} bytes")
    if args.parallel < 1:
        raise SystemExit("parallel must be positive")
    if args.parallel > 65535:
        raise SystemExit("parallel must be <= 65535 because identifiers are 16-bit")
    if args.port is not None and not (1 <= args.port <= 65535):
        raise SystemExit("port must be between 1 and 65535")

    if args.protocol in ("udp", "tcp") and not args.server and args.port is None:
        args.port = random.randint(49152, 65535)
        print(f"no --port provided; picked random destination port {args.port}")


def build_streams(args):
    base_ident = os.getpid() & 0xFFFF
    started = time.monotonic()
    streams = []
    used_idents = set()

    for stream_no in range(1, args.parallel + 1):
        ident = (base_ident + stream_no - 1) & 0xFFFF
        if ident in used_idents:
            raise SystemExit("parallel produced duplicate identifiers")
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
                "sock": None,
                "out": bytearray(),
                "in": bytearray(),
                "closed": False,
            }
        )

    return streams, started


def ident_range(streams):
    if len(streams) == 1:
        return f"0x{streams[0]['ident']:04x}"
    if len(streams) <= 4:
        return ", ".join(f"0x{stream['ident']:04x}" for stream in streams)
    return f"0x{streams[0]['ident']:04x}..0x{streams[-1]['ident']:04x}"


def print_client_header(args, dest_ip, streams):
    target_total = args.count * args.parallel
    endpoint = dest_ip if args.protocol == "icmp" else f"{dest_ip}:{args.port}"
    print(
        f"verify_ping {args.protocol} {endpoint}: {args.count} packets/stream, "
        f"{args.parallel} streams, {target_total} total packets, {args.size} data bytes, "
        f"interval {args.interval}s, ids {ident_range(streams)}"
    )


def print_client_stats(args, dest_ip, started, streams, pending, bad, duplicates, unexpected):
    sent_total = sum(stream["sent"] for stream in streams)
    verified_total = sum(stream["verified"] for stream in streams)
    lost = len(pending)
    checked_bytes = verified_total * args.size
    elapsed = time.monotonic() - started

    endpoint = dest_ip if args.protocol == "icmp" else f"{dest_ip}:{args.port}"
    print()
    print(f"--- {endpoint} verified {args.protocol} statistics ---")
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
        for item in bad[:20]:
            print(
                f"bad payload: stream={item['stream']} index={item['index']} "
                f"seq={item['seq']} from={item['from']} got_size={item['got_size']} "
                f"expected_size={item['expected_size']}"
            )
        if len(bad) > 20:
            print(f"bad payload: ... {len(bad) - 20} more")

    return 0 if sent_total == verified_total and not pending and not bad else 1


def make_stream_payload(args, stream):
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
    return seq, payload


def record_pending(pending, stream, seq, payload, interval):
    pending[(stream["ident"], seq)] = {
        "stream": stream["stream"],
        "ident": stream["ident"],
        "seq": seq,
        "index": seq,
        "hash": hashlib.sha256(payload).digest(),
        "size": len(payload),
        "sent_at": time.monotonic(),
    }
    stream["sent"] += 1
    stream["last_send"] = pending[(stream["ident"], seq)]["sent_at"]
    stream["next_send"] += interval


def verify_payload(payload, source, streams_by_ident, pending, completed, bad):
    parsed = parse_payload(payload)
    if not parsed or parsed["ident"] not in streams_by_ident:
        return "unexpected"

    key = (parsed["ident"], parsed["seq"])
    rec = pending.get(key)
    digest = hashlib.sha256(payload).digest()
    if rec is None:
        return "duplicate" if completed.get(key) == digest else "unexpected"

    stream = streams_by_ident[parsed["ident"]]
    if (
        parsed["stream"] != rec["stream"]
        or len(payload) != rec["size"]
        or digest != rec["hash"]
    ):
        stream["bad"] += 1
        bad.append(
            {
                "stream": rec["stream"],
                "index": rec["index"],
                "seq": parsed["seq"],
                "from": source,
                "got_size": len(payload),
                "expected_size": rec["size"],
            }
        )
        del pending[key]
        return "bad"

    rtt_ms = (time.monotonic() - rec["sent_at"]) * 1000.0
    stream["verified"] += 1
    completed[key] = digest
    del pending[key]
    return "ok", rec, rtt_ms


def next_send_wait(streams, count, now, timeout):
    pending_send_times = [stream["next_send"] for stream in streams if stream["sent"] < count]
    if not pending_send_times:
        return timeout
    return max(0.0, min(pending_send_times) - now)


def should_stop_waiting(args, streams, pending, target_total):
    sent_total = sum(stream["sent"] for stream in streams)
    if sent_total < target_total or not pending:
        return False
    last_sent_times = [stream["last_send"] for stream in streams if stream["last_send"] is not None]
    return bool(last_sent_times) and time.monotonic() - max(last_sent_times) >= args.timeout


def run_icmp_client(args, dest_ip):
    streams, started = build_streams(args)
    streams_by_ident = {stream["ident"]: stream for stream in streams}
    target_total = args.count * args.parallel
    pending = {}
    completed = {}
    bad = []
    duplicates = 0
    unexpected = 0
    verified_total = 0

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        raise SystemExit("permission denied: run with sudo")

    sock.setblocking(False)
    selector = selectors.DefaultSelector()
    selector.register(sock, selectors.EVENT_READ)
    print_client_header(args, dest_ip, streams)

    while sum(stream["sent"] for stream in streams) < target_total or pending:
        now = time.monotonic()
        for stream in streams:
            while stream["sent"] < args.count and now >= stream["next_send"]:
                seq, payload = make_stream_payload(args, stream)
                packet = make_icmp_packet(stream["ident"], seq, payload)
                sock.sendto(packet, (dest_ip, 0))
                record_pending(pending, stream, seq, payload, args.interval)
                now = time.monotonic()

        timeout = min(next_send_wait(streams, args.count, time.monotonic(), args.timeout), args.timeout, 0.2)
        if timeout == 0 and pending:
            timeout = 0.001

        events = selector.select(timeout)
        for _key, _mask in events:
            while True:
                try:
                    packet, src = sock.recvfrom(65535)
                except BlockingIOError:
                    break

                parsed = parse_icmp_reply(packet)
                if not parsed:
                    continue
                typ, code, reply_ident, seq, payload = parsed
                if typ != ICMP_ECHO_REPLY or code != 0 or reply_ident not in streams_by_ident:
                    continue

                result = verify_payload(payload, src[0], streams_by_ident, pending, completed, bad)
                if result == "duplicate":
                    duplicates += 1
                elif result == "unexpected":
                    unexpected += 1
                elif result != "bad":
                    verified_total += 1
                    _state, rec, rtt_ms = result
                    if args.verbose or (args.progress and verified_total % args.progress == 0):
                        print(
                            f"ok={verified_total}/{target_total} stream={rec['stream']} "
                            f"seq={seq} from={src[0]} rtt={rtt_ms:.3f} ms"
                        )

        if should_stop_waiting(args, streams, pending, target_total):
            break

    return print_client_stats(args, dest_ip, started, streams, pending, bad, duplicates, unexpected)


def run_udp_client(args, dest_ip):
    streams, started = build_streams(args)
    streams_by_ident = {stream["ident"]: stream for stream in streams}
    target_total = args.count * args.parallel
    pending = {}
    completed = {}
    bad = []
    duplicates = 0
    unexpected = 0
    verified_total = 0

    selector = selectors.DefaultSelector()
    socket_to_stream = {}
    for stream in streams:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((dest_ip, args.port))
        except OSError as exc:
            raise SystemExit(f"udp connect to {dest_ip}:{args.port} failed: {exc}") from exc
        sock.setblocking(False)
        stream["sock"] = sock
        socket_to_stream[sock.fileno()] = stream
        selector.register(sock, selectors.EVENT_READ)

    print_client_header(args, dest_ip, streams)

    while sum(stream["sent"] for stream in streams) < target_total or pending:
        now = time.monotonic()
        for stream in streams:
            while stream["sent"] < args.count and now >= stream["next_send"]:
                seq, payload = make_stream_payload(args, stream)
                try:
                    stream["sock"].send(payload)
                except OSError:
                    pass
                record_pending(pending, stream, seq, payload, args.interval)
                now = time.monotonic()

        timeout = min(next_send_wait(streams, args.count, time.monotonic(), args.timeout), args.timeout, 0.2)
        if timeout == 0 and pending:
            timeout = 0.001

        events = selector.select(timeout)
        for key, _mask in events:
            stream = socket_to_stream[key.fileobj.fileno()]
            while True:
                try:
                    payload = key.fileobj.recv(UDP_MAX_PAYLOAD)
                except BlockingIOError:
                    break
                except OSError:
                    break

                result = verify_payload(
                    payload,
                    f"{dest_ip}:{args.port}",
                    streams_by_ident,
                    pending,
                    completed,
                    bad,
                )
                if result == "duplicate":
                    duplicates += 1
                elif result == "unexpected":
                    unexpected += 1
                elif result != "bad":
                    verified_total += 1
                    _state, rec, rtt_ms = result
                    if args.verbose or (args.progress and verified_total % args.progress == 0):
                        print(
                            f"ok={verified_total}/{target_total} stream={rec['stream']} "
                            f"seq={rec['seq']} from={dest_ip}:{args.port} rtt={rtt_ms:.3f} ms"
                        )

        if should_stop_waiting(args, streams, pending, target_total):
            break

    for stream in streams:
        stream["sock"].close()

    return print_client_stats(args, dest_ip, started, streams, pending, bad, duplicates, unexpected)


def run_tcp_client(args, dest_ip):
    streams, started = build_streams(args)
    streams_by_ident = {stream["ident"]: stream for stream in streams}
    target_total = args.count * args.parallel
    pending = {}
    completed = {}
    bad = []
    duplicates = 0
    unexpected = 0
    verified_total = 0

    selector = selectors.DefaultSelector()
    socket_to_stream = {}
    for stream in streams:
        try:
            sock = socket.create_connection((dest_ip, args.port), timeout=args.timeout)
        except OSError as exc:
            raise SystemExit(f"tcp connect to {dest_ip}:{args.port} failed: {exc}") from exc
        sock.setblocking(False)
        stream["sock"] = sock
        socket_to_stream[sock.fileno()] = stream
        selector.register(sock, selectors.EVENT_READ)

    print_client_header(args, dest_ip, streams)

    while sum(stream["sent"] for stream in streams) < target_total or pending:
        now = time.monotonic()
        for stream in streams:
            while stream["sent"] < args.count and now >= stream["next_send"]:
                seq, payload = make_stream_payload(args, stream)
                frame = struct.pack("!I", len(payload)) + payload
                stream["out"].extend(frame)
                record_pending(pending, stream, seq, payload, args.interval)
                selector.modify(stream["sock"], selectors.EVENT_READ | selectors.EVENT_WRITE)
                now = time.monotonic()

        timeout = min(next_send_wait(streams, args.count, time.monotonic(), args.timeout), args.timeout, 0.2)
        if timeout == 0 and pending:
            timeout = 0.001

        events = selector.select(timeout)
        for key, mask in events:
            sock = key.fileobj
            stream = socket_to_stream[sock.fileno()]

            if mask & selectors.EVENT_WRITE and stream["out"]:
                try:
                    sent = sock.send(stream["out"])
                    del stream["out"][:sent]
                except BlockingIOError:
                    pass
                if not stream["out"]:
                    selector.modify(sock, selectors.EVENT_READ)

            if mask & selectors.EVENT_READ:
                try:
                    chunk = sock.recv(65535)
                except BlockingIOError:
                    chunk = None
                if chunk == b"":
                    stream["closed"] = True
                    selector.unregister(sock)
                    sock.close()
                    continue
                if chunk:
                    stream["in"].extend(chunk)
                    while len(stream["in"]) >= TCP_FRAME_HEADER_SIZE:
                        length = struct.unpack("!I", stream["in"][:TCP_FRAME_HEADER_SIZE])[0]
                        if len(stream["in"]) < TCP_FRAME_HEADER_SIZE + length:
                            break
                        payload = bytes(
                            stream["in"][TCP_FRAME_HEADER_SIZE:TCP_FRAME_HEADER_SIZE + length]
                        )
                        del stream["in"][:TCP_FRAME_HEADER_SIZE + length]

                        result = verify_payload(
                            payload,
                            f"{dest_ip}:{args.port}",
                            streams_by_ident,
                            pending,
                            completed,
                            bad,
                        )
                        if result == "duplicate":
                            duplicates += 1
                        elif result == "unexpected":
                            unexpected += 1
                        elif result != "bad":
                            verified_total += 1
                            _state, rec, rtt_ms = result
                            if args.verbose or (args.progress and verified_total % args.progress == 0):
                                print(
                                    f"ok={verified_total}/{target_total} stream={rec['stream']} "
                                    f"seq={rec['seq']} from={dest_ip}:{args.port} rtt={rtt_ms:.3f} ms"
                                )

        if should_stop_waiting(args, streams, pending, target_total):
            break

    for stream in streams:
        sock = stream["sock"]
        if sock and not stream["closed"]:
            selector.unregister(sock)
            sock.close()

    return print_client_stats(args, dest_ip, started, streams, pending, bad, duplicates, unexpected)


def run_udp_server(args):
    port = args.port or 0
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((args.bind, port))
    except OSError as exc:
        raise SystemExit(f"udp bind to {args.bind}:{port} failed: {exc}") from exc
    actual_host, actual_port = sock.getsockname()
    print(f"verify_ping udp echo server listening on {actual_host}:{actual_port}", flush=True)

    try:
        while True:
            data, addr = sock.recvfrom(UDP_MAX_PAYLOAD)
            if data:
                sock.sendto(data, addr)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        sock.close()

    return 0


def run_tcp_server(args):
    port = args.port or 0
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((args.bind, port))
    except OSError as exc:
        raise SystemExit(f"tcp bind to {args.bind}:{port} failed: {exc}") from exc
    server.listen()
    server.setblocking(False)
    actual_host, actual_port = server.getsockname()
    print(f"verify_ping tcp echo server listening on {actual_host}:{actual_port}", flush=True)

    selector = selectors.DefaultSelector()
    selector.register(server, selectors.EVENT_READ, None)
    buffers = {}

    try:
        while True:
            for key, mask in selector.select(1.0):
                if key.data is None:
                    conn, _addr = server.accept()
                    conn.setblocking(False)
                    buffers[conn.fileno()] = bytearray()
                    selector.register(conn, selectors.EVENT_READ, conn.fileno())
                    continue

                conn = key.fileobj
                fileno = key.data
                if mask & selectors.EVENT_READ:
                    try:
                        data = conn.recv(65535)
                    except ConnectionResetError:
                        data = b""
                    if not data:
                        selector.unregister(conn)
                        buffers.pop(fileno, None)
                        conn.close()
                        continue
                    buffers[fileno].extend(data)
                    selector.modify(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, fileno)

                if mask & selectors.EVENT_WRITE and buffers.get(fileno):
                    try:
                        sent = conn.send(buffers[fileno])
                    except (BrokenPipeError, ConnectionResetError):
                        selector.unregister(conn)
                        buffers.pop(fileno, None)
                        conn.close()
                        continue
                    del buffers[fileno][:sent]
                    if not buffers[fileno]:
                        selector.modify(conn, selectors.EVENT_READ, fileno)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        for key in list(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()

    return 0


def main():
    args = parse_args()
    validate_args(args)

    if args.server:
        if args.protocol == "udp":
            return run_udp_server(args)
        return run_tcp_server(args)

    dest_ip = socket.gethostbyname(args.host)
    if args.protocol == "icmp":
        return run_icmp_client(args, dest_ip)
    if args.protocol == "udp":
        return run_udp_client(args, dest_ip)
    return run_tcp_client(args, dest_ip)


if __name__ == "__main__":
    sys.exit(main())
