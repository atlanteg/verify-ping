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
MAGIC = b"vpng3\x00\x00\x00"
# Client-owned header: ident, stream, seq, index, send_ns, run_nonce.
PAYLOAD_HEADER = "!HHHIQ16s"
CLIENT_HEADER_SIZE = len(MAGIC) + struct.calcsize(PAYLOAD_HEADER)
# Server-owned stamp, written by the echo server into every reply:
#   rseq   -- per-stream monotonic receive counter (server arrival order)
#   recv_ns-- server receive timestamp (reserved for one-way delay use)
# The client always sends this region zeroed; it is normalized back to zero
# before payload verification, so SHA-256 still covers the whole packet.
STAMP_FMT = "!IQ"
STAMP_SIZE = struct.calcsize(STAMP_FMT)
STAMP_OFFSET = CLIENT_HEADER_SIZE
STAMP_END = STAMP_OFFSET + STAMP_SIZE
PAYLOAD_HEADER_SIZE = STAMP_END
# In-band control: after the run the client pulls the server's per-stream
# arrival log over the SAME socket/port the test used (so it crosses the same
# firewall hole and NAT mapping). The data path is lossy, so the log is served
# as independent, idempotent chunks that the client re-requests until it has
# them all (selective-repeat pull ARQ). The server stays stateless.
CTRL_MAGIC = b"vpnc3\x00\x00\x00"
CTRL_REQ_FMT = "!16sH"      # nonce, chunk index
CTRL_REP_FMT = "!16sHHI"    # nonce, chunk index, total chunks, total entries
CTRL_REQ_SIZE = len(CTRL_MAGIC) + struct.calcsize(CTRL_REQ_FMT)
CTRL_REP_SIZE = len(CTRL_MAGIC) + struct.calcsize(CTRL_REP_FMT)
CTRL_CHUNK_SEQS = 512       # 2 bytes each -> ~1 KB chunk, no IP fragmentation
CTRL_WINDOW = 64            # outstanding chunk requests per round
CTRL_ROUND_WAIT = 0.25      # seconds to collect replies per round
CONTROL_PROTOCOLS = ("udp", "tcp")
IPV4_HEADER_SIZE = 20
RAW_TCP_HEADER_SIZE = 20
RAW_TCP_MAX_PAYLOAD = 65535 - IPV4_HEADER_SIZE - RAW_TCP_HEADER_SIZE
TCP_FRAME_HEADER_SIZE = 4
UDP_MAX_PAYLOAD = 65507
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


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
    # Client header followed by a zeroed server stamp; the deterministic
    # filler is derived from the whole prefix so every packet is unique.
    prefix = (
        MAGIC
        + struct.pack(PAYLOAD_HEADER, ident, stream, seq, index, send_ns, run_nonce)
        + bytes(STAMP_SIZE)
    )
    if size <= len(prefix):
        return prefix[:size]
    return prefix + expand(prefix, size - len(prefix))


def parse_payload(payload):
    if len(payload) < PAYLOAD_HEADER_SIZE or not payload.startswith(MAGIC):
        return None
    start = len(MAGIC)
    ident, stream, seq, index, send_ns, nonce = struct.unpack(
        PAYLOAD_HEADER, payload[start:CLIENT_HEADER_SIZE]
    )
    rseq, recv_ns = struct.unpack_from(STAMP_FMT, payload, STAMP_OFFSET)
    return {
        "ident": ident,
        "stream": stream,
        "seq": seq,
        "index": index,
        "send_ns": send_ns,
        "nonce": nonce,
        "rseq": rseq,
        "recv_ns": recv_ns,
    }


def stamp_payload(payload, rseq, recv_ns):
    """Return a copy of payload with the server stamp filled in."""
    buf = bytearray(payload)
    struct.pack_into(STAMP_FMT, buf, STAMP_OFFSET, rseq & 0xFFFFFFFF, recv_ns & 0xFFFFFFFFFFFFFFFF)
    return bytes(buf)


def normalize_payload(payload):
    """Return payload with the server stamp zeroed, as the client sent it."""
    if len(payload) < STAMP_END:
        return payload
    buf = bytearray(payload)
    struct.pack_into(STAMP_FMT, buf, STAMP_OFFSET, 0, 0)
    return bytes(buf)


def count_reordered(keys):
    """RFC 4737 style late-arrival count: entries below the running maximum."""
    reordered = 0
    run_max = None
    for key in keys:
        if run_max is not None and key < run_max:
            reordered += 1
        else:
            run_max = key
    return reordered


class ArrivalLog:
    """Server-side per-stream arrival accounting, keyed by run nonce."""

    def __init__(self):
        self.arrivals = {}

    def record(self, nonce, seq):
        log = self.arrivals.setdefault(nonce, [])
        log.append(seq)
        return len(log)

    def chunk(self, nonce, index):
        """Return (total_chunks, total_entries, seqs) for one chunk of a log."""
        log = self.arrivals.get(nonce, [])
        total = len(log)
        total_chunks = max(1, (total + CTRL_CHUNK_SEQS - 1) // CTRL_CHUNK_SEQS)
        start = index * CTRL_CHUNK_SEQS
        return total_chunks, total, log[start:start + CTRL_CHUNK_SEQS]


class ServerProgress:
    """Once-a-second receive summary on the server so the far end shows life.

    Prints only while packets are arriving, plus one line when a burst ends,
    so an idle server does not spam its log.
    """

    def __init__(self, enabled):
        self.enabled = enabled
        self.next_tick = time.monotonic() + 1.0
        self.window = 0
        self.total = 0
        self.streams = set()
        self.clients = set()
        self.active = False

    def add(self, nonce, client_ip):
        self.window += 1
        self.total += 1
        self.streams.add(nonce)
        self.clients.add(client_ip)

    def tick(self):
        if not self.enabled:
            return
        now = time.monotonic()
        if now < self.next_tick:
            return
        self.next_tick = now + 1.0
        stamp = time.strftime("%H:%M:%S")
        if self.window:
            self.active = True
            print(
                f"[{stamp}] rx={self.window} pkt/s streams={len(self.streams)} "
                f"clients={len(self.clients)} total={self.total}",
                flush=True,
            )
        elif self.active:
            self.active = False
            print(f"[{stamp}] idle, total received {self.total}", flush=True)
            self.streams.clear()
            self.clients.clear()
        self.window = 0


def make_ctrl_request(nonce, index):
    return CTRL_MAGIC + struct.pack(CTRL_REQ_FMT, nonce, index)


def parse_ctrl_request(data):
    if len(data) != CTRL_REQ_SIZE or not data.startswith(CTRL_MAGIC):
        return None
    nonce, index = struct.unpack_from(CTRL_REQ_FMT, data, len(CTRL_MAGIC))
    return nonce, index


def make_ctrl_reply(nonce, index, total_chunks, total_entries, seqs):
    return (
        CTRL_MAGIC
        + struct.pack(CTRL_REP_FMT, nonce, index, total_chunks, total_entries)
        + struct.pack(f"!{len(seqs)}H", *seqs)
    )


def parse_ctrl_reply(data):
    if len(data) < CTRL_REP_SIZE or not data.startswith(CTRL_MAGIC):
        return None
    nonce, index, total_chunks, total_entries = struct.unpack_from(
        CTRL_REP_FMT, data, len(CTRL_MAGIC)
    )
    body = data[CTRL_REP_SIZE:]
    if len(body) % 2:
        return None
    return {
        "nonce": nonce,
        "index": index,
        "total_chunks": total_chunks,
        "total_entries": total_entries,
        "seqs": list(struct.unpack(f"!{len(body) // 2}H", body)),
    }


def serve_ctrl_request(arrival_log, data):
    """Server side: answer one in-band chunk request, or None if not one."""
    request = parse_ctrl_request(data)
    if request is None:
        return None
    nonce, index = request
    total_chunks, total_entries, seqs = arrival_log.chunk(nonce, index)
    return make_ctrl_reply(nonce, index, total_chunks, total_entries, seqs)


def fetch_arrival_logs(args, streams, send_request, recv_replies):
    """Client side: pull each stream's arrival log over the data path.

    send_request(carrier, data) sends one control datagram on the carrier
    stream's socket/port; recv_replies(timeout) returns raw control payloads
    received meanwhile. Chunks are independent, so lost ones are simply
    requested again. The server keys logs by nonce, not by port, so after the
    first round a stream whose own port is blocked is retried through the
    other streams' sockets; that is how a firewalled port still gets its
    "nothing reached the server" verdict.
    Returns {stream_no: [seqs in server arrival order] or None if unavailable}.
    """
    states = {
        stream["nonce"]: {
            "stream": stream,
            "total_chunks": None,
            "total": None,
            "chunks": {},
            "attempt": 0,
        }
        for stream in streams
    }
    deadline = time.monotonic() + max(10.0, args.timeout * 3)

    while time.monotonic() < deadline:
        wanted = []
        for state in states.values():
            if state["total_chunks"] is None:
                wanted.append((state, 0))
            else:
                wanted.extend(
                    (state, index)
                    for index in range(state["total_chunks"])
                    if index not in state["chunks"]
                )
        if not wanted:
            break

        for state, index in wanted[:CTRL_WINDOW]:
            stream = state["stream"]
            position = streams.index(stream)
            carrier = streams[(position + state["attempt"]) % len(streams)]
            try:
                send_request(carrier, make_ctrl_request(stream["nonce"], index))
            except OSError:
                pass
        for state, _index in wanted:
            state["attempt"] += 1

        for data in recv_replies(CTRL_ROUND_WAIT):
            reply = parse_ctrl_reply(data)
            if reply is None:
                continue
            state = states.get(reply["nonce"])
            if state is None:
                continue
            # A log that changed size between chunks (late arrivals) would be
            # inconsistent; start that stream over rather than mix snapshots.
            if state["total_chunks"] is not None and (
                state["total_chunks"] != reply["total_chunks"]
                or state["total"] != reply["total_entries"]
            ):
                state["chunks"].clear()
            state["total_chunks"] = reply["total_chunks"]
            state["total"] = reply["total_entries"]
            if reply["index"] < reply["total_chunks"]:
                state["chunks"][reply["index"]] = reply["seqs"]

    logs = {}
    incomplete = []
    for state in states.values():
        stream_no = state["stream"]["stream"]
        if state["total_chunks"] is None or len(state["chunks"]) != state["total_chunks"]:
            logs[stream_no] = None
            incomplete.append(stream_no)
        else:
            logs[stream_no] = [
                seq for index in range(state["total_chunks"]) for seq in state["chunks"][index]
            ]

    if len(incomplete) == len(streams):
        print(
            "control: arrival log fetch failed for every stream "
            "(old server, no path to it, or data path too lossy); directional stats unavailable"
        )
        return None
    if incomplete:
        labels = ", ".join(str(item) for item in incomplete)
        print(f"control: arrival log fetch incomplete for stream(s) {labels}; shown as unavailable")
    return logs


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


def route_source_ip(dest_ip):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((dest_ip, 9))
        return sock.getsockname()[0]
    finally:
        sock.close()


def make_ipv4_header(src_ip, dest_ip, protocol, body_len):
    version_ihl = (4 << 4) | 5
    total_len = IPV4_HEADER_SIZE + body_len
    packet_id = random.randint(0, 0xFFFF)
    flags_fragment = 0
    ttl = 64
    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        packet_id,
        flags_fragment,
        ttl,
        protocol,
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )
    csum = checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_len,
        packet_id,
        flags_fragment,
        ttl,
        protocol,
        csum,
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
    )


def tcp_checksum(src_ip, dest_ip, tcp_segment):
    pseudo = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dest_ip),
        0,
        socket.IPPROTO_TCP,
        len(tcp_segment),
    )
    return checksum(pseudo + tcp_segment)


def make_raw_tcp_packet(src_ip, dest_ip, src_port, dest_port, seq, ack, flags, payload):
    data_offset = 5 << 4
    window = 65535
    urg_ptr = 0
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dest_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        data_offset,
        flags,
        window,
        0,
        urg_ptr,
    )
    csum = tcp_checksum(src_ip, dest_ip, tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dest_port,
        seq & 0xFFFFFFFF,
        ack & 0xFFFFFFFF,
        data_offset,
        flags,
        window,
        csum,
        urg_ptr,
    )
    return make_ipv4_header(src_ip, dest_ip, socket.IPPROTO_TCP, len(tcp_header) + len(payload)) + tcp_header + payload


def parse_ipv4_tcp_packet(packet):
    if len(packet) < IPV4_HEADER_SIZE or packet[0] >> 4 != 4:
        return None
    ihl = (packet[0] & 0x0F) * 4
    if len(packet) < ihl + RAW_TCP_HEADER_SIZE:
        return None
    protocol = packet[9]
    if protocol != socket.IPPROTO_TCP:
        return None
    src_ip = socket.inet_ntoa(packet[12:16])
    dest_ip = socket.inet_ntoa(packet[16:20])
    tcp = packet[ihl:]
    src_port, dest_port, seq, ack, data_offset_flags, flags, _window, _csum, _urg = struct.unpack(
        "!HHIIBBHHH", tcp[:RAW_TCP_HEADER_SIZE]
    )
    tcp_header_len = (data_offset_flags >> 4) * 4
    if len(tcp) < tcp_header_len:
        return None
    return {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "seq": seq,
        "ack": ack,
        "flags": flags,
        "payload": tcp[tcp_header_len:],
    }


def open_raw_tcp_sockets():
    try:
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        try:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        except OSError:
            send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        raise SystemExit("permission denied: run with sudo/root for raw TCP")
    except OSError as exc:
        raise SystemExit(f"raw TCP socket setup failed: {exc}") from exc
    recv_sock.setblocking(False)
    return recv_sock, send_sock


def retry_would_block(deadline):
    if time.monotonic() >= deadline:
        return False
    time.sleep(0.001)
    return True


def sendto_with_retry(sock, data, address, timeout):
    deadline = time.monotonic() + timeout
    while True:
        try:
            sock.sendto(data, address)
            return True
        except BlockingIOError:
            if not retry_would_block(deadline):
                return False
        except InterruptedError:
            continue


def send_connected_with_retry(sock, data, timeout):
    deadline = time.monotonic() + timeout
    while True:
        try:
            sock.send(data)
            return True
        except BlockingIOError:
            if not retry_would_block(deadline):
                return False
        except InterruptedError:
            continue


def fmt_bytes(value):
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(value)
    for unit in units:
        if n < 1024 or unit == units[-1]:
            return f"{n:.1f}{unit}" if unit != "B" else f"{int(n)}B"
        n /= 1024
    return f"{value}B"


def loss_percent(sent, lost):
    if sent <= 0:
        return 0.0
    return lost * 100.0 / sent


def parse_args():
    parser = argparse.ArgumentParser(
        description="Payload-verifying ICMP/UDP/TCP echo tester."
    )
    parser.add_argument("host", nargs="?", help="destination host for client mode")
    parser.add_argument(
        "--protocol",
        choices=("icmp", "udp", "tcp", "tcp-stream"),
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
        help="server bind address for UDP/TCP; raw TCP uses it only for display/filtering",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=None,
        help="UDP/TCP port; server uses a random high port when omitted",
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
    parser.add_argument(
        "--progress",
        type=int,
        default=100,
        help="client: print progress every N verified replies; server: per-second rx line (0 disables)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="print every verified reply")
    parser.add_argument(
        "--no-directional",
        action="store_true",
        help="skip the post-run arrival log fetch; report round-trip stats only",
    )
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
    if not args.server and args.protocol == "tcp" and args.size > RAW_TCP_MAX_PAYLOAD:
        raise SystemExit(f"raw tcp payload size must be <= {RAW_TCP_MAX_PAYLOAD} bytes")
    if args.parallel < 1:
        raise SystemExit("parallel must be positive")
    if args.parallel > 65535:
        raise SystemExit("parallel must be <= 65535 because identifiers are 16-bit")
    if args.port is not None and not (1 <= args.port <= 65535):
        raise SystemExit("port must be between 1 and 65535")

    if args.protocol in ("udp", "tcp", "tcp-stream") and args.port is None:
        max_base_port = 65535 - args.parallel + 1
        min_base_port = 49152 if max_base_port >= 49152 else 1024
        if max_base_port < min_base_port:
            min_base_port = 1
        args.port = random.randint(min_base_port, max_base_port)
        label = "test" if args.server else "destination"
        print(f"no --port provided; picked random {label} base port {args.port}")

    if args.protocol in ("udp", "tcp", "tcp-stream"):
        last_port = args.port + args.parallel - 1
        if last_port > 65535:
            raise SystemExit(
                f"port range {args.port}..{last_port} exceeds 65535; reduce --parallel or --port"
            )

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
                # Reply arrival order at the client, one entry per first-time
                # verified reply: (seq, rseq). Used for reordering direction.
                "replies": [],
            }
        )

    return streams, started


def ident_range(streams):
    if len(streams) == 1:
        return f"0x{streams[0]['ident']:04x}"
    if len(streams) <= 4:
        return ", ".join(f"0x{stream['ident']:04x}" for stream in streams)
    return f"0x{streams[0]['ident']:04x}..0x{streams[-1]['ident']:04x}"


def stream_port(args, stream):
    return args.port + stream["stream"] - 1


def port_range(args):
    if args.protocol == "icmp":
        return None
    first = args.port
    last = args.port + args.parallel - 1
    return f"{first}" if first == last else f"{first}..{last}"


def endpoint_label(args, host):
    if args.protocol == "icmp":
        return host
    return f"{host}:{port_range(args)}"


def print_client_header(args, dest_ip, streams):
    target_total = args.count * args.parallel
    endpoint = endpoint_label(args, dest_ip)
    print(
        f"verify_ping {args.protocol} {endpoint}: {args.count} packets/stream, "
        f"{args.parallel} streams, {target_total} total packets, {args.size} data bytes, "
        f"interval {args.interval}s, ids {ident_range(streams)}"
    )


def print_client_stats(
    args, dest_ip, started, streams, pending, bad, duplicates, unexpected, arrival_logs=None
):
    sent_total = sum(stream["sent"] for stream in streams)
    verified_total = sum(stream["verified"] for stream in streams)
    lost = len(pending)
    checked_bytes = verified_total * args.size
    elapsed = time.monotonic() - started

    endpoint = endpoint_label(args, dest_ip)
    print()
    print(f"--- {endpoint} verified {args.protocol} statistics ---")
    print(
        f"streams={args.parallel} count_per_stream={args.count} sent={sent_total} "
        f"verified={verified_total} lost={lost} bad_payload={len(bad)} "
        f"loss={loss_percent(sent_total, lost):.3f}% duplicates={duplicates} unexpected={unexpected}"
    )
    print(f"checked_payload={fmt_bytes(checked_bytes)} elapsed={elapsed:.3f}s")

    if args.parallel > 1:
        pending_by_stream = {stream["stream"]: 0 for stream in streams}
        for rec in pending.values():
            pending_by_stream[rec["stream"]] += 1
        for stream in streams:
            stream_lost = pending_by_stream[stream["stream"]]
            print(
                f"stream={stream['stream']} sent={stream['sent']} "
                f"verified={stream['verified']} lost={stream_lost} "
                f"loss={loss_percent(stream['sent'], stream_lost):.3f}% "
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

    if args.protocol in CONTROL_PROTOCOLS and not args.no_directional:
        if arrival_logs is not None:
            print_directional_stats(streams, arrival_logs)
    elif args.protocol == "icmp":
        print("directional stats: n/a for icmp (echo comes from the remote OS, no arrival log)")
    elif args.protocol == "tcp-stream":
        print("directional stats: n/a for tcp-stream (TCP masks loss and reordering)")

    return 0 if sent_total == verified_total and not pending and not bad else 1


def directional_summary(stream, server_log):
    """Attribute loss/reordering/duplication to the forward or reverse path.

    server_log: seqs in the order the server received them (forward-delivered).
    stream["replies"]: (seq, rseq) in the order the client verified replies.
    """
    sent_seqs = set(range(1, stream["sent"] + 1))
    reached = set(server_log)
    verified = {seq for seq, _rseq in stream["replies"]}

    forward_lost = sorted(sent_seqs - reached)
    reverse_lost = sorted(reached - verified)
    return {
        "sent": stream["sent"],
        "reached": len(reached),
        "verified": len(verified),
        "forward_lost": forward_lost,
        "reverse_lost": reverse_lost,
        # Duplicates: forward = server saw a seq more than once; reverse = client
        # counted the same verified seq again (already tracked as `duplicates`).
        "forward_dup": len(server_log) - len(reached),
        # Reordering (RFC 4737 late-arrival count):
        #   forward: seq inversions in server arrival order
        #   reverse: rseq inversions in client reply-arrival order, i.e. against
        #            the order the server actually emitted echoes
        #   end_to_end: seq inversions in client reply-arrival order (naive view)
        "reorder_forward": count_reordered(server_log),
        "reorder_reverse": count_reordered([rseq for _seq, rseq in stream["replies"]]),
        "reorder_end_to_end": count_reordered([seq for seq, _rseq in stream["replies"]]),
    }


def fmt_seq_list(seqs, limit=20):
    shown = ", ".join(str(seq) for seq in seqs[:limit])
    return shown + (" ..." if len(seqs) > limit else "")


def print_directional_stats(streams, logs):
    unavailable = [stream for stream in streams if logs.get(stream["stream"]) is None]
    summaries = [
        (stream, directional_summary(stream, logs[stream["stream"]]))
        for stream in streams
        if logs.get(stream["stream"]) is not None
    ]
    totals = {
        key: sum(summary[key] for _stream, summary in summaries)
        for key in ("sent", "reached", "verified", "forward_dup", "reorder_forward",
                    "reorder_reverse", "reorder_end_to_end")
    }
    totals["forward_lost"] = sum(len(summary["forward_lost"]) for _stream, summary in summaries)
    totals["reverse_lost"] = sum(len(summary["reverse_lost"]) for _stream, summary in summaries)

    print()
    print("--- directional statistics (server arrival log fetched in-band after the run) ---")
    if unavailable:
        labels = ", ".join(str(stream["stream"]) for stream in unavailable)
        print(f"streams without arrival log (excluded from totals): {labels}")

    def print_block(label, summary, forward_lost, reverse_lost):
        sent = summary["sent"]
        total_lost = forward_lost + reverse_lost
        print(
            f"{label}sent={sent} reached_server={summary['reached']} verified={summary['verified']}"
        )
        print(
            f"{label}loss: forward={forward_lost} ({loss_percent(sent, forward_lost):.3f}%) "
            f"reverse={reverse_lost} ({loss_percent(sent, reverse_lost):.3f}%) "
            f"total={total_lost} ({loss_percent(sent, total_lost):.3f}%)"
        )
        print(
            f"{label}reorder: forward={summary['reorder_forward']} "
            f"reverse={summary['reorder_reverse']} end_to_end={summary['reorder_end_to_end']}  "
            f"forward_dup={summary['forward_dup']}"
        )

    multi = len(streams) > 1
    if len(summaries) > 1:
        print_block("all streams: ", totals, totals["forward_lost"], totals["reverse_lost"])
    for stream, summary in summaries:
        label = f"stream={stream['stream']} " if multi else ""
        print_block(label, summary, len(summary["forward_lost"]), len(summary["reverse_lost"]))
        if summary["sent"] and summary["reached"] == 0:
            print(
                f"{label}nothing reached the server on this port: forward path blocked "
                f"(firewall / security group on port {stream.get('port', '?')}?)"
            )
        elif summary["forward_lost"]:
            print(f"{label}forward-lost seqs (never reached server): {fmt_seq_list(summary['forward_lost'])}")
        if summary["reverse_lost"]:
            print(f"{label}reverse-lost seqs (echo never returned): {fmt_seq_list(summary['reverse_lost'])}")


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
    # The server stamp is the only region a legitimate echo may change;
    # zero it back out so the digest covers exactly what was sent.
    digest = hashlib.sha256(normalize_payload(payload)).digest()
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
    stream["replies"].append((parsed["seq"], parsed["rseq"]))
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
                if not sendto_with_retry(sock, packet, (dest_ip, 0), args.timeout):
                    raise SystemExit(f"icmp send to {dest_ip} timed out waiting for socket buffer")
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
        port = stream_port(args, stream)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((dest_ip, port))
        except OSError as exc:
            raise SystemExit(f"udp connect to {dest_ip}:{port} failed: {exc}") from exc
        sock.setblocking(False)
        stream["sock"] = sock
        stream["port"] = port
        socket_to_stream[sock.fileno()] = stream
        selector.register(sock, selectors.EVENT_READ)

    print_client_header(args, dest_ip, streams)

    while sum(stream["sent"] for stream in streams) < target_total or pending:
        now = time.monotonic()
        for stream in streams:
            while stream["sent"] < args.count and now >= stream["next_send"]:
                seq, payload = make_stream_payload(args, stream)
                try:
                    sent = send_connected_with_retry(stream["sock"], payload, args.timeout)
                except OSError as exc:
                    raise SystemExit(f"udp send to {dest_ip}:{stream['port']} failed: {exc}") from exc
                if not sent:
                    raise SystemExit(
                        f"udp send to {dest_ip}:{stream['port']} timed out waiting for socket buffer"
                    )
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
                if payload.startswith(CTRL_MAGIC):
                    continue

                result = verify_payload(
                    payload,
                    f"{dest_ip}:{stream['port']}",
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
                            f"seq={rec['seq']} from={dest_ip}:{stream['port']} rtt={rtt_ms:.3f} ms"
                        )

        if should_stop_waiting(args, streams, pending, target_total):
            break

    arrival_logs = None
    if not args.no_directional:
        # Pull the arrival log over the same connected sockets the test used.
        def send_request(stream, data):
            stream["sock"].send(data)

        def recv_replies(wait):
            replies = []
            end = time.monotonic() + wait
            while True:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    break
                events = selector.select(remaining)
                if not events:
                    break
                for key, _mask in events:
                    while True:
                        try:
                            data = key.fileobj.recv(UDP_MAX_PAYLOAD)
                        except OSError:
                            break
                        if data.startswith(CTRL_MAGIC):
                            replies.append(data)
            return replies

        arrival_logs = fetch_arrival_logs(args, streams, send_request, recv_replies)

    for stream in streams:
        stream["sock"].close()

    return print_client_stats(
        args, dest_ip, started, streams, pending, bad, duplicates, unexpected, arrival_logs
    )


def run_tcp_stream_client(args, dest_ip):
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
        port = stream_port(args, stream)
        try:
            sock = socket.create_connection((dest_ip, port), timeout=args.timeout)
        except OSError as exc:
            raise SystemExit(f"tcp connect to {dest_ip}:{port} failed: {exc}") from exc
        sock.setblocking(False)
        stream["sock"] = sock
        stream["port"] = port
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
                            f"{dest_ip}:{stream['port']}",
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
                                    f"seq={rec['seq']} from={dest_ip}:{stream['port']} rtt={rtt_ms:.3f} ms"
                                )

        if should_stop_waiting(args, streams, pending, target_total):
            break

    for stream in streams:
        sock = stream["sock"]
        if sock and not stream["closed"]:
            selector.unregister(sock)
            sock.close()

    return print_client_stats(args, dest_ip, started, streams, pending, bad, duplicates, unexpected)


def assign_raw_tcp_source_ports(streams):
    base_port = random.randint(20000, 60000)
    used_ports = set()
    for index, stream in enumerate(streams):
        port = base_port + index
        if port > 65535:
            port = 20000 + (port - 65536)
        if port in used_ports:
            raise SystemExit("parallel produced duplicate raw TCP source ports")
        used_ports.add(port)
        stream["src_port"] = port


def run_raw_tcp_client(args, dest_ip):
    streams, started = build_streams(args)
    assign_raw_tcp_source_ports(streams)
    for stream in streams:
        stream["port"] = stream_port(args, stream)
    streams_by_ident = {stream["ident"]: stream for stream in streams}
    source_ports = {stream["src_port"] for stream in streams}
    source_ip = route_source_ip(dest_ip)
    target_total = args.count * args.parallel
    pending = {}
    completed = {}
    bad = []
    duplicates = 0
    unexpected = 0
    verified_total = 0
    arrival_logs = None

    recv_sock, send_sock = open_raw_tcp_sockets()
    selector = selectors.DefaultSelector()
    selector.register(recv_sock, selectors.EVENT_READ)
    print_client_header(args, dest_ip, streams)
    print(f"raw tcp source {source_ip}, source ports {min(source_ports)}..{max(source_ports)}")

    try:
        while sum(stream["sent"] for stream in streams) < target_total or pending:
            now = time.monotonic()
            for stream in streams:
                port = stream_port(args, stream)
                while stream["sent"] < args.count and now >= stream["next_send"]:
                    seq, payload = make_stream_payload(args, stream)
                    packet = make_raw_tcp_packet(
                        source_ip,
                        dest_ip,
                        stream["src_port"],
                        port,
                        seq,
                        0,
                        TCP_PSH | TCP_ACK,
                        payload,
                    )
                    try:
                        sent = sendto_with_retry(send_sock, packet, (dest_ip, 0), args.timeout)
                    except OSError as exc:
                        raise SystemExit(f"raw tcp send to {dest_ip}:{port} failed: {exc}") from exc
                    if not sent:
                        raise SystemExit(
                            f"raw tcp send to {dest_ip}:{port} timed out waiting for socket buffer"
                        )
                    record_pending(pending, stream, seq, payload, args.interval)
                    now = time.monotonic()

            timeout = min(next_send_wait(streams, args.count, time.monotonic(), args.timeout), args.timeout, 0.2)
            if timeout == 0 and pending:
                timeout = 0.001

            events = selector.select(timeout)
            for _key, _mask in events:
                while True:
                    try:
                        packet, _addr = recv_sock.recvfrom(65535)
                    except BlockingIOError:
                        break

                    parsed = parse_ipv4_tcp_packet(packet)
                    if not parsed:
                        continue
                    if (
                        parsed["src_ip"] != dest_ip
                        or not (args.port <= parsed["src_port"] <= args.port + args.parallel - 1)
                        or parsed["dest_port"] not in source_ports
                        or not parsed["payload"].startswith(MAGIC)
                    ):
                        continue

                    result = verify_payload(
                        parsed["payload"],
                        f"{parsed['src_ip']}:{parsed['src_port']}",
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
                                f"seq={rec['seq']} from={parsed['src_ip']}:{parsed['src_port']} "
                                f"rtt={rtt_ms:.3f} ms"
                            )

            if should_stop_waiting(args, streams, pending, target_total):
                break

        if not args.no_directional:
            # Pull the arrival log as raw segments on the same ports the test used.
            def send_request(stream, data):
                packet = make_raw_tcp_packet(
                    source_ip,
                    dest_ip,
                    stream["src_port"],
                    stream_port(args, stream),
                    0,
                    0,
                    TCP_PSH | TCP_ACK,
                    data,
                )
                sendto_with_retry(send_sock, packet, (dest_ip, 0), args.timeout)

            def recv_replies(wait):
                replies = []
                end = time.monotonic() + wait
                while True:
                    remaining = end - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        break
                    while True:
                        try:
                            packet, _addr = recv_sock.recvfrom(65535)
                        except BlockingIOError:
                            break
                        parsed = parse_ipv4_tcp_packet(packet)
                        if (
                            parsed
                            and parsed["src_ip"] == dest_ip
                            and args.port <= parsed["src_port"] <= args.port + args.parallel - 1
                            and parsed["dest_port"] in source_ports
                            and parsed["payload"].startswith(CTRL_MAGIC)
                        ):
                            replies.append(parsed["payload"])
                return replies

            arrival_logs = fetch_arrival_logs(args, streams, send_request, recv_replies)
    finally:
        recv_sock.close()
        send_sock.close()

    return print_client_stats(
        args, dest_ip, started, streams, pending, bad, duplicates, unexpected, arrival_logs
    )


def run_raw_tcp_server(args):
    recv_sock, send_sock = open_raw_tcp_sockets()
    first_port = args.port
    last_port = args.port + args.parallel - 1
    arrival_log = ArrivalLog()
    progress = ServerProgress(args.progress > 0)
    print(f"verify_ping raw tcp echo server listening on {args.bind}:{port_range(args)}", flush=True)
    print("raw tcp mode ignores non-test TCP packets, including kernel-generated RST", flush=True)
    print("arrival logs for directional stats are served in-band on the same ports", flush=True)

    try:
        while True:
            progress.tick()
            try:
                packet, _addr = recv_sock.recvfrom(65535)
            except BlockingIOError:
                time.sleep(0.001)
                continue

            parsed = parse_ipv4_tcp_packet(packet)
            if not parsed:
                continue
            if not (first_port <= parsed["dest_port"] <= last_port):
                continue
            if args.bind != "0.0.0.0" and parsed["dest_ip"] != args.bind:
                continue

            echo_payload = serve_ctrl_request(arrival_log, parsed["payload"])
            if echo_payload is None:
                if not parsed["payload"].startswith(MAGIC):
                    continue
                payload_meta = parse_payload(parsed["payload"])
                if not payload_meta:
                    continue
                rseq = arrival_log.record(payload_meta["nonce"], payload_meta["seq"])
                echo_payload = stamp_payload(parsed["payload"], rseq, time.monotonic_ns())
                progress.add(payload_meta["nonce"], parsed["src_ip"])
            ack = (parsed["seq"] + len(parsed["payload"])) & 0xFFFFFFFF
            reply = make_raw_tcp_packet(
                parsed["dest_ip"],
                parsed["src_ip"],
                parsed["dest_port"],
                parsed["src_port"],
                parsed["ack"],
                ack,
                TCP_PSH | TCP_ACK,
                echo_payload,
            )
            try:
                sendto_with_retry(send_sock, reply, (parsed["src_ip"], 0), 1.0)
            except OSError:
                continue
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        recv_sock.close()
        send_sock.close()

    return 0


def run_udp_server(args):
    selector = selectors.DefaultSelector()
    sockets = []
    for offset in range(args.parallel):
        port = args.port + offset
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind((args.bind, port))
        except OSError as exc:
            raise SystemExit(f"udp bind to {args.bind}:{port} failed: {exc}") from exc
        sock.setblocking(False)
        selector.register(sock, selectors.EVENT_READ)
        sockets.append(sock)

    arrival_log = ArrivalLog()
    progress = ServerProgress(args.progress > 0)
    actual_host = sockets[0].getsockname()[0]
    print(f"verify_ping udp echo server listening on {actual_host}:{port_range(args)}", flush=True)
    print("arrival logs for directional stats are served in-band on the same ports", flush=True)

    try:
        while True:
            for key, _mask in selector.select(1.0):
                while True:
                    try:
                        data, addr = key.fileobj.recvfrom(UDP_MAX_PAYLOAD)
                    except BlockingIOError:
                        break
                    if not data:
                        continue
                    ctrl_reply = serve_ctrl_request(arrival_log, data)
                    if ctrl_reply is not None:
                        key.fileobj.sendto(ctrl_reply, addr)
                        continue
                    meta = parse_payload(data)
                    if meta:
                        rseq = arrival_log.record(meta["nonce"], meta["seq"])
                        data = stamp_payload(data, rseq, time.monotonic_ns())
                        progress.add(meta["nonce"], addr[0])
                    key.fileobj.sendto(data, addr)
            progress.tick()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        for sock in sockets:
            selector.unregister(sock)
            sock.close()

    return 0


def run_tcp_stream_server(args):
    selector = selectors.DefaultSelector()
    buffers = {}
    listeners = []
    for offset in range(args.parallel):
        port = args.port + offset
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server.bind((args.bind, port))
        except OSError as exc:
            raise SystemExit(f"tcp bind to {args.bind}:{port} failed: {exc}") from exc
        server.listen()
        server.setblocking(False)
        selector.register(server, selectors.EVENT_READ, {"listener": True})
        listeners.append(server)

    actual_host = listeners[0].getsockname()[0]
    print(f"verify_ping tcp-stream echo server listening on {actual_host}:{port_range(args)}", flush=True)

    try:
        while True:
            for key, mask in selector.select(1.0):
                if key.data and key.data.get("listener"):
                    conn, _addr = key.fileobj.accept()
                    conn.setblocking(False)
                    buffers[conn.fileno()] = bytearray()
                    selector.register(conn, selectors.EVENT_READ, {"listener": False, "fileno": conn.fileno()})
                    continue

                conn = key.fileobj
                fileno = key.data["fileno"]
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
                    selector.modify(
                        conn,
                        selectors.EVENT_READ | selectors.EVENT_WRITE,
                        {"listener": False, "fileno": fileno},
                    )

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
                        selector.modify(
                            conn,
                            selectors.EVENT_READ,
                            {"listener": False, "fileno": fileno},
                        )
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
        if args.protocol == "tcp":
            return run_raw_tcp_server(args)
        return run_tcp_stream_server(args)

    dest_ip = socket.gethostbyname(args.host)
    if args.protocol == "icmp":
        return run_icmp_client(args, dest_ip)
    if args.protocol == "udp":
        return run_udp_client(args, dest_ip)
    if args.protocol == "tcp":
        return run_raw_tcp_client(args, dest_ip)
    return run_tcp_stream_client(args, dest_ip)


if __name__ == "__main__":
    sys.exit(main())
