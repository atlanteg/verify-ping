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
CTRL_MAGIC = b"vpnc4\x00\x00\x00"
# Message type byte follows the magic.
CTRL_CHUNK_REQ = 1          # pull one chunk of a log:      nonce, kind, index
CTRL_CHUNK_REP = 2          # one chunk:                    nonce, kind, index, total chunks, total entries, entries
CTRL_START = 3              # -R: ask the server to probe:  nonce, ident, stream, count, interval_us, size, timeout_ms
CTRL_START_ACK = 4          # -R: server accepted the run:  nonce
CTRL_REQ_FMT = "!16sBH"
CTRL_REP_FMT = "!16sBHHI"
CTRL_START_FMT = "!16sHHHIHI"
CTRL_ACK_FMT = "!16s"
CTRL_TYPE_OFFSET = len(CTRL_MAGIC)
CTRL_BODY_OFFSET = CTRL_TYPE_OFFSET + 1
CTRL_REQ_SIZE = CTRL_BODY_OFFSET + struct.calcsize(CTRL_REQ_FMT)
CTRL_REP_SIZE = CTRL_BODY_OFFSET + struct.calcsize(CTRL_REP_FMT)
CTRL_START_SIZE = CTRL_BODY_OFFSET + struct.calcsize(CTRL_START_FMT)
CTRL_ACK_SIZE = CTRL_BODY_OFFSET + struct.calcsize(CTRL_ACK_FMT)
# Log kinds a chunk request can ask for. Entries are fixed-size records, and
# a chunk stays around 1 KB so it never needs IP fragmentation.
KIND_ARRIVALS = 0           # echo side: seqs in arrival order            (!H)
KIND_REPLIES = 1            # probe side: (seq, rseq) in reply order      (!HI)
KIND_SUMMARY = 2            # probe side: sent, verified, bad, dup, unexpected, done
KIND_ENTRY_FMT = {KIND_ARRIVALS: "!H", KIND_REPLIES: "!HI", KIND_SUMMARY: "!HHHHHB"}
KIND_CHUNK_ENTRIES = {KIND_ARRIVALS: 512, KIND_REPLIES: 170, KIND_SUMMARY: 1}
CTRL_WINDOW = 64            # outstanding chunk requests per round
CTRL_ROUND_WAIT = 0.25      # seconds to collect replies per round
CONTROL_PROTOCOLS = ("udp", "tcp")
REVERSE_PROTOCOLS = ("udp",)
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


def chunk_of(entries, kind, index):
    """Slice a log into fixed-size chunks: (total_chunks, total_entries, part)."""
    per_chunk = KIND_CHUNK_ENTRIES[kind]
    total = len(entries)
    total_chunks = max(1, (total + per_chunk - 1) // per_chunk)
    start = index * per_chunk
    return total_chunks, total, entries[start:start + per_chunk]


class ArrivalLog:
    """Echo-side per-stream arrival accounting, keyed by run nonce."""

    def __init__(self):
        self.arrivals = {}

    def record(self, nonce, seq):
        log = self.arrivals.setdefault(nonce, [])
        log.append(seq)
        return len(log)

    def chunk(self, nonce, kind, index):
        if kind != KIND_ARRIVALS:
            return None
        return chunk_of(self.arrivals.get(nonce, []), kind, index)


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


class ProbeSession:
    """-R on the server: one stream the server probes toward a client that asked.

    Mirrors the normal client's prober state (pending, verification, reply
    order) so the client can later pull KIND_REPLIES / KIND_SUMMARY and run
    the same directional maths with the roles swapped.
    """

    def __init__(self, start, sock, addr):
        now = time.monotonic()
        self.sock = sock
        self.addr = addr
        self.nonce = start["nonce"]
        self.count = start["count"]
        self.interval = start["interval"]
        self.size = start["size"]
        self.timeout = start["timeout"]
        self.stream = {
            "stream": start["stream"],
            "ident": start["ident"],
            "nonce": self.nonce,
            "sent": 0,
            "verified": 0,
            "bad": 0,
            "next_send": now,
            "last_send": None,
            "replies": [],
        }
        self.pending = {}
        self.completed = {}
        self.bad = []
        self.duplicates = 0
        self.unexpected = 0
        self.done = False
        self.done_at = None

    def next_wakeup(self, now):
        if self.done or self.stream["sent"] >= self.count:
            return None
        return max(0.0, self.stream["next_send"] - now)

    def pump(self, now):
        """Send due probes; mark done once all are sent and answered or timed out."""
        stream = self.stream
        while not self.done and stream["sent"] < self.count and now >= stream["next_send"]:
            seq = stream["sent"] + 1
            payload = make_payload(
                self.size, stream["ident"], stream["stream"], seq, seq, time.monotonic_ns(), self.nonce
            )
            try:
                self.sock.sendto(payload, self.addr)
            except OSError:
                pass
            record_pending(self.pending, stream, seq, payload, self.interval)
            now = time.monotonic()
        if not self.done and stream["sent"] >= self.count:
            if not self.pending or (
                stream["last_send"] is not None and now - stream["last_send"] >= self.timeout
            ):
                self.done = True
                self.done_at = now

    def on_echo(self, payload, source):
        result = verify_payload(
            payload, source, {self.stream["ident"]: self.stream}, self.pending, self.completed, self.bad
        )
        if result == "duplicate":
            self.duplicates += 1
        elif result == "unexpected":
            self.unexpected += 1

    def chunk(self, kind, index):
        if kind == KIND_REPLIES:
            return chunk_of(self.stream["replies"], kind, index)
        if kind == KIND_SUMMARY:
            stream = self.stream
            record = (
                stream["sent"],
                stream["verified"],
                min(len(self.bad), 0xFFFF),
                min(self.duplicates, 0xFFFF),
                min(self.unexpected, 0xFFFF),
                1 if self.done else 0,
            )
            return chunk_of([record], kind, index)
        return None


def ctrl_type(data):
    if len(data) <= CTRL_TYPE_OFFSET or not data.startswith(CTRL_MAGIC):
        return None
    return data[CTRL_TYPE_OFFSET]


def make_ctrl_request(nonce, kind, index):
    return CTRL_MAGIC + bytes([CTRL_CHUNK_REQ]) + struct.pack(CTRL_REQ_FMT, nonce, kind, index)


def parse_ctrl_request(data):
    if ctrl_type(data) != CTRL_CHUNK_REQ or len(data) != CTRL_REQ_SIZE:
        return None
    nonce, kind, index = struct.unpack_from(CTRL_REQ_FMT, data, CTRL_BODY_OFFSET)
    if kind not in KIND_ENTRY_FMT:
        return None
    return nonce, kind, index


def pack_entries(kind, entries):
    fmt = KIND_ENTRY_FMT[kind]
    return b"".join(
        struct.pack(fmt, *(entry if isinstance(entry, tuple) else (entry,))) for entry in entries
    )


def unpack_entries(kind, body):
    fmt = KIND_ENTRY_FMT[kind]
    if len(body) % struct.calcsize(fmt):
        return None
    records = list(struct.iter_unpack(fmt, body))
    if kind == KIND_ARRIVALS:
        return [record[0] for record in records]
    return records


def make_ctrl_reply(nonce, kind, index, total_chunks, total_entries, entries):
    return (
        CTRL_MAGIC
        + bytes([CTRL_CHUNK_REP])
        + struct.pack(CTRL_REP_FMT, nonce, kind, index, total_chunks, total_entries)
        + pack_entries(kind, entries)
    )


def parse_ctrl_reply(data):
    if ctrl_type(data) != CTRL_CHUNK_REP or len(data) < CTRL_REP_SIZE:
        return None
    nonce, kind, index, total_chunks, total_entries = struct.unpack_from(
        CTRL_REP_FMT, data, CTRL_BODY_OFFSET
    )
    if kind not in KIND_ENTRY_FMT:
        return None
    entries = unpack_entries(kind, data[CTRL_REP_SIZE:])
    if entries is None:
        return None
    return {
        "nonce": nonce,
        "kind": kind,
        "index": index,
        "total_chunks": total_chunks,
        "total_entries": total_entries,
        "entries": entries,
    }


def make_ctrl_start(nonce, ident, stream, count, interval_us, size, timeout_ms):
    return (
        CTRL_MAGIC
        + bytes([CTRL_START])
        + struct.pack(CTRL_START_FMT, nonce, ident, stream, count, interval_us, size, timeout_ms)
    )


def parse_ctrl_start(data):
    if ctrl_type(data) != CTRL_START or len(data) != CTRL_START_SIZE:
        return None
    nonce, ident, stream, count, interval_us, size, timeout_ms = struct.unpack_from(
        CTRL_START_FMT, data, CTRL_BODY_OFFSET
    )
    return {
        "nonce": nonce,
        "ident": ident,
        "stream": stream,
        "count": count,
        "interval": interval_us / 1e6,
        "size": size,
        "timeout": timeout_ms / 1e3,
    }


def make_ctrl_ack(nonce):
    return CTRL_MAGIC + bytes([CTRL_START_ACK]) + struct.pack(CTRL_ACK_FMT, nonce)


def parse_ctrl_ack(data):
    if ctrl_type(data) != CTRL_START_ACK or len(data) != CTRL_ACK_SIZE:
        return None
    return struct.unpack_from(CTRL_ACK_FMT, data, CTRL_BODY_OFFSET)[0]


def serve_ctrl_request(chunk_fn, data):
    """Answer one in-band chunk request via chunk_fn(nonce, kind, index); None if not one."""
    request = parse_ctrl_request(data)
    if request is None:
        return None
    nonce, kind, index = request
    result = chunk_fn(nonce, kind, index)
    if result is None:
        return None
    total_chunks, total_entries, entries = result
    return make_ctrl_reply(nonce, kind, index, total_chunks, total_entries, entries)


def fetch_arrival_logs(args, streams, send_request, recv_replies):
    return fetch_logs(args, streams, send_request, recv_replies, KIND_ARRIVALS)


def fetch_logs(args, streams, send_request, recv_replies, kind, budget=None):
    """Pull one kind of log for each stream over the data path.

    send_request(carrier, data) sends one control datagram on the carrier
    stream's socket/port; recv_replies(timeout) returns raw control payloads
    received meanwhile. Chunks are independent, so lost ones are simply
    requested again. The far side keys logs by nonce, not by port, so after
    the first round a stream whose own port is blocked is retried through the
    other streams' sockets; that is how a firewalled port still gets its
    "nothing reached the server" verdict.
    Returns {stream_no: entries or None if unavailable}.
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
    if budget is None:
        budget = max(10.0, args.timeout * 3)
    deadline = time.monotonic() + budget
    label = {KIND_ARRIVALS: "arrival log", KIND_REPLIES: "reply log", KIND_SUMMARY: "summary"}[kind]

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
                send_request(carrier, make_ctrl_request(stream["nonce"], kind, index))
            except OSError:
                pass
        for state, _index in wanted:
            state["attempt"] += 1

        for data in recv_replies(CTRL_ROUND_WAIT):
            reply = parse_ctrl_reply(data)
            if reply is None:
                continue
            state = states.get(reply["nonce"])
            if state is None or reply["kind"] != kind:
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
                state["chunks"][reply["index"]] = reply["entries"]

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
            f"control: {label} fetch failed for every stream "
            f"(old server, no path to it, or data path too lossy); directional stats unavailable"
        )
        return None
    if incomplete:
        labels = ", ".join(str(item) for item in incomplete)
        print(f"control: {label} fetch incomplete for stream(s) {labels}; shown as unavailable")
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
    parser.add_argument(
        "-R",
        "--reverse",
        action="store_true",
        help="reverse roles: connect as usual, then the server probes and this client echoes; "
        "the report is still printed here (udp only)",
    )
    return parser.parse_args()


def validate_args(args):
    if args.server and args.protocol == "icmp":
        raise SystemExit("ICMP echo replies are provided by the OS; --server is only for UDP/TCP")
    if not args.server and not args.host:
        raise SystemExit("host is required in client mode")
    if args.reverse and args.server:
        raise SystemExit("-R is a client option; the server side needs no flag")
    if args.reverse and args.protocol not in REVERSE_PROTOCOLS:
        raise SystemExit(f"-R is supported for {', '.join(REVERSE_PROTOCOLS)} only")
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


def print_directional_stats(streams, logs, far="server"):
    """far names the echo side: 'server' normally, 'client' under -R."""
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
    print(f"--- directional statistics ({far} arrival log fetched in-band after the run) ---")
    if unavailable:
        labels = ", ".join(str(stream["stream"]) for stream in unavailable)
        print(f"streams without arrival log (excluded from totals): {labels}")

    def print_block(label, summary, forward_lost, reverse_lost):
        sent = summary["sent"]
        total_lost = forward_lost + reverse_lost
        print(
            f"{label}sent={sent} reached_{far}={summary['reached']} verified={summary['verified']}"
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
                f"{label}nothing reached the {far} on this port: forward path blocked "
                f"(firewall / security group on port {stream.get('port', '?')}?)"
            )
        elif summary["forward_lost"]:
            print(f"{label}forward-lost seqs (never reached {far}): {fmt_seq_list(summary['forward_lost'])}")
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

            echo_payload = serve_ctrl_request(arrival_log.chunk, parsed["payload"])
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
    sessions = {}  # -R runs we are probing, keyed by client nonce
    progress = ServerProgress(args.progress > 0)
    actual_host = sockets[0].getsockname()[0]
    print(f"verify_ping udp echo server listening on {actual_host}:{port_range(args)}", flush=True)
    print("arrival logs for directional stats are served in-band on the same ports", flush=True)

    def server_chunk(nonce, kind, index):
        if kind == KIND_ARRIVALS:
            return arrival_log.chunk(nonce, kind, index)
        session = sessions.get(nonce)
        return session.chunk(kind, index) if session else None

    try:
        while True:
            now = time.monotonic()
            timeout = 1.0
            for session in sessions.values():
                wake = session.next_wakeup(now)
                if wake is not None:
                    timeout = min(timeout, wake)

            for key, _mask in selector.select(timeout):
                while True:
                    try:
                        data, addr = key.fileobj.recvfrom(UDP_MAX_PAYLOAD)
                    except BlockingIOError:
                        break
                    if not data:
                        continue
                    if ctrl_type(data) is not None:
                        start = parse_ctrl_start(data)
                        if start is not None:
                            if start["nonce"] not in sessions:
                                sessions[start["nonce"]] = ProbeSession(start, key.fileobj, addr)
                                print(
                                    f"[{time.strftime('%H:%M:%S')}] -R run for {addr[0]}: "
                                    f"stream {start['stream']} count={start['count']} "
                                    f"interval={start['interval']}s size={start['size']}",
                                    flush=True,
                                )
                            key.fileobj.sendto(make_ctrl_ack(start["nonce"]), addr)
                            continue
                        ctrl_reply = serve_ctrl_request(server_chunk, data)
                        if ctrl_reply is not None:
                            key.fileobj.sendto(ctrl_reply, addr)
                        continue
                    meta = parse_payload(data)
                    if meta:
                        session = sessions.get(meta["nonce"])
                        if session is not None:
                            # Echo of one of our own -R probes: verify, do not re-echo.
                            session.on_echo(data, addr[0])
                            progress.add(meta["nonce"], addr[0])
                            continue
                        rseq = arrival_log.record(meta["nonce"], meta["seq"])
                        data = stamp_payload(data, rseq, time.monotonic_ns())
                        progress.add(meta["nonce"], addr[0])
                    key.fileobj.sendto(data, addr)

            now = time.monotonic()
            for nonce, session in list(sessions.items()):
                session.pump(now)
                if session.done and now - session.done_at > 3600:
                    del sessions[nonce]
            progress.tick()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        for sock in sockets:
            selector.unregister(sock)
            sock.close()

    return 0


def run_udp_reverse_client(args, dest_ip):
    """-R: connect as usual, then let the server probe us while we echo.

    The report is still printed here. It combines the server's prober state
    (pulled in-band after the run) with our own arrival log, so forward means
    server -> client and reverse means client -> server.
    """
    streams, started = build_streams(args)
    streams_by_nonce = {stream["nonce"]: stream for stream in streams}
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

    endpoint = endpoint_label(args, dest_ip)
    print(
        f"verify_ping udp -R {endpoint}: server probes {args.count} packets/stream, "
        f"{args.parallel} streams, {args.count * args.parallel} total packets, {args.size} data bytes, "
        f"interval {args.interval}s, ids {ident_range(streams)}; this client echoes"
    )

    arrival_log = ArrivalLog()
    progress = ServerProgress(args.progress > 0)
    acked = set()
    summaries = {}
    handshake_deadline = started + max(10.0, args.timeout * 3)
    next_start_send = 0.0
    expected_end = None
    next_poll = None

    def send_request(carrier, data):
        carrier["sock"].send(data)

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
                    if ctrl_type(data) == CTRL_CHUNK_REP:
                        replies.append(data)
        return replies

    while True:
        now = time.monotonic()

        if len(acked) < len(streams) and now < handshake_deadline and now >= next_start_send:
            for stream in streams:
                if stream["nonce"] in acked:
                    continue
                try:
                    stream["sock"].send(
                        make_ctrl_start(
                            stream["nonce"],
                            stream["ident"],
                            stream["stream"],
                            args.count,
                            int(args.interval * 1e6),
                            args.size,
                            int(args.timeout * 1e3),
                        )
                    )
                except OSError:
                    pass
            next_start_send = now + 0.5

        if expected_end is None and (len(acked) == len(streams) or now >= handshake_deadline):
            if not acked:
                raise SystemExit(
                    "server never acknowledged the -R start on any stream "
                    "(old server without -R support, or ports blocked toward it)"
                )
            expected_end = now + args.count * args.interval + args.timeout
            next_poll = expected_end
            print(
                f"server acknowledged {len(acked)}/{len(streams)} streams; "
                f"probing should take ~{expected_end - now:.0f}s"
            )

        acked_streams = [stream for stream in streams if stream["nonce"] in acked]
        if expected_end is not None:
            if all(summaries.get(stream["stream"], {}).get("done") for stream in acked_streams):
                break
            if now > expected_end + max(30.0, args.timeout * 3):
                print("timed out waiting for the server to finish probing; reporting what we have")
                break
            if now >= next_poll:
                for stream in acked_streams:
                    if not summaries.get(stream["stream"], {}).get("done"):
                        try:
                            stream["sock"].send(make_ctrl_request(stream["nonce"], KIND_SUMMARY, 0))
                        except OSError:
                            pass
                next_poll = now + 1.0

        timeout = 0.5
        if len(acked) < len(streams) and now < handshake_deadline:
            timeout = min(timeout, max(0.0, next_start_send - now))
        if next_poll is not None:
            timeout = min(timeout, max(0.0, next_poll - now))

        for key, _mask in selector.select(timeout):
            stream = socket_to_stream[key.fileobj.fileno()]
            while True:
                try:
                    data = key.fileobj.recv(UDP_MAX_PAYLOAD)
                except OSError:
                    break
                kind = ctrl_type(data)
                if kind == CTRL_START_ACK:
                    nonce = parse_ctrl_ack(data)
                    if nonce in streams_by_nonce:
                        acked.add(nonce)
                    continue
                if kind == CTRL_CHUNK_REP:
                    reply = parse_ctrl_reply(data)
                    if reply and reply["kind"] == KIND_SUMMARY and reply["entries"]:
                        owner = streams_by_nonce.get(reply["nonce"])
                        if owner:
                            summaries[owner["stream"]] = dict(
                                zip(("sent", "verified", "bad", "duplicates", "unexpected", "done"),
                                    reply["entries"][0])
                            )
                    continue
                if kind is not None:
                    continue
                meta = parse_payload(data)
                if meta and meta["nonce"] in streams_by_nonce:
                    rseq = arrival_log.record(meta["nonce"], meta["seq"])
                    try:
                        stream["sock"].send(stamp_payload(data, rseq, time.monotonic_ns()))
                    except OSError:
                        pass
                    progress.add(meta["nonce"], dest_ip)
        progress.tick()

    acked_streams = [stream for stream in streams if stream["nonce"] in acked]
    reply_logs = None
    if acked_streams:
        reply_logs = fetch_logs(args, acked_streams, send_request, recv_replies, KIND_REPLIES)
    for stream in streams:
        stream["sock"].close()

    return print_reverse_report(
        args, dest_ip, started, streams, acked_streams, summaries, reply_logs, arrival_log
    )


def print_reverse_report(args, dest_ip, started, streams, acked_streams, summaries, reply_logs, arrival_log):
    endpoint = endpoint_label(args, dest_ip)
    elapsed = time.monotonic() - started
    unacked = [stream for stream in streams if stream not in acked_streams]

    report_streams = []
    logs = {}
    for stream in acked_streams:
        summary = summaries.get(stream["stream"]) or {}
        replies = (reply_logs or {}).get(stream["stream"])
        report_streams.append(
            {
                "stream": stream["stream"],
                "ident": stream["ident"],
                "nonce": stream["nonce"],
                "port": stream["port"],
                "sent": summary.get("sent", 0),
                "verified": summary.get("verified", 0),
                "bad": summary.get("bad", 0),
                "duplicates": summary.get("duplicates", 0),
                "unexpected": summary.get("unexpected", 0),
                "done": summary.get("done", 0),
                "replies": replies or [],
                "has_replies": replies is not None,
            }
        )
        logs[stream["stream"]] = arrival_log.arrivals.get(stream["nonce"], []) if replies is not None else None

    sent_total = sum(item["sent"] for item in report_streams)
    verified_total = sum(item["verified"] for item in report_streams)
    bad_total = sum(item["bad"] for item in report_streams)
    lost_total = sent_total - verified_total - bad_total
    duplicates = sum(item["duplicates"] for item in report_streams)
    unexpected = sum(item["unexpected"] for item in report_streams)

    print()
    print(f"--- {endpoint} verified udp statistics (-R: server probes, client echoes) ---")
    print(
        f"streams={args.parallel} count_per_stream={args.count} sent={sent_total} "
        f"verified={verified_total} lost={lost_total} bad_payload={bad_total} "
        f"loss={loss_percent(sent_total, lost_total):.3f}% duplicates={duplicates} unexpected={unexpected}"
    )
    print(f"checked_payload={fmt_bytes(verified_total * args.size)} elapsed={elapsed:.3f}s")
    if args.parallel > 1:
        for item in report_streams:
            lost = item["sent"] - item["verified"] - item["bad"]
            print(
                f"stream={item['stream']} sent={item['sent']} verified={item['verified']} "
                f"lost={lost} loss={loss_percent(item['sent'], lost):.3f}% bad_payload={item['bad']}"
            )
    for stream in unacked:
        print(
            f"stream={stream['stream']} server never acknowledged the start on port {stream['port']}: "
            f"client -> server path blocked (firewall / security group?) or old server"
        )
    for item in report_streams:
        if not item["done"]:
            print(f"stream={item['stream']} server did not report completion; figures may be partial")

    missing = []
    for item in report_streams:
        if item["has_replies"]:
            verified_seqs = {seq for seq, _rseq in item["replies"]}
            missing.extend((item["stream"], seq) for seq in range(1, item["sent"] + 1) if seq not in verified_seqs)
    if missing:
        missing.sort()
        if args.parallel == 1:
            shown = ", ".join(str(seq) for _stream, seq in missing[:20])
        else:
            shown = ", ".join(f"{stream}:{seq}" for stream, seq in missing[:20])
        print(f"missing request indexes: {shown}{' ...' if len(missing) > 20 else ''}")

    if not args.no_directional and report_streams:
        print()
        print("note: -R swaps the roles, so below forward = server -> client and reverse = client -> server")
        print_directional_stats(report_streams, logs, far="client")

    ok = (
        not unacked
        and report_streams
        and all(item["done"] and item["sent"] == item["verified"] and item["bad"] == 0 for item in report_streams)
    )
    return 0 if ok else 1


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
        if args.reverse:
            return run_udp_reverse_client(args, dest_ip)
        return run_udp_client(args, dest_ip)
    if args.protocol == "tcp":
        return run_raw_tcp_client(args, dest_ip)
    return run_tcp_stream_client(args, dest_ip)


if __name__ == "__main__":
    sys.exit(main())
