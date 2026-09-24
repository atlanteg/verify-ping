# verify-ping

`verify-ping` is a small ICMP/UDP/TCP echo tester for checking packet loss when
you need stronger guarantees than a regular `ping` summary.

It sends requests with a unique payload in every packet/message and verifies
that each reply contains exactly the same payload bytes. This helps confirm that
every counted reply belongs to the matching request and that the payload was not
corrupted or mixed up in transit.

For UDP and raw TCP it also tells you **which direction** lost or reordered
packets: forward (client → server) or reverse (server → client). See
[Directional statistics](#directional-statistics).

## Features

- Unique deterministic payload per request
- SHA-256 payload verification for every reply
- ICMP, UDP, and TCP echo verification modes
- Regular `ping`-style options for count, interval, payload size, and port
- Parallel measurement streams with separate verification identifiers
- Reports lost requests, bad payloads, duplicates, and unexpected replies
- Per-direction loss, reordering, and duplication attribution (UDP, raw TCP)
- No third-party Python dependencies

## Requirements

- Python 3.9+
- macOS or Linux
- Root/admin privileges for raw ICMP and raw TCP sockets
- A `verify-ping` UDP/TCP echo server on the remote side for UDP/TCP tests

## Usage

### ICMP

Equivalent to:

```sh
ping 10.200.200.1 -i0.08 -c 3000 -s 1200
```

but with verified unique payloads:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200
```

Run four parallel streams:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 -P 4
```

`--threads` is also accepted:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 --threads 4
```

`-c` is the packet count per stream. For example, `-c 3000 -P 4` sends
`12000` total ICMP echo requests.

For UDP, raw TCP, and `tcp-stream`, parallel streams use consecutive ports. For
example, `--port 50001 -P 4` uses ports `50001`, `50002`, `50003`, and `50004`
on both the client and server side.

### UDP

Start the echo server on the remote host:

```sh
./verify_ping.py --server --protocol udp --port 50001 -P 4
```

If `--port` is omitted in server mode, the tool chooses or receives a random
port and prints it:

```sh
./verify_ping.py --server --protocol udp
```

Run the UDP client against that port:

```sh
./verify_ping.py 10.200.200.1 --protocol udp --port 50001 -i 0.08 -c 3000 -s 1200 -P 4
```

### Raw TCP

Start the raw TCP echo responder on the remote host:

```sh
sudo ./verify_ping.py --server --protocol tcp --port 50002 -P 4
```

Run the raw TCP client:

```sh
sudo ./verify_ping.py 10.200.200.1 --protocol tcp --port 50002 -i 0.08 -c 3000 -s 1200 -P 4
```

Raw TCP mode does not call `connect()` or `accept()`. It builds IPv4/TCP
headers manually, sends standalone TCP segments with payload, and the responder
echoes matching test payloads back as raw TCP segments. Non-test TCP packets,
including kernel-generated RST packets, are ignored by the verifier.

### TCP Stream

The older application-level TCP stream echo mode is still available as
`tcp-stream`:

```sh
./verify_ping.py --server --protocol tcp-stream --port 50003 -P 4
./verify_ping.py 10.200.200.1 --protocol tcp-stream --port 50003 -i 0.08 -c 3000 -s 1200 -P 4
```

TCP stream mode uses a normal TCP connection and frames each payload internally
before echoing it.

While a UDP or raw TCP server is receiving test traffic it prints one line per
second, and one more when the burst ends, so the far end shows whether packets
arrive at all (handy when debugging a firewall):

```text
[14:02:11] rx=50 pkt/s streams=4 clients=1 total=50
[14:02:12] rx=50 pkt/s streams=4 clients=1 total=100
[14:02:13] idle, total received 100
```

Pass `--progress 0` to the server to silence it. On the client `--progress N`
prints a line every N verified replies (default 100).

Print every verified reply:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 -v
```

Wait longer for late replies after the last packet:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 -W 5
```

## Directional statistics

A plain echo test only sees a round trip: when a reply never comes back it
cannot tell whether the request was dropped on the way *to* the server or the
echo was dropped on the way *back*. `verify-ping` resolves this for UDP and raw
TCP with a TWAMP-style scheme:

1. Every request carries a zeroed 12-byte **server stamp** after the client
   header. The echo server fills it with `rseq`, a per-stream counter of the
   order in which requests actually arrived at the server, before echoing.
2. The server keeps an **arrival log** per stream (the sequence numbers it
   received, in arrival order), keyed by the run nonce.
3. After the run, the client fetches that log **in-band, over the same
   socket and port the test used**, and reconciles it with what it sent and
   what it verified. See [Fetching the arrival log](#fetching-the-arrival-log).

Payload verification is unaffected: the stamp is normalized back to zero before
the SHA-256 check, so the digest still covers the entire packet.

The client then reports, per stream and in total:

```text
--- directional statistics (server arrival log fetched in-band after the run) ---
sent=40 reached_server=38 verified=36
loss: forward=2 (5.000%) reverse=2 (5.000%) total=4 (10.000%)
reorder: forward=1 reverse=1 end_to_end=2  forward_dup=0
forward-lost seqs (never reached server): 5, 17
reverse-lost seqs (echo never returned): 9, 30
```

- `forward` loss: requests that never reached the server
  (`sent − reached_server`).
- `reverse` loss: requests the server received and echoed, whose echo never
  came back (`reached_server − verified`).
- `reorder forward`: packets that arrived at the server after a higher sequence
  number had already arrived (sender order vs. server arrival order).
- `reorder reverse`: echoes that arrived at the client after a later-emitted
  echo (server emission order `rseq` vs. client arrival order). Because this
  compares against the order the server *actually sent*, forward reordering
  does not leak into the reverse count.
- `reorder end_to_end`: what a naive tool would see (sender order vs. client
  arrival order), for reference.
- `forward_dup`: a sequence number the server saw more than once. Reverse
  duplicates are the regular `duplicates` counter.

Reordering uses the RFC 4737 late-arrival definition: an entry counts as
reordered when it is below the running maximum of the ordering key.

### Fetching the arrival log

No extra port is needed. The fetch happens **only after the run** (once the
`-W` wait for late replies has elapsed) and uses the very same UDP socket or
raw TCP port pair the test ran on, so it crosses the same firewall rule and
the same NAT mapping. Test traffic itself is unchanged.

The data path is lossy by definition, so the log is not sent as one message.
The server serves it as independent ~1 KB **chunks** (512 sequence numbers
each, below the usual MTU) and stays stateless: the client asks for chunk `k`,
the server answers with chunk `k`. The client tracks which chunks it has and
re-requests the missing ones until the log is complete or a deadline of
`max(10 s, 3 × -W)` passes. A lost chunk just costs one more round trip.

If the fetch cannot complete (old server without in-band support, or a path
too lossy even for retries) the client prints a warning and falls back to
round-trip statistics only. Use `--no-directional` to skip the fetch on
purpose.

### Not available for ICMP and tcp-stream

- **ICMP**: the echo is generated by the remote OS kernel, so there is no
  arrival log and no stamp. Only round-trip loss is reported.
- **tcp-stream**: TCP retransmits lost segments and delivers in order, so loss
  and reordering are masked by the transport and the question does not apply.

## Output

A successful run ends like this:

```text
--- 10.200.200.1 verified ping statistics ---
streams=1 count_per_stream=3000 sent=3000 verified=3000 lost=0 bad_payload=0 loss=0.000% duplicates=0 unexpected=0
checked_payload=3.4MB elapsed=239.923s
```

The command exits with status `0` only when all sent packets are verified and no
bad payloads are detected. It exits with status `1` if packets are missing or a
reply payload does not match the request.

## Notes

ICMP mode uses a raw ICMP socket, so `sudo` is normally required. Raw TCP mode
also requires `sudo` on both sides. UDP and `tcp-stream` do not need raw sockets,
but they do require the `verify-ping` echo server to be running on the other
side.

The sequence number is 16-bit, so one run is limited to `65535` packets per
stream. Payloads must be at least `54` bytes (client header + server stamp) so
each packet can carry the verification header.

The wire format changed in 0.6.0 (`vpng3` magic, server stamp) and the arrival
log moved in-band in 0.7.0 (the 0.6 TCP control port and `--control-port` are
gone). Run the same version on both sides; against an older server the client
reports that the arrival log fetch was incomplete and skips directional
statistics.
