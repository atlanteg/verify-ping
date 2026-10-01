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
- Reverse mode (`-R`, like `iperf3 -R`): the server probes, the client echoes (UDP)
- Path hunt (`--hunt`): many flows on different ports to land on different ECMP
  paths, ranked by round trip and by relative one-way delay per direction
- Live progress on both sides; no extra ports beyond the test ports
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

### Reverse mode (`-R`)

Like `iperf3 -R`: the client still initiates everything (so it works from
behind NAT and only the server needs an open port), but then the **roles
swap** — the server sends the probes and this client echoes them. The report
is still printed on the client.

`-R` does **not** change which side connects. If host A can reach host B but
not the other way round, the client always runs on A; without `-R` A probes
B, with `-R` B probes A through the path A opened. Use `-R` when you want the
unreachable side to be the sender:

```sh
./verify_ping.py --server --protocol udp --port 50001 -P 4      # remote, unchanged
./verify_ping.py 10.200.200.1 --protocol udp --port 50001 -P 4 -c 3000 -i 0.08 -s 1200 -R
```

The client sends an in-band start request per stream (count, interval, size,
`-W`) and retries it until the server acknowledges; the server then runs the
same prober state machine the client normally runs (unique payloads, SHA-256
verification of each echo, reply order) toward the client's address. While
the run lasts the client prints the per-second `rx=` line, since it is now the
echo side. Afterwards it pulls the server's reply log and summary in-band and
combines them with its own arrival log, so the directional block reads with
the roles swapped: **forward = server → client, reverse = client → server**.

```text
--- 10.200.200.1:50001 verified udp statistics (-R: server probes, client echoes) ---
streams=1 count_per_stream=40 sent=40 verified=36 lost=4 bad_payload=0 loss=10.000% duplicates=0 unexpected=0

note: -R swaps the roles, so below forward = server -> client and reverse = client -> server

--- directional statistics (client arrival log fetched in-band after the run) ---
sent=40 reached_client=38 verified=36
loss: forward=2 (5.000%) reverse=2 (5.000%) total=4 (10.000%)
reorder: forward=1 reverse=1 end_to_end=2  forward_dup=0
forward-lost seqs (never reached client): 9, 30
reverse-lost seqs (echo never returned): 5, 17
```

A stream whose start is never acknowledged (its port is blocked toward the
server, or the server is too old) is reported as such and skipped. `-R` is
currently UDP only.

### Path hunt (`--hunt`)

Backbones spread traffic over parallel links and paths by hashing the
5‑tuple (addresses, protocol, ports). Two flows between the same hosts can
therefore take different paths with different delay — and the path *back* is
hashed independently of the path *there*. `--hunt FLOWS` runs many
interleaved flows, each with its own source port (and destination port from
the server's `-P` range; ICMP varies the identifier), and ranks them:

```sh
./verify_ping.py --server --protocol udp --port 50001 -P 8            # remote
./verify_ping.py 10.200.200.1 --protocol udp,tcp,icmp --port 50001 -P 8 --hunt 32 -c 50 -i 0.05
```

`-P` is the number of server ports to spread over (must match the server),
`--hunt` the number of flows; flows wrap around the port range. Flows are
phase-shifted evenly across one interval, so a round of probes never leaves
as one burst that would queue behind itself and bias the same flows' minima
every time. With a
comma-separated `--protocol` list the protocols run one after another and a
cross-protocol summary follows. Raw TCP and ICMP still need `sudo`.

One server process can serve every protocol at once — UDP and TCP are
separate port spaces, so the same `--port` range works for both:

```sh
sudo ./verify_ping.py --server --protocol all --port 50001 -P 8     # udp + raw tcp + tcp-stream + icmp observer
sudo ./verify_ping.py --server --protocol udp,tcp --port 50001 -P 8
```

Each protocol runs in its own thread; if one cannot start (raw TCP without
root, port already in use) the process reports it and exits with status 1.

Before starting a server on a new host, check that the ports are free for
both transports:

```sh
./verify_ping.py --check-ports --port 20100 -P 8
```

It binds each port over UDP and TCP exactly as the servers would, reports
`free` / `BUSY (reason)` per port and transport, warns if the range overlaps
the ephemeral range, and releases everything. Exit status 1 if anything is
busy.

Pick a `--port` range **outside the local ephemeral port range** (Linux:
`cat /proc/sys/net/ipv4/ip_local_port_range`, usually 32768–60999). A port in
that range may be taken by an *outgoing* connection at any moment; `bind()`
then fails with "Address already in use" although `netstat -l` shows nothing.
The server says so when it happens. Ports like `20100–20107` are safe.
On the client, `--protocol all` means `icmp,udp,tcp-stream,tcp` — reachability
first, then the modes that work through NAT, raw TCP last. A protocol that
cannot start (no connection, no root) is reported and skipped; the others
still run. `tcp-stream` opens all its connections at once with one shared
timeout and carries on with those that succeed, naming the rest: *timed
out* means nothing came back at all (filtered, or no host), *refused* means
the host answered but nothing listens on that port.

Each protocol prints a table sorted by minimum RTT:

```text
--- path hunt: udp, 8 flows x 50 probes ---
flow path  src->dst         rtt_min   rtt_p50   fwd_rel   rev_rel     ok/sent    loss  lost f/r
   3 A     41233->50003     197.412   197.630    +0.000    +0.312    50/50      0.00%       0/0
   7 A     50981->50007     197.418   197.601    +0.004    +0.309    50/50      0.00%       0/0
   1 B     62553->50001     198.905   199.120    +1.480    +0.000    49/50      2.00%       0/1
   ...
paths by rtt_min (tolerance 0.15 ms):
  A: 197.412 ms  flows [3, 7, 4]
  B: 198.905 ms  flows [1, 2, 8, 5, 6]
best round trip: flow 3 (41233->50003) 197.412 ms, path A
forward (client -> server): 2 level(s), spread 1.480 ms; fastest: flows [3, 4, 7]
reverse (server -> client): 3 level(s), spread 0.312 ms; fastest: flows [1, 2, 5, 6, 8]
  no flow is fastest both ways (asymmetric ECMP)
```

When every flow lands on one path the table is folded to its top rows, and
a direction where most flows tie is summarised as `26 of 32 flows (single
path within tolerance)` instead of a list. Progress lines are off under
`--hunt` unless `--progress N` is given.

- `rtt_min` is the propagation floor of that flow's path pair; `rtt_p50` the
  typical value. Flows are grouped into paths (`A`, `B`, …) by gaps: a new
  group starts only where sorted `rtt_min` values leave a gap wider than
  `--hunt-tolerance` (default 0.15 ms). A "level" is a group with at least
  two flows; single flows are reported as outliers, and a group whose values
  spread continuously over more than twice the tolerance is flagged as
  queueing rather than distinct paths — more probes per flow (`-c`) sharpen
  the minima.
- `fwd_rel` / `rev_rel` are the **relative one‑way delays**, each shown as
  the excess over the best flow in that direction. They come from the server
  receive stamp: `fwd = server_recv − client_send`, `rev = client_recv −
  server_recv`. Both contain the unknown clock offset between the hosts
  (with opposite signs), and that offset is the same for every flow in a
  run, so *differences between flows* are exact while absolute one‑way delay
  is not measurable without synchronised clocks. Flows are sent interleaved,
  so clock drift affects them all alike.
- `lost f/r` is the per-flow loss split from the directional statistics.
- ICMP has no server stamp, so it is ranked by round trip only.

The final summary names the lowest round trip per protocol and overall, and
the flows that were fastest forward and reverse — the 5‑tuples to pin a
latency-sensitive connection to.

### Absolute one-way delay and clock sync

Every packet also carries wall-clock stamps (client send, server receive),
so absolute one-way delays *can* be computed — they are only meaningful when
both clocks are disciplined. The tool checks that itself rather than trusting
you: each side reads the kernel's view of its clock (`adjtimex(2)`: the
`STA_UNSYNC` flag and the error estimate that chrony / ntpd / ptp4l
maintain; `timedatectl` as a fallback), the server reports its status
in-band, and the client prints both:

```text
--- one-way delay ---
clocks: client synced, est. error ±0.412 ms (kernel); server synced, est. error ±0.087 ms (kernel)
forward (client -> server): min 13.871 ms p50 14.020 ms | reverse (server -> client): min 14.176 ms p50 14.310 ms  (valid within ±0.499 ms)
asymmetry (forward - reverse, by minima): -0.305 ms
```

The bound is the sum of both error estimates. The estimate comes from the
kernel's `esterror` when the daemon maintains it (ntpd, ptp4l), else from
`chronyc tracking` (|offset| + root dispersion + root delay / 2), else from
the kernel's max error when it is under 10 ms; systemd-timesyncd provides
none and lets the kernel max error drift into hundreds of milliseconds, so
hosts running it show "synced, error estimate unavailable". The bound must
also be at most half the round trip, otherwise the figures are withheld as
"larger than the delays being measured". If either side is not synced, has
no usable estimate, or cannot be read, the absolute figures are withheld and
the reason is printed (`server clock NOT synced`, `clock sync status
unknown on the client`, …); `--wallclock` prints them anyway, marked
UNVERIFIED. A one-way delay that comes out negative beyond the claimed error
proves the clocks disagree more than they admit, and the tool says so.

What counts as "synced enough": NTP over the internet typically gives
1–10 ms, which is too coarse for sub-millisecond asymmetry; chrony against a
nearby stratum-1 gives 0.1–1 ms; PTP or a GPS receiver gives microseconds.
The relative per-flow comparison in `--hunt` never needs any of this. `-R`
does not report one-way delay.

### TCP Stream

The older application-level TCP stream echo mode is still available as
`tcp-stream`:

```sh
./verify_ping.py --server --protocol tcp-stream --port 50003 -P 4
./verify_ping.py 10.200.200.1 --protocol tcp-stream --port 50003 -i 0.08 -c 3000 -s 1200 -P 4
```

TCP stream mode uses a normal TCP connection and frames each payload internally
before echoing it. Since 0.12.0 the server stamps every frame like UDP, so
`tcp-stream` yields round-trip *and* one-way delays per connection and takes
part in `--hunt` (each connection is one flow with its own source port). It
is the mode to use from behind a stateful NAT that drops raw segments. Loss
and reordering are not reported for it: TCP retransmits and reorders
underneath. `TCP_NODELAY` is set on both ends so Nagle does not skew the
timings.

The server log says, per protocol, when a client's test starts, how much is
arriving each second, and what the run totalled, so the far end shows whether
packets arrive at all (handy when debugging a firewall) and several servers in
one process stay tellable apart:

```text
[14:02:10] udp: test traffic from 10.0.0.7 started
[14:02:11] udp: rx=50 pkt/s streams=4 clients=1 total=50
[14:02:12] udp: rx=50 pkt/s streams=4 clients=1 total=100
[14:02:13] udp: finished, 100 packets over 4 stream(s) from 10.0.0.7
[14:02:20] tcp (raw): test traffic from 10.0.0.7 started
...
[14:02:31] tcp-stream: connection from 10.0.0.7:41822 on port 20100
[14:02:33] tcp-stream: 10.0.0.7:41822 closed, 58.6KB echoed
[14:02:40] icmp (observed; kernel answers): test traffic from 10.0.0.7 started
```

ICMP echo is answered by the kernel, so an `icmp` server only *observes*:
with root it watches echo requests that carry verify_ping payloads and logs
them like the others; without root it says so and the ICMP test still works.
`--protocol all` on the server includes it.

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

The server keys arrival logs by run nonce, not by port. After the first
round the client therefore retries a stream's chunks through the *other*
streams' sockets, so a stream whose own port is firewalled still gets its
verdict — typically `reached_server=0` with the note
`nothing reached the server on this port: forward path blocked`. That is the
quickest way to spot a security group that opened only the first port of a
`-P` range.

If a stream's log still cannot be completed it is reported as unavailable and
left out of the totals; the other streams are shown normally. Only when no
stream's log can be fetched at all (old server without in-band support, or a
path too lossy even for retries) does the client fall back to round-trip
statistics only. Use `--no-directional` to skip the fetch on purpose.

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

Both sides print their version on start-up (`verify_ping v0.12.3 …`), and
`--version` prints it alone. After a UDP, raw TCP or tcp-stream run the
client also asks the server for its version and warns when the two differ.

ICMP mode uses a raw ICMP socket, so `sudo` is normally required. Raw TCP mode
also requires `sudo` on both sides. UDP and `tcp-stream` do not need raw sockets,
but they do require the `verify-ping` echo server to be running on the other
side.

The sequence number is 16-bit, so one run is limited to `65535` packets per
stream. Payloads must be at least `70` bytes (client header + server stamp) so
each packet can carry the verification header.

The wire format changed in 0.6.0 (`vpng3` magic, server stamp), the arrival
log moved in-band in 0.7.0 (the 0.6 TCP control port and `--control-port` are
gone), and the in-band control messages gained a type byte and log kinds in
0.8.0 (`vpnc4`, for `-R`); 0.10.0 added wall-clock stamps and the clock status
exchange (`vpng4`). Run the same version on both sides; against an
older server the client reports that the log fetch was incomplete (or, under
`-R`, that the start was never acknowledged) and skips directional
statistics.
