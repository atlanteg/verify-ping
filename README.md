# verify-ping

`verify-ping` is a small ICMP/UDP/TCP echo tester for checking packet loss when
you need stronger guarantees than a regular `ping` summary.

It sends requests with a unique payload in every packet/message and verifies
that each reply contains exactly the same payload bytes. This helps confirm that
every counted reply belongs to the matching request and that the payload was not
corrupted or mixed up in transit.

## Features

- Unique deterministic payload per request
- SHA-256 payload verification for every reply
- ICMP, UDP, and TCP echo verification modes
- Regular `ping`-style options for count, interval, payload size, and port
- Parallel measurement streams with separate verification identifiers
- Reports lost requests, bad payloads, duplicates, and unexpected replies
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

Print every verified reply:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 -v
```

Wait longer for late replies after the last packet:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200 -W 5
```

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
stream. UDP/TCP payloads must be at least `42` bytes so each packet can carry the
verification header.
