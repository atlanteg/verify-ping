# verify-ping

`verify-ping` is a small ICMP echo tester for checking packet loss when you
need stronger guarantees than a regular `ping` summary.

It sends ICMP echo requests with a unique payload in every packet and verifies
that each echo reply contains exactly the same payload bytes. This helps confirm
that every counted reply belongs to the matching request and that the payload was
not corrupted or mixed up in transit.

## Features

- Unique deterministic payload per ICMP request
- SHA-256 payload verification for every reply
- Regular `ping`-style options for count, interval, and payload size
- Reports lost requests, bad payloads, duplicates, and unexpected replies
- No third-party Python dependencies

## Requirements

- Python 3.9+
- macOS or Linux
- Root/admin privileges for raw ICMP sockets

## Usage

Equivalent to:

```sh
ping 10.200.200.1 -i0.08 -c 3000 -s 1200
```

but with verified unique payloads:

```sh
sudo ./verify_ping.py 10.200.200.1 -i 0.08 -c 3000 -s 1200
```

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
sent=3000 verified=3000 lost=0 bad_payload=0 duplicates=0 unexpected=0
checked_payload=3.4MB elapsed=239.923s
```

The command exits with status `0` only when all sent packets are verified and no
bad payloads are detected. It exits with status `1` if packets are missing or a
reply payload does not match the request.

## Notes

The tool uses a raw ICMP socket, so `sudo` is normally required. The ICMP
sequence number is 16-bit, so one run is limited to `65535` packets.

