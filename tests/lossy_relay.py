#!/usr/bin/env python3
"""UDP relay that injects deterministic loss + reordering per direction.

Usage: lossy_relay.py <repo dir> <listen port> <upstream port>

client -> :LISTEN (relay) -> 127.0.0.1:UPSTREAM ; replies flow back the same way.
Forward rules act on client->server packets, reverse rules on server->client.
The first CTRL_REPLY_DROP in-band control replies are dropped as well, to
prove the client's chunk re-request (pull ARQ) and the -R start retry work.

Expected verify_ping verdicts through this relay (single stream, -c 40):
  normal mode: forward-lost 5,17  reverse-lost 9,30  reorder fwd=1 rev=1 e2e=2
  -R mode:     forward-lost 9,30  reverse-lost 5,17  reorder fwd=1 rev=1 e2e=2

Single-client only: it remembers the last client address, so do not use it
with --hunt or -P > 1.
"""
import selectors
import socket
import sys

sys.path.insert(0, sys.argv[1])
import verify_ping as vp  # noqa: E402

LISTEN = int(sys.argv[2])
UPSTREAM = ("127.0.0.1", int(sys.argv[3]))

FWD_DROP = {5, 17}
REV_DROP = {9, 30}
# hold `hold` until `release` passes, then emit hold after release -> 1 late arrival
FWD_SWAP = (12, 13)
REV_SWAP = (20, 21)
CTRL_REPLY_DROP = 2

cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cs.bind(("127.0.0.1", LISTEN))
ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ss.connect(UPSTREAM)
sel = selectors.DefaultSelector()
sel.register(cs, selectors.EVENT_READ)
sel.register(ss, selectors.EVENT_READ)

client_addr = None
fwd_held = None
rev_held = None
ctrl_dropped = 0
ctrl_seen = 0
print(f"relay :{LISTEN} -> {UPSTREAM} fwd_drop={sorted(FWD_DROP)} rev_drop={sorted(REV_DROP)} "
      f"fwd_swap={FWD_SWAP} rev_swap={REV_SWAP} ctrl_reply_drop={CTRL_REPLY_DROP}", flush=True)

while True:
    for key, _ in sel.select():
        if key.fileobj is cs:
            data, client_addr = cs.recvfrom(65535)
            seq = (vp.parse_payload(data) or {}).get("seq")
            if seq in FWD_DROP:
                continue
            if seq == FWD_SWAP[0]:
                fwd_held = data
                continue
            ss.send(data)
            if seq == FWD_SWAP[1] and fwd_held is not None:
                ss.send(fwd_held)
                fwd_held = None
        else:
            data = ss.recv(65535)
            if data.startswith(vp.CTRL_MAGIC):
                ctrl_seen += 1
                if ctrl_dropped < CTRL_REPLY_DROP:
                    ctrl_dropped += 1
                    print(f"relay: dropped control reply #{ctrl_seen}", flush=True)
                    continue
                cs.sendto(data, client_addr)
                continue
            seq = (vp.parse_payload(data) or {}).get("seq")
            if seq in REV_DROP:
                continue
            if seq == REV_SWAP[0]:
                rev_held = data
                continue
            cs.sendto(data, client_addr)
            if seq == REV_SWAP[1] and rev_held is not None:
                cs.sendto(rev_held, client_addr)
                rev_held = None
