#!/usr/bin/env python3
"""UDP relay that makes early flows slow after a while, for testing --reroll.

Usage: degrading_relay.py <listen port> <upstream port> <degrade after s> <extra ms>

Every client address gets its own upstream socket (so many flows work).
Flows first seen before <degrade after> seconds get <extra ms> added to
their server->client packets once that time has passed; flows created later
are relayed at full speed. A held flow therefore degrades and a fresh batch
offers something better, which is exactly what --reroll must notice and do.
"""
import heapq
import selectors
import socket
import sys
import time

LISTEN = int(sys.argv[1])
UPSTREAM = ("127.0.0.1", int(sys.argv[2]))
DEGRADE_AFTER = float(sys.argv[3])
EXTRA = float(sys.argv[4]) / 1000.0

cs = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
cs.bind(("127.0.0.1", LISTEN))
sel = selectors.DefaultSelector()
sel.register(cs, selectors.EVENT_READ)
flows = {}      # client addr -> (upstream sock, created_at)
by_sock = {}    # upstream sock -> client addr
delayed = []    # heap of (release time, seq, data, client addr)
seq = 0
start = time.monotonic()
print(f"relay :{LISTEN} -> {UPSTREAM}; flows older than {DEGRADE_AFTER}s get +{EXTRA * 1000:.0f} ms "
      f"on the way back after that time", flush=True)

while True:
    timeout = None
    now = time.monotonic()
    if delayed:
        timeout = max(0.0, delayed[0][0] - now)
    for key, _ in sel.select(timeout):
        if key.fileobj is cs:
            data, addr = cs.recvfrom(65535)
            if addr not in flows:
                up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up.connect(UPSTREAM)
                up.setblocking(False)
                flows[addr] = (up, time.monotonic())
                by_sock[up] = addr
                sel.register(up, selectors.EVENT_READ)
            flows[addr][0].send(data)
        else:
            data = key.fileobj.recv(65535)
            addr = by_sock[key.fileobj]
            created = flows[addr][1]
            now = time.monotonic()
            if now - start >= DEGRADE_AFTER and created - start < DEGRADE_AFTER:
                seq += 1
                heapq.heappush(delayed, (now + EXTRA, seq, data, addr))
            else:
                cs.sendto(data, addr)
    now = time.monotonic()
    while delayed and delayed[0][0] <= now:
        _t, _s, data, addr = heapq.heappop(delayed)
        cs.sendto(data, addr)
