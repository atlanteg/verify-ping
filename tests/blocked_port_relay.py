#!/usr/bin/env python3
"""Simulate a firewall that lets only the first data port through.

Usage: blocked_port_relay.py <listen port> <upstream port>

Listens on LISTEN and LISTEN+1. LISTEN <-> 127.0.0.1:UPSTREAM is relayed
verbatim (both directions); LISTEN+1 is a black hole: everything sent to it
is dropped, so that stream never reaches the server and never gets a reply.

Expected verify_ping verdicts (client -P 2 --port LISTEN, server -P 2):
  normal mode: stream 2 reached_server=0, "nothing reached the server on this port"
  -R mode:     stream 2 "server never acknowledged the start on port LISTEN+1"
"""
import selectors
import socket
import sys

LISTEN = int(sys.argv[1])
UPSTREAM = ("127.0.0.1", int(sys.argv[2]))

ok_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ok_port.bind(("127.0.0.1", LISTEN))
blocked = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
blocked.bind(("127.0.0.1", LISTEN + 1))
up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
up.connect(UPSTREAM)

sel = selectors.DefaultSelector()
for s in (ok_port, blocked, up):
    sel.register(s, selectors.EVENT_READ)

client_addr = None
dropped = 0
print(f"relay: {LISTEN} <-> {UPSTREAM} open, {LISTEN + 1} blackholed", flush=True)
while True:
    for key, _ in sel.select():
        if key.fileobj is ok_port:
            data, client_addr = ok_port.recvfrom(65535)
            up.send(data)
        elif key.fileobj is blocked:
            blocked.recvfrom(65535)
            dropped += 1
            if dropped in (1, 10, 100):
                print(f"relay: blackholed {dropped} packets on {LISTEN + 1}", flush=True)
        else:
            data = up.recv(65535)
            ok_port.sendto(data, client_addr)
