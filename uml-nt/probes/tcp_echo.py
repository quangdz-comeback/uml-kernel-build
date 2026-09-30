#!/usr/bin/env python3
"""Framed TCP echo server for the M5.1a netprobe gate.

Speaks the kernel↔helper wire protocol (D8): every message is one
2-byte big-endian length prefix followed by that many payload bytes —
the exact framing vdeplug-go's TCP transport (internal/transport
tcpConn) and the kernel's net_win.c use. The probe sends a payload and
requires the identical bytes back; this server echoes every frame.
"""
import socket
import sys


def recv_exact(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 19292
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    print(f"tcp_echo: listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, addr = srv.accept()
        with conn:
            print(f"tcp_echo: peer {addr}", flush=True)
            while True:
                head = recv_exact(conn, 2)
                if head is None:
                    break
                n = (head[0] << 8) | head[1]
                if n == 0:
                    break
                payload = recv_exact(conn, n)
                if payload is None:
                    break
                conn.sendall(head + payload)
                print(f"tcp_echo: echoed {n} bytes", flush=True)
        print("tcp_echo: peer gone", flush=True)


if __name__ == "__main__":
    main()
