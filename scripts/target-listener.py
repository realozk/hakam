#!/usr/bin/env python3
"""target-listener.py — no-op TCP sink for the Hakam demo.

Accepts connections on 10.99.0.10:80 (or $HOST:$PORT), drains data, closes.
Without a listener, attack nc(1) calls get RST before they can transmit the
HTTP payload — meaning XDP/DPI sees only SYN, never the signature pattern.

Run from setup-demo.sh; harmless if started twice (second instance exits on
EADDRINUSE).
"""
import argparse
import socket
import sys
import threading


def handle(conn: socket.socket) -> None:
    try:
        conn.settimeout(2.0)
        while True:
            chunk = conn.recv(8192)
            if not chunk:
                break
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="10.99.0.10")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--backlog", type=int, default=128)
    args = ap.parse_args()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((args.host, args.port))
    except OSError as e:
        print(f"target-listener: cannot bind {args.host}:{args.port}: {e}", file=sys.stderr)
        return 1
    s.listen(args.backlog)
    print(f"target-listener: ready on {args.host}:{args.port}", flush=True)

    try:
        while True:
            conn, _ = s.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            s.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
