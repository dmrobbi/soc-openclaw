#!/usr/bin/env python3
"""laya-bridge — docker-bridge-only TCP forwarder to host-loopback laya-serve.

Binds the wazuh-stack_default network gateway IP (re-resolved at start;
falls back to the last known) on :8099 and forwards bidirectionally to
127.0.0.1:8099, so container-side callers (soc_decision in the wazuh
manager) can reach the loopback-only laya-serve without exposing laya
to the LAN. If the docker network is ever recreated with a different
subnet, Restart=on-failure re-resolves on the next start.
"""
import socket
import subprocess
import threading

LISTEN_PORT = 8099
TARGET = ("127.0.0.1", 8099)
FALLBACK_GW = "172.19.0.1"


def _gateway() -> str:
    try:
        out = subprocess.run(
            ["docker", "network", "inspect", "wazuh-stack_default",
             "--format", "{{(index .IPAM.Config 0).Gateway}}"],
            capture_output=True, text=True, timeout=10,
        ).stdout.strip()
        if out:
            return out
    except Exception:
        pass
    return FALLBACK_GW


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> None:
    gw = _gateway()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((gw, LISTEN_PORT))
    srv.listen(16)
    print(f"laya-bridge: {gw}:{LISTEN_PORT} -> {TARGET[0]}:{TARGET[1]}",
          flush=True)
    while True:
        client, _addr = srv.accept()
        try:
            upstream = socket.create_connection(TARGET, timeout=5)
        except OSError:
            client.close()
            continue
        threading.Thread(target=_pipe, args=(client, upstream),
                         daemon=True).start()
        threading.Thread(target=_pipe, args=(upstream, client),
                         daemon=True).start()


if __name__ == "__main__":
    main()