#!/usr/bin/env python3
"""soc_mcp_bridge — docker-bridge-only TCP forwarder to a host-loopback service.

Binds the wazuh-stack_default network gateway IP (re-resolved at start;
falls back to SOC_MCP_BRIDGE_FALLBACK_GW) on SOC_MCP_BRIDGE_PORT and
forwards bidirectionally to SOC_MCP_BRIDGE_TARGET, so container-side
callers can reach loopback-only host services without exposing them to
the LAN.

Generalized from laya_bridge.py (commit 9e7e92c) so each loopback-only
MCP the wazuh manager needs gets its own one-unit bridge. First user:
soc-tickets-bridge (172.19.0.1:8768 -> 127.0.0.1:8768) — pointing a
bridge-network container at the host LAN IP never worked for a
loopback-bound listener, which is why the soc-tickets helper got
ConnectionRefused on every alert until 2026-09-27.

If the docker network is ever recreated with a different subnet,
Restart=on-failure re-resolves on the next start.
"""
import os
import socket
import subprocess
import threading

LISTEN_PORT = int(os.environ.get("SOC_MCP_BRIDGE_PORT", "8099"))
_target = os.environ.get("SOC_MCP_BRIDGE_TARGET", "127.0.0.1:8099")
_target_host, _target_port = _target.rsplit(":", 1)
TARGET = (_target_host, int(_target_port))
NETWORK = os.environ.get("SOC_MCP_BRIDGE_NETWORK", "wazuh-stack_default")
FALLBACK_GW = os.environ.get("SOC_MCP_BRIDGE_FALLBACK_GW", "172.19.0.1")


def _gateway() -> str:
    try:
        out = subprocess.run(
            ["docker", "network", "inspect", NETWORK,
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
    print(f"soc_mcp_bridge: {gw}:{LISTEN_PORT} -> {TARGET[0]}:{TARGET[1]}",
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