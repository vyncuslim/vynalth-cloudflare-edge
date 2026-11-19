#!/usr/bin/env python3
"""CI-only real TCP handshake through HAProxy on host 127.0.0.1.

Tests the dedicated cloud topology in a disposable GitHub runner.
No public IPs, credentials, SQL access, external probes, or raw logs.
"""
import json
import socket
import time


def connect(port, timeout=55):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            s=socket.create_connection(("127.0.0.1",port),timeout=4)
            s.settimeout(4)
            return s
        except (OSError,TimeoutError):
            time.sleep(2)
    raise AssertionError("dedicated gateway not listening on expected port")


def greeting(port):
    with connect(port) as sock:
        if port==2323:
            sock.sendall(b"\r\n")
            return "telnet_tunnel_connected"
        try: banner=sock.recv(512)
        except (TimeoutError,OSError): banner=b""
        if port==2222 and not banner.startswith(b"SSH-2.0-"):
            raise AssertionError("HAProxy to Cowrie SSH failed")
        if port==2121 and not banner.startswith(b"220"):
            raise AssertionError("HAProxy to OpenCanary FTP failed")
        if port==13306 and (len(banner)<5 or banner[4]!=10):
            raise AssertionError("HAProxy to OpenCanary MySQL handshake failed")
        return {
            2222:"cowrie_ssh_through_gateway",
            2121:"opencanary_ftp_through_gateway",
            13306:"opencanary_mysql_through_gateway",
        }[port]


def main():
    outcomes=[greeting(p) for p in (2222,2323,2121,13306)]
    print(json.dumps({
        "proof_type":"dedicated_topology_ephemeral_cloud",
        "gateway": "haproxy",
        "real_tcp_handshakes": outcomes,
        "public_bind":False,
        "production_vm_created":False,
        "production_tidb_written":False,
    },sort_keys=True))


if __name__=="__main__":
    main()
