#!/usr/bin/env python3
"""CI-only live socket smoke test against 127.0.0.1 protocol sensors.

No internet addresses, production credentials, or raw log uploads. The
Docker processes are started by GitHub-hosted Actions and destroyed afterward.
"""
from __future__ import annotations
import json
import socket
import subprocess
import time
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from event_sanitizer import clean_event


def connect_local(port, wait=65):
    deadline=time.monotonic()+wait
    while time.monotonic()<deadline:
        try:
            return socket.create_connection(("127.0.0.1",port),timeout=4)
        except (OSError,TimeoutError):
            time.sleep(2)
    raise AssertionError("service not accepting local connections on "+str(port))


def read_banner(sock):
    sock.settimeout(4)
    try: return sock.recv(512)
    except (TimeoutError,OSError): return b""


def check_ssh():
    with connect_local(2222) as s:
        banner=read_banner(s)
        if not banner.startswith(b"SSH-2.0-"):
            raise AssertionError("Cowrie SSH protocol banner unavailable")
        # No login attempt needed to produce an authentic network connection event.
    return "ssh_banner_verified"


def check_telnet():
    with connect_local(2223) as s:
        # Small, benign local Telnet prelude; no actual password.
        s.settimeout(3)
        try: s.sendall(b"\r\n")
        except OSError: pass
    return "telnet_listener_verified"


def check_ftp():
    with connect_local(2121) as s:
        banner=read_banner(s)
        if not banner.startswith(b"220"):
            raise AssertionError("OpenCanary FTP 220 greeting not received")
        s.sendall(b"USER lab-test\r\n")
        read_banner(s)
        s.sendall(b"PASS synthetic-ci-value\r\n")
        read_banner(s)
        s.sendall(b"QUIT\r\n")
    return "ftp_banner_and_auth_simulation_verified"


def check_mysql():
    with connect_local(13306) as s:
        greeting=read_banner(s)
        if len(greeting)<5 or greeting[4]!=10:
            raise AssertionError("OpenCanary MySQL protocol-v10 handshake unavailable")
    return "mysql_protocol_handshake_verified"


def check_redis():
    with connect_local(16379) as s:
        s.sendall(b"*1\r\n$4\r\nPING\r\n")
        read_banner(s)
    return "redis_listener_verified"


def run(cmd):
    return subprocess.check_output(cmd,timeout=20,stderr=subprocess.DEVNULL,
                                   text=True,errors="replace")


def verify_real_cowrie_events():
    # Read the actual on-container JSONL; don't echo raw evidence to CI logs.
    raw=run(["docker","exec","vynalth-lab-cowrie","cat",
             "/cowrie/cowrie-git/var/log/cowrie/cowrie.json"])
    observed=0
    sanitized=[]
    for line in raw.splitlines()[:500]:
        try: event=json.loads(line)
        except ValueError: continue
        if event.get("eventid")=="cowrie.session.connect" and event.get("protocol") in ("ssh","telnet"):
            observed+=1
            item=clean_event(event,"cowrie")
            if item is not None:
                sanitized.append(item)
    if observed<1 or not sanitized:
        raise AssertionError("real Cowrie JSON event was not captured and sanitized")
    for item in sanitized:
        assert set(item)=={"event_type","source","protocol","source_ip_hash",
                          "country_code","request_path","action_taken"}
        assert item["source_ip_hash"] is None
    return {"cowrie_connection_events_verified":observed,
            "cowrie_sanitized_rows":len(sanitized)}


def verify_real_opencanary_events():
    # Docker stdout carries raw honeypot logs; do not print them.
    raw=run(["docker","logs","vynalth-lab-opencanary"])
    observed=0
    sanitized=[]
    for line in raw.splitlines()[:1000]:
        try: event=json.loads(line)
        except ValueError: continue
        if not isinstance(event,dict): continue
        item=clean_event(event,"opencanary")
        if item is not None:
            observed+=1
            sanitized.append(item)
    if observed<1 or not sanitized:
        raise AssertionError("OpenCanary event was not captured and sanitized")
    for item in sanitized:
        assert item["source_ip_hash"] is None
        assert item["source"]=="opencanary"
    return {"opencanary_events_verified":observed,
            "opencanary_sanitized_rows":len(sanitized)}


def main():
    statuses=[check_ssh(),check_telnet(),check_ftp(),check_mysql(),check_redis()]
    time.sleep(3)
    cowrie=verify_real_cowrie_events()
    opencanary=verify_real_opencanary_events()
    print(json.dumps({
        "proof_type":"ephemeral_github_runner_real_local_protocols",
        "public_internet_sensor":False,
        "production_tidb_inserted":False,
        "credentials_exported":False,
        "protocol_checks":statuses,
        **cowrie,**opencanary
    },sort_keys=True))


if __name__=="__main__":
    main()
