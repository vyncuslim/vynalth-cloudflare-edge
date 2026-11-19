#!/usr/bin/env python3
"""Allowlist-only export of real Cowrie/OpenCanary events. No credentials or raw IP.

Reads one local JSONL file. Output is a new, sanitized JSONL stream compatible
with the existing vynalth_honeypot.honeypot_events INSERT-only table.
It does NOT forward data automatically or contact TiDB/Cloudflare.
"""
import argparse
import datetime as dt
import hashlib
import hmac
import ipaddress
import json
import sys
from pathlib import Path

COWRIE_EVENTS = {
    "cowrie.session.connect": "connect",
    "cowrie.session.closed": "disconnect",
    "cowrie.login.failed": "login_attempt",
    "cowrie.login.success": "login_attempt",
    "cowrie.command.input": "command_observed",
    "cowrie.command.failed": "command_observed",
    "cowrie.log.closed": "session_replay_available",
    "cowrie.session.file_download": "file_observed",
    "cowrie.session.file_upload": "file_observed",
}
OPEN_PORTS = {2121: "FTP", 13306: "MYSQL", 16379: "REDIS"}


def anonymous_network_marker(value, secret, timestamp):
    """Daily pseudonym for correlation. Not anonymization or user identity."""
    if not secret or len(secret) < 32 or not isinstance(value, str):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    date = timestamp.astimezone(dt.timezone.utc).date().isoformat()
    data = ("sensor-v1|" + date + "|" + address.compressed).encode()
    return hmac.new(secret.encode(), data, hashlib.sha256).hexdigest()


def clean_cowrie(event, secret=None, now=None):
    if not isinstance(event, dict):
        return None
    eventid = event.get("eventid")
    kind = COWRIE_EVENTS.get(eventid)
    protocol = str(event.get("protocol") or "").lower()
    if kind is None or protocol not in {"ssh", "telnet"}:
        return None
    timestamp = now or dt.datetime.now(dt.timezone.utc)
    return {
        "event_type": "suspicious_probe",
        "source": "cowrie",
        "protocol": protocol.upper(),
        "source_ip_hash": anonymous_network_marker(event.get("src_ip"), secret, timestamp),
        "country_code": None,
        "request_path": "/" + protocol + "/" + kind,
        "action_taken": "observed",
    }


def clean_opencanary(event, secret=None, now=None):
    if not isinstance(event, dict):
        return None
    port = event.get("dst_port")
    if isinstance(port, bool) or not isinstance(port, int):
        return None
    protocol = OPEN_PORTS.get(port)
    if protocol is None or not isinstance(event.get("logtype"), int):
        return None
    timestamp = now or dt.datetime.now(dt.timezone.utc)
    return {
        "event_type": "suspicious_probe",
        "source": "opencanary",
        "protocol": protocol,
        "source_ip_hash": anonymous_network_marker(event.get("src_host"), secret, timestamp),
        "country_code": None,
        "request_path": "/" + protocol.lower() + "/probe",
        "action_taken": "observed",
    }


def clean_event(event, source, secret=None, now=None):
    if source == "cowrie":
        return clean_cowrie(event, secret=secret, now=now)
    if source == "opencanary":
        return clean_opencanary(event, secret=secret, now=now)
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, choices=["cowrie", "opencanary"])
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-lines", type=int, default=1000)
    args = parser.parse_args()
    if args.max_lines < 1 or args.max_lines > 10000:
        parser.error("--max-lines must be between 1 and 10000")
    if args.output.resolve() == args.input.resolve():
        parser.error("Never overwrite the source evidence log")
    import os
    secret = os.environ.get("HONEY_SENSOR_NETWORK_HMAC_KEY")
    if secret and len(secret) < 32:
        parser.error("HONEY_SENSOR_NETWORK_HMAC_KEY must be at least 32 characters")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    processed = kept = 0
    with args.input.open("rt", encoding="utf-8", errors="replace") as src, \
         args.output.open("wt", encoding="utf-8") as dest:
        try:
            os.chmod(args.output, 0o600)
        except OSError:
            pass
        for line in src:
            if processed >= args.max_lines:
                break
            processed += 1
            if len(line) > 65536:
                continue
            try:
                raw = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            clean = clean_event(raw, args.source, secret=secret)
            if clean is None:
                continue
            dest.write(json.dumps(clean, separators=(",", ":")) + "\n")
            kept += 1
    print(json.dumps({"input_lines": processed, "sanitized_events": kept,
                      "output": str(args.output)}))


if __name__ == "__main__":
    main()
