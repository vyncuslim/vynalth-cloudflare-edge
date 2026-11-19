#!/usr/bin/env python3
"""One-shot, signed, allowlisted event sender. Nothing is sent without --send.

Must run on a separate trusted collector host, NOT inside the public-facing
Cowrie/OpenCanary containers. No automatic retries or background process.
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ENDPOINT = "https://vynalthai.com/__vynalth/honeypot/sensors/v1"
FIELDS = frozenset(("event_type", "source", "protocol", "source_ip_hash",
                    "country_code", "request_path", "action_taken"))


def sign_message(raw, secret, when, nonce):
    if len(secret) < 32:
        raise ValueError("HMAC key too short")
    material = (str(when) + "\n" + nonce + "\n" + raw).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def validate_row(value):
    if not isinstance(value, dict) or set(value) - FIELDS:
        return False
    if value.get("event_type") != "suspicious_probe":
        return False
    if value.get("action_taken") != "observed":
        return False
    proto = value.get("protocol")
    source = value.get("source")
    if (proto in ("SSH", "TELNET") and source != "cowrie") or (
        proto in ("FTP", "MYSQL", "REDIS") and source != "opencanary"
    ):
        return False
    if proto not in ("SSH", "TELNET", "FTP", "MYSQL", "REDIS"):
        return False
    path = value.get("request_path")
    if not isinstance(path, str) or not path.startswith("/" + proto.lower() + "/"):
        return False
    if value.get("country_code") is not None:
        return False
    ip_hash = value.get("source_ip_hash")
    if ip_hash is not None and (not isinstance(ip_hash, str) or
                               len(ip_hash) != 64 or
                               any(c not in "0123456789abcdefABCDEF" for c in ip_hash)):
        return False
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--input", type=Path, required=True)
    ap.add_argument("--max-events", type=int, default=20)
    ap.add_argument("--send", action="store_true",
                    help="Explicitly send to the dedicated authenticated Worker endpoint")
    args = ap.parse_args()
    if args.max_events < 1 or args.max_events > 100:
        ap.error("max-events must be 1..100")
    key = os.getenv("HONEY_SENSOR_INGEST_KEY", "")
    if args.send and len(key) < 32:
        ap.error("Set a 32+ char HONEY_SENSOR_INGEST_KEY on the trusted collector")
    valid = inserted = sampled = rejected = 0
    with args.input.open("rt", encoding="utf-8") as data:
        for line in data:
            if valid >= args.max_events:
                break
            if len(line) > 1024:
                rejected += 1
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                rejected += 1
                continue
            if not validate_row(payload):
                rejected += 1
                continue
            valid += 1
            if not args.send:
                continue
            raw = json.dumps(payload, separators=(",", ":"))
            timestamp = int(time.time())
            nonce = str(uuid.uuid4())
            proof = sign_message(raw, key, timestamp, nonce)
            req = urllib.request.Request(ENDPOINT, data=raw.encode(),
                method="POST", headers={
                    "Content-Type": "application/json",
                    "X-Vynalth-Sensor-Time": str(timestamp),
                    "X-Vynalth-Sensor-Nonce": nonce,
                    "X-Vynalth-Sensor-Signature": proof,
                    "User-Agent": "VynalthHoneypotCollector/1.0"
                })
            try:
                with urllib.request.urlopen(req, timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as exc:
                status = exc.code
            except (urllib.error.URLError, TimeoutError):
                print("Transport failure; stopped without retry", file=sys.stderr)
                break
            if status == 201:
                inserted += 1
            elif status == 202:
                sampled += 1
            else:
                print("Non-success HTTP status; stopped without retry", file=sys.stderr)
                break
    print(json.dumps({
        "validated": valid, "rejected": rejected,
        "confirmed_insert_acknowledgments": inserted,
        "sampled_out": sampled, "sent": args.send,
        "source": "sanitized_protocol_events"
    }))


if __name__ == "__main__":
    main()
