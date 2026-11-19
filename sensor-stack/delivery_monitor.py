#!/usr/bin/env python3
"""Offline SOC health gate for local sensor capture and signed delivery outbox.

Builds a signed privacy-safe status document. A critical condition produces
nonzero exit when called as the standalone monitor. No network, Telegram,
email, raw IP, plaintext credentials or untrusted commands are emitted.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys

from durable_spool import EvidenceError
from rotation_collector import health_status,_signed_health,_load_key,_private_health_parent
from spool_uplink import inspect

VERSION="vynalth-sensor-operations-v1"


def monitor(spool_db,collector_health,alert_path,key,
            backlog_max=500,min_free_mb=128):
    if not isinstance(key,str) or len(key)<32:
        raise EvidenceError("protected local alert signing key missing")
    if not 0<=backlog_max<=100000 or not 0<=min_free_mb<=4096:
        raise EvidenceError("invalid monitor threshold")
    reasons=[]
    try:
        upstream=health_status(collector_health,key)
        sensor_rows=upstream["spool_queue_events"]
    except (OSError,ValueError,KeyError,EvidenceError,TypeError):
        upstream=None
        sensor_rows=None
        reasons.append("collector_unhealthy_or_stale")
    try:
        outbox=inspect(spool_db,key)
        pending=outbox["unsent"]
        held=outbox["operator_review_needed"]
        if pending>backlog_max:
            reasons.append("outbox_backlog")
        if held>0:
            reasons.append("delivery_requires_review")
    except (OSError,sqlite3.Error,ValueError,KeyError,EvidenceError,TypeError):
        pending=held=None
        reasons.append("outbox_missing_or_invalid")
    try:
        free=shutil.disk_usage(Path(spool_db).parent).free
        if free < min_free_mb*1024*1024:
            reasons.append("disk_capacity_low")
    except OSError:
        reasons.append("disk_unknown")
    report={
        "schema":VERSION,
        "checked_at_utc":datetime.now(timezone.utc).isoformat(
            timespec="seconds").replace("+00:00","Z"),
        "status":"critical" if reasons else "healthy",
        "reason_codes":sorted(set(reasons)),
        "sanitized_event_count":sensor_rows,
        "pending_upload_events":pending,
        "held_for_operator_review":held,
        "raw_telemetry_included":False,
        "network_alerts_sent":False,
        "real_internet_attacks_verified":False,
    }
    _signed_health(Path(alert_path),report,key.encode())
    return report


def verify_alert(path,key,max_age=180,now=None):
    if not isinstance(key,str) or len(key)<32 or not 10<=max_age<=86400:
        raise EvidenceError("invalid alert verification inputs")
    path=Path(path)
    _private_health_parent(path)
    if not path.is_file() or path.stat().st_size>32768:
        raise EvidenceError("missing/oversized alert")
    wrapper=json.loads(path.read_text(encoding="utf-8"))
    report=wrapper.get("report")
    signature=wrapper.get("hmac_sha256")
    if not isinstance(report,dict) or report.get("schema")!=VERSION:
        raise EvidenceError("alert version missing")
    encoded=json.dumps(report,sort_keys=True,separators=(",",":"))
    expected=hmac.new(key.encode(),encoded.encode(),hashlib.sha256).hexdigest()
    if not isinstance(signature,str) or not hmac.compare_digest(expected,signature):
        raise EvidenceError("alert HMAC invalid")
    when=datetime.fromisoformat(report["checked_at_utc"].replace("Z","+00:00"))
    now=now or datetime.now(timezone.utc)
    delta=(now-when).total_seconds()
    if delta<0 or delta>max_age:
        raise EvidenceError("alert heartbeat stale")
    status=report["status"]
    if status not in {"healthy","critical"}:
        raise EvidenceError("invalid alert status")
    return {"alert_verified":True,"status":status,
            "reason_codes":report["reason_codes"],
            "age_seconds":int(delta),"private":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--db",type=Path,required=False)
    p.add_argument("--collector-health",type=Path,required=False)
    p.add_argument("--alert",type=Path,required=True)
    p.add_argument("--check",action="store_true")
    p.add_argument("--max-pending",type=int,default=500)
    p.add_argument("--min-free-mb",type=int,default=128)
    args=p.parse_args()
    try:
        key=_load_key()
        if args.check:
            response=verify_alert(args.alert,key)
        else:
            if args.db is None or args.collector_health is None:
                raise EvidenceError("explicit local paths required")
            response=monitor(args.db,args.collector_health,args.alert,key,
                             args.max_pending,args.min_free_mb)
        print(json.dumps(response,sort_keys=True))
        if response.get("status")=="critical":
            raise SystemExit(2)
    except (EvidenceError,OSError,sqlite3.Error,ValueError,KeyError,TypeError):
        print("MONITOR_BLOCKED: signed local health or delivery status not valid",
              file=sys.stderr)
        raise SystemExit(2)


if __name__=="__main__":
    main()
