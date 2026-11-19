#!/usr/bin/env python3
"""One-shot OFF-by-default loss-aware signed spool -> Cloudflare Worker sender.

The sanitized_event SQLite queue is the ONLY source. Dry run is read-only.
Before a network request, the local event is durably reserved, then marked as
confirmed-201, sampled-out-202 or held-for-review. After an uncertain crash
or response the event is NEVER automatically retried, because TiDB does not
yet have durable unique event-ID constraints. This is NOT exactly-once.
201 is only an INSERT driver acknowledgement, NOT independent SQL readback.
Never sends raw IPs, usernames, passwords, commands, TTY or malware bytes.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import sys
import time
import urllib.error
import urllib.request
import uuid

from durable_spool import EvidenceError,safe_store_path,conn_for,_mac,verify as verify_spool
from send_summaries import ENDPOINT,sign_message,validate_row

VERSION="vynalth-sensor-outbox-v1"
MAPPING={
    "cowrie":{
      "connection":"connect","disconnection":"disconnect",
      "authentication_attempt":"login_attempt",
      "honeypot_login_accepted":"login_attempt",
      "shell_command":"command_observed",
      "tty_finalized":"session_replay_available","file_arrival":"file_observed"
    },
    "opencanary":{"service_probe":"probe"},
}
PROTOCOLS={"cowrie":{"SSH","TELNET"},"opencanary":{"FTP","MYSQL","REDIS"}}
TERMINAL={"insert_acknowledged","sampled_out"}
HELD={"uncertain","needs_review","reserved"}
VALID=TERMINAL|HELD


def _canonical(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":"),ensure_ascii=True)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")


def _mac_state(key,ref,status,stamp,http_code):
    body=_canonical({"v":VERSION,"event":ref,"status":status,
                     "time":stamp,"http_code":http_code})
    return hmac.new(key,b"outbox-state-v1|"+body.encode(),
                    hashlib.sha256).hexdigest()


def _ro(dbfile):
    path=safe_store_path(dbfile)
    if not path.is_file():
        raise EvidenceError("restricted spool missing")
    db=sqlite3.connect(path.resolve().as_uri()+"?mode=ro",uri=True,timeout=6)
    db.execute("PRAGMA query_only=ON")
    return db


def _schema(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS delivery_outbox(
      event_ref TEXT NOT NULL PRIMARY KEY,
      status TEXT NOT NULL,
      checked_at TEXT NOT NULL,
      http_code INTEGER NULL,
      status_hmac TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_delivery_state
      ON delivery_outbox(status,checked_at);
    """)


def _verified_states(db,key):
    for ref,state,stamp,code,signature in db.execute("""
      SELECT event_ref,status,checked_at,http_code,status_hmac
      FROM delivery_outbox ORDER BY rowid
    """):
        if state not in VALID:
            raise EvidenceError("unrecognized outbox status")
        expected=_mac_state(key,ref,state,stamp,code)
        if not isinstance(signature,str) or not hmac.compare_digest(expected,signature):
            raise EvidenceError("outbox status integrity failure")
        yield ref,state


def _summary(ref,sensor,payload,signature,key):
    if not isinstance(ref,str) or len(ref)!=64 or not all(
        c in "0123456789abcdef" for c in ref.lower()):
        raise EvidenceError("bad local event reference")
    if not hmac.compare_digest(_mac(key,sensor,ref,payload),signature):
        raise EvidenceError("forensic source HMAC mismatch")
    item=json.loads(payload)
    if (not isinstance(item,dict) or item.get("event_ref")!=ref or
        item.get("share_authorized") is not False or
        item.get("verified_intrusion") is not False or
        item.get("indicator_status")!="observation_only"):
        raise EvidenceError("untrusted forensic source")
    source=item.get("source")
    protocol=item.get("protocol")
    kind=item.get("event_class")
    if source not in MAPPING or protocol not in PROTOCOLS[source] or kind not in MAPPING[source]:
        raise EvidenceError("unrecognized protocol/event class")
    event={
        "event_type":"suspicious_probe",
        "source":source,"protocol":protocol,
        "source_ip_hash":None,"country_code":None,
        "request_path":"/"+protocol.lower()+"/"+MAPPING[source][kind],
        "action_taken":"observed",
    }
    if not validate_row(event):
        raise EvidenceError("Worker allowlist mismatch")
    serialized=_canonical(event)
    if len(serialized.encode())>1024:
        raise EvidenceError("signed event exceeds input cap")
    return serialized


def reserve(dbfile,key):
    if not isinstance(key,str) or len(key)<32:
        raise EvidenceError("private evidence HMAC key required")
    db=conn_for(dbfile)
    try:
        _schema(db)
        db.execute("BEGIN IMMEDIATE")
        if any(state in HELD for _,state in _verified_states(db,key.encode())):
            raise EvidenceError("ambiguous in-flight delivery; owner review required")
        row=db.execute("""
          SELECT e.event_ref,e.sensor_id,e.payload_json,e.record_hmac
          FROM sanitized_event e LEFT JOIN delivery_outbox d
          ON d.event_ref=e.event_ref
          WHERE d.event_ref IS NULL ORDER BY e.rowid LIMIT 1
        """).fetchone()
        if row is None:
            db.commit()
            return None
        ref,sensor,payload,signature=row
        raw=_summary(ref,sensor,payload,signature,key.encode())
        stamp=_now()
        db.execute("""
          INSERT INTO delivery_outbox
            (event_ref,status,checked_at,http_code,status_hmac)
          VALUES(?,?,?,?,?)
        """,(ref,"reserved",stamp,None,
             _mac_state(key.encode(),ref,"reserved",stamp,None)))
        db.commit()
        return ref,raw
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def settle(dbfile,key,ref,status,code=None):
    if status not in TERMINAL|{"uncertain","needs_review"}:
        raise EvidenceError("invalid delivery result")
    if code is not None and (type(code) is not int or not 100<=code<=599):
        raise EvidenceError("invalid HTTP code")
    db=conn_for(dbfile)
    try:
        db.execute("BEGIN IMMEDIATE")
        state=db.execute("""
           SELECT status,checked_at,http_code,status_hmac
           FROM delivery_outbox WHERE event_ref=?
        """,(ref,)).fetchone()
        if state is None or state[0]!="reserved" or not hmac.compare_digest(
            _mac_state(key.encode(),ref,*state[:3]),state[3]):
            raise EvidenceError("invalid signed delivery reservation")
        stamp=_now()
        db.execute("""
           UPDATE delivery_outbox SET status=?,checked_at=?,http_code=?,
           status_hmac=? WHERE event_ref=?
        """,(status,stamp,code,_mac_state(key.encode(),ref,status,stamp,code),ref))
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,request,fp,code,msg,headers,newurl):
        return None


def send_one(raw,ingest_key):
    if not isinstance(ingest_key,str) or len(ingest_key)<32:
        raise EvidenceError("separate scoped ingest key missing")
    now=int(time.time())
    nonce=str(uuid.uuid4())
    request=urllib.request.Request(ENDPOINT,data=raw.encode(),method="POST",
        headers={
          "Content-Type":"application/json",
          "X-Vynalth-Sensor-Time":str(now),
          "X-Vynalth-Sensor-Nonce":nonce,
          "X-Vynalth-Sensor-Signature":sign_message(raw,ingest_key,now,nonce),
          "User-Agent":"VynalthTrustedCollector/1.1",
        })
    try:
        with urllib.request.build_opener(_NoRedirect).open(request,timeout=6) as response:
            return response.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError,TimeoutError,OSError):
        raise EvidenceError("network outcome uncertain")


def deliver(dbfile,key,ingest_key,max_events=1,transport=None):
    if not 1<=max_events<=20:
        raise EvidenceError("outbox send cap is 1 to 20")
    if not isinstance(ingest_key,str) or len(ingest_key)<32:
        raise EvidenceError("separate scoped ingest key required")
    accepted=sampled=0
    for _ in range(max_events):
        row=reserve(dbfile,key)
        if row is None:
            break
        ref,payload=row
        try:
            status=(transport or send_one)(payload,ingest_key)
        except Exception:
            settle(dbfile,key,ref,"uncertain")
            raise EvidenceError("ambiguous delivery held without retry")
        if status==201:
            settle(dbfile,key,ref,"insert_acknowledged",201)
            accepted+=1
        elif status==202:
            settle(dbfile,key,ref,"sampled_out",202)
            sampled+=1
        else:
            settle(dbfile,key,ref,"needs_review",
                   status if type(status) is int and 100<=status<=599 else None)
            raise EvidenceError("non-success response held for owner review")
    return {"schema":VERSION,"insert_acknowledged_not_sql_verified":accepted,
            "sampled_out_no_insert":sampled,
            "automatic_retries":0,"raw_identifiers_uploaded":False,
            "production_tidb_readback_verified":False}


def inspect(dbfile,key):
    if not isinstance(key,str) or len(key)<32:
        raise EvidenceError("private evidence HMAC key required")
    # Zero events is a valid idle sensor, but NOT evidence of any capture.
    # Once the spool has events, verify every source record before any status
    # can be considered trusted; tampering fails closed.
    with _ro(dbfile) as db:
        total=db.execute("SELECT COUNT(*) FROM sanitized_event").fetchone()[0]
    if total:
        verify_spool(dbfile,key)
    with _ro(dbfile) as db:
        exists=db.execute("""
            SELECT 1 FROM sqlite_master WHERE type='table'
            AND name='delivery_outbox'
        """).fetchone()
        counts={}
        if exists:
            for _,status in _verified_states(db,key.encode()):
                counts[status]=counts.get(status,0)+1
        return {"schema":VERSION,"total_sanitized_events":total,
                "outbox_states":counts,
                "unsent":total-sum(counts.values()),
                "operator_review_needed":sum(counts.get(x,0) for x in HELD),
                "readonly":True,"network_requests":0,
                "captured_evidence_verified":bool(total)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db",type=Path,required=True)
    parser.add_argument("--send",action="store_true")
    parser.add_argument("--max-events",type=int,default=1)
    args=parser.parse_args()
    secret=os.environ.get("VYNALTH_EVIDENCE_HMAC_KEY","")
    try:
        if args.send:
            result=deliver(args.db,secret,
                           os.environ.get("HONEY_SENSOR_INGEST_KEY",""),
                           args.max_events)
        else:
            result=inspect(args.db,secret)
        print(json.dumps(result,sort_keys=True))
    except (OSError,sqlite3.Error,EvidenceError,TypeError,ValueError,KeyError):
        print("UPLINK_BLOCKED: invalid evidence, uncertain delivery or missing permission",
              file=sys.stderr)
        raise SystemExit(2)


if __name__=="__main__":
    main()
