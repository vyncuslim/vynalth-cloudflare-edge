#!/usr/bin/env python3
"""Offline evidence-retention audit for source archives: NEVER DELETES files.

Verifies the archive is physically present, complete, not a symlink, and
has been fully checkpointed into the signed restricted SQLite spool.
Produces a private HMAC-protected inventory with raw file SHA-256 digests
only. Archive disposition always requires separate owner/retention review.
No uploading, outbound network calls, source deletion or malware execution.
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
import stat
import sys

from durable_spool import EvidenceError
from rotation_collector import _allowed_files,_missing_unprocessed,_signed_health,_private_health_parent,_load_key
from spool_uplink import _ro

VERSION="vynalth-restricted-retention-v1"


def _sha256_file(path,expected):
    flags=os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|getattr(os,"O_NONBLOCK",0)
    fd=os.open(path,flags)
    with os.fdopen(fd,"rb") as stream:
        metadata=os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or
            (metadata.st_dev,metadata.st_ino)!=(expected.st_dev,expected.st_ino) or
            metadata.st_size!=expected.st_size):
            raise EvidenceError("archive changed before custody hash")
        digest=hashlib.sha256()
        while True:
            chunk=stream.read(65536)
            if not chunk:
                break
            digest.update(chunk)
        after=os.fstat(stream.fileno())
        if after.st_size!=expected.st_size or after.st_mtime_ns!=metadata.st_mtime_ns:
            raise EvidenceError("archive modified during custody hash")
        return digest.hexdigest()


def audit(directory:Path,active_name:str,dbfile:Path,manifest:Path,
          source:str,sensor:str,key:str):
    if source not in {"cowrie","opencanary"} or not isinstance(key,str) or len(key)<32:
        raise EvidenceError("operator source and protected HMAC key required")
    if not isinstance(sensor,str) or len(sensor)>80 or not sensor:
        raise EvidenceError("invalid sensor identifier")
    files=_allowed_files(directory,active_name,key.encode())
    present={(info.st_dev,info.st_ino,prefix)
             for _,_,_,info,prefix in files}
    evidence=[]
    with _ro(dbfile) as db:
        _missing_unprocessed(db,source,sensor,present)
        for is_active,_,file,info,prefix in files:
            if is_active:
                continue
            state=db.execute("""
              SELECT processed_bytes,last_known_bytes
              FROM observed_source_file
              WHERE sensor_id=? AND source=? AND device=?
                AND inode=? AND prefix_hmac=?
            """,(sensor,source,info.st_dev,info.st_ino,prefix)).fetchone()
            ack=bool(state and state[0]>=info.st_size and
                     state[1]>=info.st_size)
            evidence.append({
                "source_name":file.name,
                "sha256":_sha256_file(file,info),
                "size_bytes":info.st_size,
                "spool_checkpoint_complete":ack,
                "operator_retention_release_approved":False,
                "automatic_delete":False,
            })
    report={
       "schema":VERSION,
       "checked_at_utc":datetime.now(timezone.utc).isoformat(
           timespec="seconds").replace("+00:00","Z"),
       "source":source,
       "sensor_id":sensor,
       "archived_count":len(evidence),
       "archived_uncheckpointed_count":sum(
           not e["spool_checkpoint_complete"] for e in evidence),
       "retained_archives":evidence,
       "deletions_performed":0,
       "outbound_uploads_performed":0,
       "retention_release_authorized":False,
    }
    _signed_health(manifest,report,key.encode())
    return {"schema":VERSION,"archived_count":report["archived_count"],
            "uncheckpointed":report["archived_uncheckpointed_count"],
            "deletions":0,"release_authorized":False,
            "manifest_signed":True}


def verify_manifest(path:Path,key:str):
    if not isinstance(key,str) or len(key)<32:
        raise EvidenceError("protected audit key missing")
    path=Path(path)
    _private_health_parent(path)
    if not path.is_file() or path.stat().st_size>65536:
        raise EvidenceError("restricted archive inventory unavailable")
    data=json.loads(path.read_text(encoding="utf-8"))
    report=data["report"]
    raw=json.dumps(report,sort_keys=True,separators=(",",":"))
    expected=hmac.new(key.encode(),raw.encode(),hashlib.sha256).hexdigest()
    if not isinstance(data["hmac_sha256"],str) or not hmac.compare_digest(
      expected,data["hmac_sha256"]):
        raise EvidenceError("archive inventory HMAC mismatch")
    if (report.get("schema")!=VERSION or
        report.get("retention_release_authorized") is not False or
        report.get("deletions_performed")!=0):
        raise EvidenceError("archive custody manifest invalid")
    return {"verified":True,
            "archived_count":report["archived_count"],
            "uncheckpointed":report["archived_uncheckpointed_count"],
            "no_files_deleted":True}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--raw-dir",type=Path)
    p.add_argument("--active-name",default="cowrie.json")
    p.add_argument("--db",type=Path)
    p.add_argument("--manifest",type=Path,required=True)
    p.add_argument("--source",choices=("cowrie","opencanary"),default="cowrie")
    p.add_argument("--sensor-id",default="vynalth-sensor-01")
    p.add_argument("--verify",action="store_true")
    args=p.parse_args()
    try:
        key=_load_key()
        if args.verify:
            result=verify_manifest(args.manifest,key)
        else:
            if args.raw_dir is None or args.db is None:
                raise EvidenceError("operator source paths required")
            result=audit(args.raw_dir,args.active_name,args.db,args.manifest,
                         args.source,args.sensor_id,key)
        print(json.dumps(result,sort_keys=True))
    except (EvidenceError,OSError,sqlite3.Error,ValueError,KeyError,TypeError):
        print("RETENTION_BLOCKED: unverified archives or custody integrity",
              file=sys.stderr)
        raise SystemExit(2)


if __name__=="__main__":
    main()
