#!/usr/bin/env python3
"""One cycle of an isolated, rotation-aware, restart-safe honeypot collector.

Only recognized raw JSONL files in a caller-approved directory are scanned.
Archived files are drained BEFORE the active log; neither raw evidence nor
credentials are transmitted. Runs as a supervised, unprivileged local job.

Limit: this cannot recover logs deleted before the collector ever saw them,
or unobserved writes made after the last check. Archive retention and external
backup/recovery must be validated independently; never claim zero loss.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import shutil
import sqlite3
import stat
import sys
import tempfile

from durable_spool import conn_for, spool, EvidenceError, SENSOR_NAME

MAX_FILES = 32
ACTIVE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,79}$")
ARCHIVE_RE = re.compile(r"^(?:[1-9][0-9]{0,3}|20[0-9]{2}-[01][0-9]-[0-3][0-9](?:T[0-2][0-9][0-5][0-9][0-5][0-9]Z)?)$")
MAX_LOG_BYTES = 64 * 1024 * 1024


def _allowed_files(directory: Path, active_name: str, key: bytes):
    directory = Path(directory)
    if not ACTIVE_RE.fullmatch(active_name) or "/" in active_name or active_name in {".", ".."}:
        raise EvidenceError("unsafe active log name")
    if directory.is_symlink() or not directory.is_dir():
        raise EvidenceError("approved raw log directory missing")
    found = []
    inode_seen = set()
    active_exists = False
    for entry in directory.iterdir():
        if entry.name != active_name and not entry.name.startswith(active_name + "."):
            continue
        if entry.name != active_name:
            suffix=entry.name[len(active_name)+1:]
            if not ARCHIVE_RE.fullmatch(suffix):
                raise EvidenceError("unrecognized archive suffix; do not discard")
        if entry.is_symlink() or not entry.is_file():
            raise EvidenceError("nonregular or symlink source in raw directory")
        info=entry.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_LOG_BYTES:
            raise EvidenceError("source file type or size cap failed")
        # A recycled inode is not a stable file identity. The protected
        # first-64-byte signature identifies the source generation without
        # storing plaintext log fragments in SQLite.
        with entry.open("rb") as stream:
            prefix=stream.read(64)
        fingerprint=hmac.new(key,b"source-prefix-v1|"+prefix,
                             hashlib.sha256).hexdigest()
        identity=(info.st_dev,info.st_ino,fingerprint)
        if identity in inode_seen:
            raise EvidenceError("hard-linked source might double-count")
        inode_seen.add(identity)
        active = entry.name == active_name
        active_exists |= active
        if not active and info.st_size:
            # A rotated archive containing an unfinished JSONL record must not
            # be silently skipped when a newer active file is available.
            with entry.open("rb") as stream:
                stream.seek(-1,os.SEEK_END)
                if stream.read(1) != b"\n":
                    raise EvidenceError("archived log ends in an incomplete JSONL record")
        found.append((active,info.st_mtime_ns,entry,info,fingerprint))
        if len(found)>MAX_FILES:
            raise EvidenceError("more than 32 retained archives; fail closed")
    if not active_exists:
        raise EvidenceError("active JSONL input missing")
    found.sort(key=lambda x:(x[0],x[1],x[2].name))
    return found


def _inventory_table(db):
    db.execute("""
    CREATE TABLE IF NOT EXISTS observed_source_file (
      sensor_id TEXT NOT NULL,
      source TEXT NOT NULL,
      device INTEGER NOT NULL,
      inode INTEGER NOT NULL,
      prefix_hmac TEXT NOT NULL,
      last_known_bytes INTEGER NOT NULL,
      processed_bytes INTEGER NOT NULL,
      last_seen_utc TEXT NOT NULL,
      PRIMARY KEY (sensor_id,source,device,inode,prefix_hmac)
    )
    """)


def _missing_unprocessed(db, source, sensor, present):
    for dev,ino,prefix,known,processed in db.execute("""
      SELECT device,inode,prefix_hmac,last_known_bytes,processed_bytes
      FROM observed_source_file WHERE sensor_id=? AND source=?
    """,(sensor,source)):
        if (dev,ino,prefix) not in present and processed < known:
            raise EvidenceError("previously observed unread archive vanished")


def _update_inventory(db, source, sensor, info, fingerprint, processed, now):
    db.execute("""
      INSERT INTO observed_source_file
        (sensor_id,source,device,inode,prefix_hmac,last_known_bytes,processed_bytes,last_seen_utc)
      VALUES (?,?,?,?,?,?,?,?)
      ON CONFLICT(sensor_id,source,device,inode,prefix_hmac) DO UPDATE SET
        last_known_bytes=MAX(last_known_bytes,excluded.last_known_bytes),
        processed_bytes=MAX(processed_bytes,excluded.processed_bytes),
        last_seen_utc=excluded.last_seen_utc
    """,(sensor,source,info.st_dev,info.st_ino,fingerprint,info.st_size,processed,now))


def _private_health_parent(path: Path):
    path=Path(path)
    if path.suffix!=".json" or path.is_symlink():
        raise EvidenceError("health report must be an unused regular .json path")
    parent=path.parent
    parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    mode=parent.lstat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_mode & 0o077:
        raise EvidenceError("health directory must be private")
    if hasattr(os,"getuid") and mode.st_uid != os.getuid():
        raise EvidenceError("health directory ownership mismatch")
    if path.exists() and (not path.is_file() or path.stat().st_mode & 0o077):
        raise EvidenceError("health report must be 0600")
    return parent


def _signed_health(path: Path, report: dict, key: bytes):
    parent=_private_health_parent(path)
    payload=json.dumps(report,sort_keys=True,separators=(",",":"))
    wrapper={"report":report,"hmac_sha256":hmac.new(
        key, payload.encode(), hashlib.sha256).hexdigest()}
    fd,tempfile_path=tempfile.mkstemp(prefix=".health-",dir=parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,"w",encoding="utf-8") as out:
            json.dump(wrapper,out,sort_keys=True)
            out.write("\n")
            out.flush()
            os.fsync(out.fileno())
        os.replace(tempfile_path,path)
        fd_parent=os.open(parent,os.O_RDONLY|getattr(os,"O_DIRECTORY",0))
        try:os.fsync(fd_parent)
        finally:os.close(fd_parent)
    finally:
        if os.path.lexists(tempfile_path):
            os.unlink(tempfile_path)


def health_status(path: Path, key: str, max_age_seconds=180,
                  current_time=None):
    if not isinstance(key,str) or len(key)<32 or not 10<=max_age_seconds<=86400:
        raise EvidenceError("health key or age limit invalid")
    path=Path(path)
    _private_health_parent(path)
    if not path.is_file() or path.stat().st_size>65536:
        raise EvidenceError("health report absent or oversized")
    envelope=json.loads(path.read_text(encoding="utf-8"))
    report=envelope["report"]
    signature=envelope["hmac_sha256"]
    payload=json.dumps(report,sort_keys=True,separators=(",",":"))
    expected=hmac.new(key.encode(),payload.encode(),hashlib.sha256).hexdigest()
    if not isinstance(signature,str) or not hmac.compare_digest(expected,signature):
        raise EvidenceError("health report tampered")
    stamp=datetime.fromisoformat(report["checked_at_utc"].replace("Z","+00:00"))
    now=current_time or datetime.now(timezone.utc)
    age=(now-stamp).total_seconds()
    if not 0<=age<=max_age_seconds:
        raise EvidenceError("collector heartbeat stale")
    if report["status"]!="healthy" or report["remaining_bytes"]!=0:
        raise EvidenceError("collector backlog or capacity warning")
    return {"healthy":True,"heartbeat_age_seconds":int(age),
            "spool_queue_events":report["queue_rows"],
            "privacy_safe":True}


def collect(raw_dir:Path,active_name:str,db_path:Path,health_path:Path,
            source:str,sensor:str,key:str,
            batch_size=256,max_rounds=4,max_records=10000,
            min_free_mb=128):
    if source not in {"cowrie","opencanary"} or not SENSOR_NAME.fullmatch(sensor):
        raise EvidenceError("invalid sensor source/id")
    if not isinstance(key,str) or len(key)<32:
        raise EvidenceError("protected HMAC key required")
    if not 1<=batch_size<=512 or not 1<=max_rounds<=16 or not 1<=max_records<=100000:
        raise EvidenceError("bounded cycle limits violated")
    if not 0<=min_free_mb<=4096:
        raise EvidenceError("invalid minimum free disk setting")
    # No attacker-supplied paths, and no raw evidence is printed.
    files=_allowed_files(raw_dir,active_name,key.encode())
    present={(i.st_dev,i.st_ino,fingerprint) for _,_,_,i,fingerprint in files}
    _private_health_parent(health_path)
    db=conn_for(db_path)
    try:
        _inventory_table(db)
        _missing_unprocessed(db,source,sensor,present)
    finally:
        db.close()
    space=shutil.disk_usage(Path(db_path).parent)
    if space.free < min_free_mb*1024*1024:
        raise EvidenceError("collector free-space threshold reached")
    new_events=rejected=0
    remaining=0
    archive_count=sum(1 for active,_,_,_,_ in files if not active)
    now=datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00","Z")
    for is_active,_,file_path,info,fingerprint in files:
        processed=0
        for _ in range(max_rounds):
            outcome=spool(file_path,db_path,source,sensor,key,batch_size,max_records)
            new_events+=outcome["new_events"]
            rejected+=outcome["rejected_rows"]
            processed=outcome["checkpoint_bytes"]
            # If writer appended in parallel, do not infer EOF from old stat.
            refreshed=file_path.stat()
            if refreshed.st_ino!=info.st_ino or refreshed.st_dev!=info.st_dev:
                raise EvidenceError("source changed inode during evidence cycle")
            if processed >= refreshed.st_size:
                break
            if processed==0 and refreshed.st_size and is_active:
                # Live writer may be midway through its first JSONL line.
                break
            # If this archive lacks a newline, _allowed_files already refused.
            # For active partial tail, looping would be wasteful.
            if is_active:
                with file_path.open("rb") as check:
                    check.seek(-1,os.SEEK_END)
                    if check.read(1)!=b"\n":
                        break
        latest=file_path.stat()
        remaining += max(0,latest.st_size-processed)
        db=conn_for(db_path)
        try:
            db.execute("BEGIN IMMEDIATE")
            _update_inventory(db,source,sensor,latest,fingerprint,processed,now)
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()
        if not is_active and processed < latest.st_size:
            # Do not consume newer log while older retained evidence is pending.
            break
    db=conn_for(db_path)
    try:
        rows=db.execute("SELECT COUNT(*) FROM sanitized_event").fetchone()[0]
    finally:
        db.close()
    report={
       "schema":"vynalth-collector-health-v1","source":source,"sensor_id":sensor,
       "checked_at_utc":now,"status":"healthy" if remaining==0 else "backlogged",
       "source_file_count":len(files),"archives_retained":archive_count,
       "new_sanitized_events":new_events,"rejected_rows":rejected,
       "queue_rows":rows,"remaining_bytes":remaining,
       "external_uploads":False,"public_attacks_verified":False,
    }
    _signed_health(health_path,report,key.encode())
    return {k:report[k] for k in (
        "status","source_file_count","archives_retained",
        "new_sanitized_events","rejected_rows","queue_rows","remaining_bytes")}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-dir",type=Path)
    parser.add_argument("--active-name",default="cowrie.json")
    parser.add_argument("--db",type=Path)
    parser.add_argument("--health",type=Path,required=True)
    parser.add_argument("--source",choices=("cowrie","opencanary"),default="cowrie")
    parser.add_argument("--sensor-id",default="vynalth-sensor-01")
    parser.add_argument("--batch-size",type=int,default=256)
    parser.add_argument("--max-rounds",type=int,default=4)
    parser.add_argument("--max-records",type=int,default=10000)
    parser.add_argument("--min-free-mb",type=int,default=128)
    parser.add_argument("--check",action="store_true")
    args=parser.parse_args()
    key=os.environ.get("VYNALTH_EVIDENCE_HMAC_KEY","")
    try:
        if args.check:
            outcome=health_status(args.health,key)
        else:
            if args.raw_dir is None or args.db is None:
                raise EvidenceError("raw directory and DB required")
            outcome=collect(args.raw_dir,args.active_name,args.db,args.health,
                            args.source,args.sensor_id,key,args.batch_size,
                            args.max_rounds,args.max_records,args.min_free_mb)
        print(json.dumps(outcome,sort_keys=True))
    except (EvidenceError,OSError,ValueError,TypeError,sqlite3.Error,KeyError):
        print("COLLECTOR_BLOCKED: insufficient freshness, evidence or disk capacity",
              file=sys.stderr)
        raise SystemExit(2)


if __name__=="__main__":
    main()
