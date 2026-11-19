#!/usr/bin/env python3
"""Restart-safe LOCAL honeypot evidence spool: sanitized events, never raw logs.

Reads one bounded batch of append-only Cowrie/OpenCanary JSONL and atomically
commits both sanitized events and a byte checkpoint to protected SQLite.
At-least-once source reads + unique rows give no duplicates during normal
restart. A file replaced mid-read is not a guaranteed lossless rotation;
rotate with retention and drain the old file first in production.

No network, uploads, database credentials, raw IPs, usernames, passwords,
commands, session tapes or malware bytes in the spool.
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
import sqlite3
import stat
import sys

from evidence_capture import _canonical_event, EvidenceError, MAX_LINE

SCHEMA = "vynalth-spool-v1"
MAX_BATCH_LINES = 512
MAX_RECORD_BYTES = 4096
SENSOR_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{1,79}$")


def safe_store_path(path: Path):
    path = Path(path)
    if path.suffix != ".db" or path.is_symlink():
        raise EvidenceError("private spool must be a regular .db path")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = parent.lstat()
    if not stat.S_ISDIR(mode.st_mode) or mode.st_mode & 0o077:
        raise EvidenceError("spool parent must be a private 0700 directory")
    if hasattr(os, "getuid") and mode.st_uid != os.getuid():
        raise EvidenceError("spool parent ownership mismatch")
    if path.exists() and (not path.is_file() or
                          path.stat().st_mode & 0o077):
        raise EvidenceError("spool DB must be owned and private (0600)")
    return path


def conn_for(path):
    # A safe restricted directory is our defence against SQLite path swapping.
    path = safe_store_path(path)
    previous = os.umask(0o077)
    try:
        db = sqlite3.connect(str(path), timeout=6, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=6000")
        db.execute("PRAGMA trusted_schema=OFF")
        db.executescript("""
        CREATE TABLE IF NOT EXISTS input_checkpoint (
          sensor_id TEXT NOT NULL, source TEXT NOT NULL, input_path TEXT NOT NULL,
          device INTEGER NOT NULL, inode INTEGER NOT NULL, position INTEGER NOT NULL,
          updated_at TEXT NOT NULL, PRIMARY KEY(sensor_id, source, input_path)
        );
        CREATE TABLE IF NOT EXISTS sanitized_event (
          event_ref TEXT NOT NULL PRIMARY KEY,
          sensor_id TEXT NOT NULL, source TEXT NOT NULL, event_class TEXT NOT NULL,
          observed_at TEXT NULL, payload_json TEXT NOT NULL,
          record_hmac TEXT NOT NULL, captured_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_spool_sensor_time
          ON sanitized_event(sensor_id, observed_at);
        """)
        return db
    finally:
        os.umask(previous)


def file_for(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("input must be a regular, non-symlink JSONL file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    mode = os.fstat(fd)
    if not stat.S_ISREG(mode.st_mode):
        os.close(fd)
        raise EvidenceError("unexpected nonregular input")
    return os.fdopen(fd, "rb"), mode


def _mac(key: bytes, sensor: str, event_ref: str, payload: str):
    message = (SCHEMA + "|" + sensor + "|" + event_ref + "|" + payload).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def spool(input_path: Path, spool_db: Path, source: str, sensor: str,
          key: str, max_lines=256, max_records=10000):
    if source not in {"cowrie", "opencanary"} or not SENSOR_NAME.fullmatch(sensor):
        raise EvidenceError("invalid source or sensor identifier")
    if not isinstance(key, str) or len(key) < 32:
        raise EvidenceError("private spool signing key must be at least 32 characters")
    if not 1 <= max_lines <= MAX_BATCH_LINES or not 1 <= max_records <= 100000:
        raise EvidenceError("invalid batch/row limit")
    if input_path.resolve() == spool_db.resolve():
        raise EvidenceError("input and database must differ")
    raw, info = file_for(input_path)
    db = None
    accepted = rejected = 0
    try:
        db = conn_for(spool_db)
        db.execute("BEGIN IMMEDIATE")
        path_id = str(input_path.resolve())
        state = db.execute("""
          SELECT device,inode,position FROM input_checkpoint
          WHERE sensor_id=? AND source=? AND input_path=?
        """, (sensor, source, path_id)).fetchone()
        position = state[2] if state and state[:2] == (
            info.st_dev, info.st_ino) and state[2] <= info.st_size else 0
        rotated = bool(state and (state[:2] != (info.st_dev, info.st_ino)
                                  or state[2] > info.st_size))
        raw.seek(position)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        keybytes = key.encode()
        for _ in range(max_lines):
            start = raw.tell()
            line = raw.readline(MAX_LINE+1)
            if not line:
                break
            if len(line) > MAX_LINE:
                # Drain a completed overlong JSONL record in bounded chunks.
                # Never mistake an unfinished line for a committed event.
                completed = line.endswith(b"\n")
                total = len(line)
                while not completed and total <= 1024 * 1024:
                    chunk = raw.readline(MAX_LINE+1)
                    if not chunk:
                        break
                    total += len(chunk)
                    completed = chunk.endswith(b"\n")
                if total > 1024 * 1024:
                    raise EvidenceError("oversized log line exceeds 1MiB cap")
                if not completed:
                    raw.seek(start)
                    break
                position = raw.tell()
                rejected += 1
                continue
            if not line.endswith(b"\n"):
                raw.seek(start)
                break
            position = raw.tell()
            try:
                item = _canonical_event(json.loads(line), source, keybytes,
                                        start, None, None)
            except (TypeError, ValueError, UnicodeError, OverflowError):
                item = None
            if item is None:
                rejected += 1
                continue
            # Bind source file identity to each event, otherwise reusing the
            # same source JSON after log rotation could collide in the spool.
            item["event_ref"] = hmac.new(
                keybytes, (sensor+"|"+source+"|"+
                           str(info.st_dev)+"|"+str(info.st_ino)+"|"+
                           item["event_ref"]).encode(), hashlib.sha256).hexdigest()
            payload = json.dumps(item, sort_keys=True,
                                 separators=(",", ":"), ensure_ascii=True)
            if len(payload.encode()) > MAX_RECORD_BYTES:
                rejected += 1
                continue
            size = db.execute("SELECT COUNT(*) FROM sanitized_event").fetchone()[0]
            if size >= max_records:
                raise EvidenceError("spool row cap reached; pause before data loss")
            db.execute("""
              INSERT OR IGNORE INTO sanitized_event
              (event_ref,sensor_id,source,event_class,observed_at,
               payload_json,record_hmac,captured_at)
              VALUES(?,?,?,?,?,?,?,?)
            """, (item["event_ref"], sensor, source, item["event_class"],
                  item["observed_at"], payload,
                  _mac(keybytes, sensor, item["event_ref"], payload), now))
            if db.execute("SELECT changes()").fetchone()[0]:
                accepted += 1
        db.execute("""
          INSERT INTO input_checkpoint
          (sensor_id,source,input_path,device,inode,position,updated_at)
          VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(sensor_id,source,input_path) DO UPDATE SET
            device=excluded.device, inode=excluded.inode,
            position=excluded.position, updated_at=excluded.updated_at
        """, (sensor,source,path_id,info.st_dev,info.st_ino,position,now))
        db.commit()
        return {
            "schema": SCHEMA, "source": source, "sensor_id": sensor,
            "new_events": accepted, "rejected_rows": rejected,
            "checkpoint_bytes": position, "file_replaced_or_truncated": rotated,
            "external_uploads": False, "raw_credentials_stored": False,
            "spool_verified": False,
        }
    except BaseException:
        if db:
            db.rollback()
        raise
    finally:
        raw.close()
        if db:
            db.close()


def verify(spool_db: Path, key: str):
    if not isinstance(key, str) or len(key) < 32:
        raise EvidenceError("protected verification key required")
    if not Path(spool_db).is_file() or Path(spool_db).is_symlink():
        raise EvidenceError("private spool file missing")
    db = conn_for(spool_db)
    count = 0
    try:
        for ref, sensor, payload, signature in db.execute("""
          SELECT event_ref,sensor_id,payload_json,record_hmac
          FROM sanitized_event ORDER BY rowid
        """):
            if not hmac.compare_digest(
                _mac(key.encode(), sensor, ref, payload), signature):
                raise EvidenceError("spool HMAC integrity failure")
            row = json.loads(payload)
            if row["event_ref"] != ref or row["share_authorized"] is not False:
                raise EvidenceError("spool privacy/correlation mismatch")
            count += 1
        return {"verified": True, "sanitized_events": count, "no_network": True}
    finally:
        db.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path)
    p.add_argument("--db", type=Path, required=True)
    p.add_argument("--source", choices=("cowrie","opencanary"))
    p.add_argument("--sensor-id", default="vynalth-lab-01")
    p.add_argument("--batch-size", type=int, default=256)
    p.add_argument("--max-records", type=int, default=10000)
    p.add_argument("--verify", action="store_true")
    args=p.parse_args()
    key=os.environ.get("VYNALTH_EVIDENCE_HMAC_KEY","")
    try:
        if args.verify:
            result=verify(args.db,key)
        else:
            if args.input is None or args.source is None:
                raise EvidenceError("source and input required")
            result=spool(args.input,args.db,args.source,args.sensor_id,
                         key,args.batch_size,args.max_records)
    except (OSError, sqlite3.Error, EvidenceError, TypeError, ValueError, KeyError):
        print("SPOOL_BLOCKED: invalid input, capacity or integrity",file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
