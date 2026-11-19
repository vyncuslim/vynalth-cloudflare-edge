#!/usr/bin/env python3
"""Generate a disposable Python-signed sensor outbox event for JS Worker CI.

No HTTP requests or real credentials. The artifact is synthetic only and is
created with 0600 permissions, then destroyed by the GitHub Actions runner.
"""
import json
import os
from pathlib import Path
import sys
import tempfile

from durable_spool import spool
from spool_uplink import reserve
from send_summaries import sign_message

KEY="ci-integration-evidence-key-"+("x"*42)
INGEST_KEY="ci-integration-sensor-key-"+("a"*48)
TS=1795075200
NONCE="11111111-2222-4333-8444-555555555555"


def main(target:Path):
    if target.exists() or target.is_symlink():
        raise RuntimeError("refusing to overwrite fixture")
    with tempfile.TemporaryDirectory() as location:
        root=Path(location)
        raw=root/"cowrie.jsonl"
        db=root/"private"/"events.db"
        ev={"eventid":"cowrie.login.failed","protocol":"ssh",
            "timestamp":"2026-11-19T08:00:00Z","session":"disposable-ci-only",
            "src_ip":"198.51.100.101","username":"secret-ci-user",
            "password":"never-send-test-password"}
        raw.write_text(json.dumps(ev)+"\n")
        spool(raw,db,"cowrie","ci-signed-agent-01",KEY)
        _,body=reserve(db,KEY)
        json_body=json.loads(body)
        assert json_body["request_path"]=="/ssh/login_attempt"
        assert "password" not in body and "src_ip" not in body
        fixture={
          "body":body,
          "timestamp":str(TS),
          "nonce":NONCE,
          "signature":sign_message(body,INGEST_KEY,TS,NONCE),
          "key":INGEST_KEY,
          "expected_source":"cowrie",
        }
        payload=(json.dumps(fixture)+"\n").encode()
        target.parent.mkdir(exist_ok=True,parents=True)
        old=os.umask(0o077)
        try:
            fd=os.open(target,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
            with os.fdopen(fd,"wb") as f:
                f.write(payload)
        finally:
            os.umask(old)
        print(json.dumps({"signed_fixture":True,"synthetic_only":True,
                          "posted_to_production":False,
                          "original_credentials_excluded":True}))


if __name__=="__main__":
    try:
        main(Path(sys.argv[1]))
    except (OSError,ValueError,IndexError,RuntimeError):
        print("FIXTURE_BLOCKED",file=sys.stderr)
        raise SystemExit(2)
