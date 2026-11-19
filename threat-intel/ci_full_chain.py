#!/usr/bin/env python3
"""An end-to-end OFFLINE integration proof using *synthetic* sensor evidence.

Demonstrates the real sanitizer -> observation-only index -> human approval
gate -> signed approval -> STIX/MISP draft. It does NOT claim a real malicious
IP, real human reviewers, production TiDB writes or real external sharing.
"""
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
import uuid

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
sys.path.insert(0,str(HERE.parent/"sensor-stack"))
from event_sanitizer import clean_event
from normalize import write_index
from intel import export_to_file, ReviewError
from sign_approval import write_signed_approval

NOW=datetime.now(timezone.utc)
UTC=lambda t:t.isoformat(timespec="seconds").replace("+00:00","Z")
ID1=str(uuid.uuid4())
ID2=str(uuid.uuid4())
KEY="ephemeral-ci-hmac-never-for-production-"+uuid.uuid4().hex
os.environ["VYNALTH_TI_APPROVAL_HMAC_KEY"]=KEY


def run():
    original={
       "eventid":"cowrie.session.connect", "protocol":"ssh",
       "src_ip":"198.51.100.25", "password":"SYNTHETIC_NOT_A_REAL_PASSWORD",
       "username":"fictional-ci-user", "input":"fake-sensitive-command",
       "session":"random-private-session", "timestamp":UTC(NOW),
    }
    safe=clean_event(original,"cowrie")
    if safe is None or "password" in safe or "src_ip" in safe:
        raise AssertionError("sensor sanitizer failed")
    with tempfile.TemporaryDirectory(prefix="vynalth-integration-") as temp:
        root=Path(temp)
        source=root/"safe.jsonl"
        source.write_text(json.dumps(safe)+"\n",encoding="utf-8")
        index=root/"restricted"/"observations.json"
        stats=write_index(source,index)
        observations=json.loads(index.read_text(encoding="utf-8"))["events"]
        assert stats["accepted"]==1
        assert len(observations)==1
        assert observations[0]["sharing_allowed"] is False
        assert observations[0]["indicator_status"]=="observation_only"
        evidence=b"Vynalth CI synthetic text fixture - not malware"
        hash_value=hashlib.sha256(evidence).hexdigest()
        row={
          "indicator_id":ID1,"indicator_type":"sha256","value":hash_value,
          "review_status":"approved","false_positive_status":"cleared",
          "confidence":80,"first_seen":UTC(NOW-timedelta(days=7)),
          "last_seen":UTC(NOW-timedelta(days=3)),
          "valid_until":UTC(NOW+timedelta(days=7)),
          "reviewed_at":UTC(NOW-timedelta(days=1)),
          "reviewer_id":"ci-reviewer-a",
          "evidence_sha256":[hash_value],
          "source_event_ids":[observations[0]["observation_id"]],
          "tlp":"TLP:AMBER","share_authorized":True,
          "public_ip_release_approved":False,
        }
        manifest={"schema_version":"vynalth-ti-v1","indicators":[row]}
        approval={
          "approval_id":ID2,"recipient_id":"synthetic-ci-csirt",
          "purpose":"Isolated synthetic fixture test of approval handling",
          "export_format":"stix","tlp":"TLP:AMBER",
          "indicator_ids":[ID1],"approved":True,
          "approved_by":"ci-reviewer-b",
          "approved_at":UTC(NOW-timedelta(hours=4)),
          "expires_at":UTC(NOW+timedelta(days=1)),
          "public_ip_release_approved":False,
          "second_reviewer_id":None,
        }
        manifest_path=root/"manifest.json"
        unsigned=root/"unsigned.json"
        signed=root/"signed.json"
        manifest_path.write_text(json.dumps(manifest))
        unsigned.write_text(json.dumps(approval))
        write_signed_approval(unsigned,signed,confirmed=True)
        stix_target=root/"exports"/"stix.json"
        result=export_to_file(manifest_path,signed,stix_target,"stix",NOW)
        bundle=json.loads(stix_target.read_text())
        assert bundle["type"]=="bundle" and len(bundle["objects"])==1
        assert bundle["objects"][0]["type"]=="indicator"
        assert result["uploaded"] is False
        # Confirm modifying approval immediately prevents export.
        altered=json.loads(signed.read_text())
        altered["recipient_id"]="unauthorized-recipient"
        signed.write_text(json.dumps(altered))
        try:
            export_to_file(manifest_path,signed,root/"exports"/"forbidden.json","stix",NOW)
        except ReviewError:
            pass
        else:
            raise AssertionError("tampered approval must be rejected")
        approval["export_format"]="misp"
        unsigned.write_text(json.dumps(approval))
        signed.unlink()
        write_signed_approval(unsigned,signed,confirmed=True)
        misp_target=root/"exports"/"misp.json"
        export_to_file(manifest_path,signed,misp_target,"misp",NOW)
        misp=json.loads(misp_target.read_text())
        assert misp["Event"]["published"] is False
        assert misp["Event"]["distribution"]=="0"
        all_output=json.dumps([observations,bundle,misp])
        for word in ("SYNTHETIC_NOT_A_REAL_PASSWORD",
                     "198.51.100.25","fake-sensitive-command",
                     "random-private-session"):
            assert word not in all_output, "private data leaked"
        print(json.dumps({
            "proof_type":"synthetic_offline_end_to_end",
            "sanitized_observations":stats["accepted"],
            "stix_indicators":len(bundle["objects"]),
            "misp_draft_attributes":len(misp["Event"]["Attribute"]),
            "tamper_rejected":True,
            "external_sharing":False,
            "production_tidb_verified":False,
        },sort_keys=True))


if __name__=="__main__":
    run()
