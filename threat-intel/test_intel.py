import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent))
from intel import (ReviewError, eligible, export_misp, export_stix,
                   export_to_file, validated_batch, valid_indicator_value, sign_approval)


NOW = datetime(2026, 11, 19, 8, 0, tzinfo=timezone.utc)
KEY = "test-only-approval-key-" + "x" * 48
os.environ["VYNALTH_TI_APPROVAL_HMAC_KEY"] = KEY
def time_at(days=0):
    return (NOW + timedelta(days=days)).isoformat().replace("+00:00", "Z")

def fixed_uuid(last):
    return "11111111-2222-4333-8444-" + ("%012d" % last)

def indicator(kind="sha256", value="a" * 64, **changes):
    row = dict(
        indicator_id=fixed_uuid(1),
        indicator_type=kind,
        value=value,
        review_status="approved",
        false_positive_status="cleared",
        confidence=87,
        first_seen=time_at(-8),
        last_seen=time_at(-5),
        valid_until=time_at(15),
        reviewed_at=time_at(-2),
        reviewer_id="reviewer-A",
        evidence_sha256=["b" * 64],
        source_event_ids=[fixed_uuid(5)],
        tlp="TLP:AMBER",
        share_authorized=True,
        public_ip_release_approved=False,
    )
    row.update(changes)
    return row

def approval(indicators, fmt="stix", **changes):
    doc = dict(
        approval_id=fixed_uuid(9),
        recipient_id="partner-CSIRT",
        purpose="Manually approved malware indicator sharing",
        export_format=fmt,
        tlp="TLP:AMBER",
        indicator_ids=[item["indicator_id"] for item in indicators],
        approved=True,
        approved_by="reviewer-B",
        approved_at=time_at(-1),
        expires_at=time_at(5),
        public_ip_release_approved=False,
        second_reviewer_id=None,
    )
    doc.update(changes)
    doc["signature"] = sign_approval(doc, KEY)
    return doc

def batch(row=None, grant=None, fmt="stix"):
    rows=[row or indicator()]
    return validated_batch({"schema_version": "vynalth-ti-v1", "indicators": rows},
                           grant or approval(rows,fmt), fmt, NOW)

class IntelTests(unittest.TestCase):
    def test_standard_stix_indicator_has_marking_pattern_timestamps(self):
        rows=batch()
        b=export_stix(rows,approval([indicator()]),NOW)
        self.assertEqual(b["type"],"bundle")
        self.assertEqual(len(b["objects"]),1)
        obj=b["objects"][0]
        self.assertEqual(obj["type"],"indicator")
        self.assertEqual(obj["spec_version"],"2.1")
        self.assertEqual(obj["pattern"],"[file:hashes.'SHA-256' = '"+"a"*64+"']")
        self.assertEqual(obj["confidence"],87)
        self.assertEqual(obj["object_marking_refs"],[
            "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"])
        self.assertEqual(obj["created"],obj["modified"])
        self.assertTrue(obj["valid_from"].endswith(".000Z"))
        self.assertNotIn("source_ip_hash", json.dumps(b))
        self.assertNotIn("reviewer-A", json.dumps(b))

    def test_misp_draft_is_local_and_not_published(self):
        row=indicator(kind="domain",value="research.example")
        grant=approval([row],fmt="misp")
        data=export_misp(batch(row,grant,fmt="misp"),grant,NOW)
        evt=data["Event"]
        self.assertFalse(evt["published"])
        self.assertEqual(evt["distribution"],"0")
        self.assertEqual(evt["Attribute"][0]["type"],"domain")
        self.assertTrue(evt["Attribute"][0]["to_ids"])
        self.assertEqual(evt["Tag"][0]["name"],"tlp:amber")

    def test_unreviewed_event_cannot_become_an_indicator(self):
        for status in ["candidate","under_review","rejected","revoked"]:
            with self.subTest(status=status),self.assertRaises(ReviewError):
                batch(indicator(review_status=status))
        for fp in ["unknown","confirmed"]:
            with self.subTest(fp=fp),self.assertRaises(ReviewError):
                batch(indicator(false_positive_status=fp))

    def test_missing_sharing_approval_or_no_review_blocks(self):
        with self.assertRaises(ReviewError):
            batch(indicator(share_authorized=False))
        with self.assertRaises(ReviewError):
            batch(indicator(confidence=40))
        with self.assertRaises(ReviewError):
            batch(indicator(evidence_sha256=[]))
        with self.assertRaises(ReviewError):
            batch(indicator(source_event_ids=[]))
        with self.assertRaises(ReviewError):
            batch(indicator(reviewed_at=time_at(1)))

    def test_both_approval_and_issuer_must_be_distinct(self):
        row=indicator()
        bad=approval([row],approved_by="reviewer-A")
        with self.assertRaisesRegex(ReviewError,"independent"):
            batch(row,bad)
        with self.assertRaisesRegex(ReviewError,"approval missing"):
            batch(row,approval([row],approved=False))
        with self.assertRaisesRegex(ReviewError,"format differs"):
            batch(row,approval([row],fmt="misp"))

    def test_expired_evidence_and_downgrade_blocked(self):
        row=indicator(valid_until=time_at(-1))
        with self.assertRaises(ReviewError):
            batch(row)
        row=indicator(tlp="TLP:RED")
        grant=approval([row],tlp="TLP:RED")
        with self.assertRaises(ReviewError):
            batch(row,grant)
        row=indicator(tlp="TLP:GREEN")
        grant=approval([row],tlp="TLP:CLEAR",recipient_id="public")
        with self.assertRaises(ReviewError):
            batch(row,grant)

    def test_public_ip_requires_independent_review_plus_special_approval(self):
        row=indicator(kind="ipv4",value="8.8.8.8",tlp="TLP:CLEAR")
        grant=approval([row],tlp="TLP:CLEAR",recipient_id="public")
        with self.assertRaisesRegex(ReviewError,"public IP"):
            batch(row,grant)
        row["public_ip_release_approved"]=True
        grant["public_ip_release_approved"]=True
        grant["signature"]=sign_approval(grant,KEY)
        with self.assertRaisesRegex(ReviewError,"public IP"):
            batch(row,grant)
        grant["second_reviewer_id"]="reviewer-C"
        grant["signature"]=sign_approval(grant,KEY)
        self.assertEqual(len(batch(row,grant)),1)

    def test_no_private_or_documentation_ips(self):
        for value in ["127.0.0.1","10.0.0.3","192.0.2.12","169.254.1.2"]:
            with self.subTest(value=value),self.assertRaises(ReviewError):
                valid_indicator_value("ipv4",value)
        with self.assertRaises(ReviewError):
            valid_indicator_value("ipv6","::1")

    def test_input_injection_and_unknown_sensitive_fields_refused(self):
        base=indicator()
        for extra in [{"password":"secret"},{"raw_ip":"198.51.100.7"},
                      {"command":"rm -rf /"}]:
            with self.subTest(extra=extra),self.assertRaises(ReviewError):
                batch({**base,**extra})
        with self.assertRaises(ReviewError):
            batch(indicator(kind="domain",value="evil.example'; DROP TABLE t; --"))
        with self.assertRaises(ReviewError):
            batch(indicator(kind="sha256",value="A"*64))

    def test_tampering_after_approval_signature_is_rejected(self):
        row=indicator()
        signed=approval([row])
        signed["recipient_id"]="attacker-controller"
        with self.assertRaisesRegex(ReviewError,"signature"):
            batch(row,signed)
        signed=approval([row])
        signed["approved"]=False
        with self.assertRaisesRegex(ReviewError,"signature"):
            batch(row,signed)
        signed=approval([row])
        signed["signature"]="0"*64
        with self.assertRaisesRegex(ReviewError,"signature"):
            batch(row,signed)
        signed=approval([row])
        del os.environ["VYNALTH_TI_APPROVAL_HMAC_KEY"]
        try:
            with self.assertRaisesRegex(ReviewError,"HMAC key"):
                batch(row,signed)
        finally:
            os.environ["VYNALTH_TI_APPROVAL_HMAC_KEY"]=KEY

    def test_unknown_approval_fields_and_wrong_ids_refused(self):
        row=indicator()
        with self.assertRaises(ReviewError):
            batch(row,{**approval([row]),"api_token":"secret"})
        with self.assertRaises(ReviewError):
            batch(row,approval([row],indicator_ids=[fixed_uuid(99)]))
        altered=approval([row])
        altered["signature"]="broken"
        with self.assertRaises(ReviewError):
            batch(row,altered)

    def test_duplicate_or_nonstring_approval_ids_are_rejected(self):
        row=indicator()
        for ids in [[row["indicator_id"],row["indicator_id"]], [None], {"a":"b"}, [42]]:
            with self.subTest(ids=ids):
                bad=approval([row],indicator_ids=ids)
                with self.assertRaises(ReviewError):
                    batch(row,bad)

    def test_independent_signer_and_expiration_must_be_valid(self):
        row=indicator()
        for bad in [
            approval([row],expires_at=time_at(-1)),
            approval([row],approved_at=time_at(2)),
            approval([row],approved_by="reviewer-A"),
        ]:
            with self.assertRaises(ReviewError):
                batch(row,bad)

    def test_export_writes_restricted_local_file_and_no_network(self):
        rows=[indicator()]
        grant=approval(rows)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            manifest=root/"manifest.json"
            consent=root/"consent.json"
            output=root/"protected"/"bundle.json"
            manifest.write_text(json.dumps({"schema_version":"vynalth-ti-v1","indicators":rows}))
            consent.write_text(json.dumps(grant))
            result=export_to_file(manifest,consent,output,"stix",NOW)
            self.assertEqual(result["exported"],1)
            self.assertEqual(result["uploaded"],False)
            self.assertEqual(result["delivery"],"manual_only")
            self.assertTrue(output.exists())
            self.assertEqual(len(result["payload_sha256"]),64)
            if os.name=="posix":
                self.assertEqual(output.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ReviewError):
                export_to_file(manifest,consent,output,"stix",NOW)

    def test_reading_oversized_manifest_is_rejected(self):
        rows=[indicator()]
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            m=p/"manifest.json"
            a=p/"approval.json"
            m.write_text(" "*1048577)
            a.write_text(json.dumps(approval(rows)))
            with self.assertRaises(ReviewError):
                export_to_file(m,a,p/"dir"/"out.json","stix",NOW)

if __name__=="__main__":
    unittest.main()
