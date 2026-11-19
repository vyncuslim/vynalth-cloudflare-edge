"""Offline custody and evidence retention audit acceptance tests."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_spool import EvidenceError
from rotation_collector import collect
from retention_audit import audit,verify_manifest

KEY="test-only-retention-key-"+"m"*48
SENSOR="ci-retention-sensor"


def row(kind="cowrie.session.connect"):
    return {"eventid":kind,"protocol":"ssh",
            "timestamp":"2026-11-19T12:00:00Z",
            "session":"PRIVATE_SESS","src_ip":"203.0.113.11",
            "password":"PRIVATE_SECRET"}


def jsonl(*rows):
    return "".join(json.dumps(r)+"\n" for r in rows)


class RetentionTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root=Path(folder.name)
        self.raw=self.root/"raw"
        self.raw.mkdir()
        self.active=self.raw/"cowrie.json"
        self.archive=self.raw/"cowrie.json.1"
        self.archive.write_text(jsonl(row(),row("cowrie.login.failed")))
        self.active.write_text(jsonl(row("cowrie.session.closed")))
        self.db=self.root/"private"/"evidence.db"
        self.health=self.root/"private"/"collector.json"
        self.manifest=self.root/"private"/"retention.json"

    def collect(self,**kw):
        return collect(self.raw,"cowrie.json",self.db,self.health,
                       "cowrie",SENSOR,KEY,min_free_mb=0,**kw)

    def audit(self):
        return audit(self.raw,"cowrie.json",self.db,self.manifest,
                     "cowrie",SENSOR,KEY)

    def test_physical_archive_hash_and_retention_manifest(self):
        self.collect()
        result=self.audit()
        self.assertEqual(result["archived_count"],1)
        self.assertEqual(result["uncheckpointed"],0)
        self.assertEqual(result["deletions"],0)
        signed=verify_manifest(self.manifest,KEY)
        self.assertTrue(signed["verified"])
        self.assertTrue(signed["no_files_deleted"])
        data=json.loads(self.manifest.read_text())["report"]
        self.assertEqual(data["retained_archives"][0]["source_name"],"cowrie.json.1")
        self.assertEqual(len(data["retained_archives"][0]["sha256"]),64)
        self.assertTrue(data["retained_archives"][0]["spool_checkpoint_complete"])
        self.assertFalse(data["retained_archives"][0]["operator_retention_release_approved"])
        self.assertTrue(self.archive.exists())
        for secret in ("PRIVATE_SESS","PRIVATE_SECRET","203.0.113.11"):
            self.assertNotIn(secret,self.manifest.read_text())

    def test_archive_is_held_until_all_bytes_processed(self):
        outcome=self.collect(batch_size=1,max_rounds=1)
        self.assertEqual(outcome["status"],"backlogged")
        result=self.audit()
        self.assertEqual(result["uncheckpointed"],1)
        data=json.loads(self.manifest.read_text())["report"]
        self.assertFalse(data["retained_archives"][0]["spool_checkpoint_complete"])
        self.assertFalse(data["retention_release_authorized"])
        self.assertTrue(self.archive.exists())

    def test_missing_unread_archive_cannot_be_silently_ignored(self):
        self.collect(batch_size=1,max_rounds=1)
        self.archive.unlink()
        with self.assertRaisesRegex(EvidenceError,"unread archive vanished"):
            self.audit()

    def test_symlinked_archive_never_hashed(self):
        self.collect()
        self.archive.unlink()
        self.archive.symlink_to(self.active)
        with self.assertRaises(EvidenceError):
            self.audit()

    def test_signed_inventory_rejects_tampering(self):
        self.collect()
        self.audit()
        contents=json.loads(self.manifest.read_text())
        contents["report"]["retained_archives"][0]["sha256"]="0"*64
        self.manifest.write_text(json.dumps(contents))
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            verify_manifest(self.manifest,KEY)

    def test_no_database_cannot_claim_retention(self):
        with self.assertRaises(EvidenceError):
            self.audit()

    def test_empty_archive_is_not_deleted(self):
        self.archive.write_bytes(b"")
        self.collect()
        self.audit()
        self.assertTrue(self.archive.exists())
        self.assertEqual(self.archive.stat().st_size,0)
        self.assertEqual(verify_manifest(self.manifest,KEY)["archived_count"],1)


if __name__=="__main__":
    unittest.main()
