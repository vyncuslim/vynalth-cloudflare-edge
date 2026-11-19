"""Durable, *offline* honeypot spool integrity and restart tests.

All input JSON is synthetic. No public scans, cloud resources or credentials.
"""
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_spool import EvidenceError, spool, verify, safe_store_path

KEY="ci-spool-hmac-key-"+"7"*52
SENSOR="lab-ssh-01"


def cowrie(eventid="cowrie.session.connect",**other):
    item={
        "eventid":eventid,"protocol":"ssh","session":"dont-expose-this-session",
        "timestamp":"2026-11-19T12:00:00.000Z",
        "src_ip":"198.51.100.123",
        "username":"PRIVATE_USERNAME",
        "password":"PRIVATE_PASSWORD_123",
        "input":"curl https://secret.example/internal?sensitive=yes",
    }
    item.update(other)
    return item


def lines(*events):
    return "".join(json.dumps(x,separators=(",",":"))+"\n" for x in events)


class DurableSpoolTests(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root=Path(self.folder.name)
        self.raw=self.root/"cowrie.jsonl"
        self.store=self.root/"restricted"/"spool.db"

    def append(self,*events):
        with self.raw.open("a",encoding="utf-8") as f:
            f.write(lines(*events))

    def run_spool(self,**kw):
        return spool(self.raw,self.store,"cowrie",SENSOR,KEY,**kw)

    def test_ingest_and_restarts_do_not_duplicate(self):
        self.raw.write_text(lines(cowrie(),cowrie("cowrie.login.failed")),encoding="utf-8")
        result=self.run_spool()
        self.assertEqual(result["new_events"],2)
        self.assertEqual(result["checkpoint_bytes"],self.raw.stat().st_size)
        self.assertFalse(result["external_uploads"])
        self.assertFalse(result["raw_credentials_stored"])
        self.assertEqual(self.run_spool()["new_events"],0)
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],2)
        self.append(cowrie("cowrie.command.input"))
        self.assertEqual(self.run_spool()["new_events"],1)
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],3)

    def test_spool_contains_only_sanitized_data(self):
        self.raw.write_text(lines(cowrie(),cowrie("cowrie.command.input")))
        self.run_spool()
        db_bytes=self.store.read_bytes()
        for sensitive in (b"PRIVATE_USERNAME",b"PRIVATE_PASSWORD_123",
                          b"secret.example",b"dont-expose-this-session",
                          b"198.51.100.123"):
            self.assertNotIn(sensitive,db_bytes)
        with sqlite3.connect(self.store) as db:
            rows=[json.loads(x[0]) for x in db.execute(
                "SELECT payload_json FROM sanitized_event")]
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[1]["command_category"],"download_attempt")
        self.assertEqual(rows[0]["indicator_status"],"observation_only")
        self.assertFalse(rows[0]["share_authorized"])
        if os.name=="posix":
            self.assertEqual(self.store.stat().st_mode & 0o777,0o600)
            self.assertEqual(self.store.parent.stat().st_mode & 0o777,0o700)

    def test_partial_line_is_not_acknowledged_until_complete(self):
        source=lines(cowrie("cowrie.session.connect"))
        cut=len(source)//2
        self.raw.write_bytes(source[:cut].encode())
        first=self.run_spool()
        self.assertEqual(first["new_events"],0)
        self.assertEqual(first["checkpoint_bytes"],0)
        with self.raw.open("ab") as f:
            f.write(source[cut:].encode())
        second=self.run_spool()
        self.assertEqual(second["new_events"],1)
        self.assertEqual(second["checkpoint_bytes"],self.raw.stat().st_size)

    def test_capacity_error_rolls_back_checkpoint_and_batch(self):
        self.raw.write_text(lines(cowrie(),cowrie("cowrie.login.failed")))
        self.assertEqual(self.run_spool(max_records=2)["new_events"],2)
        old=self.raw.stat().st_size
        self.append(cowrie("cowrie.command.input"))
        with self.assertRaisesRegex(EvidenceError,"cap reached"):
            self.run_spool(max_records=2)
        with sqlite3.connect(self.store) as db:
            checkpoint=db.execute("SELECT position FROM input_checkpoint").fetchone()[0]
        self.assertEqual(checkpoint,old)
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],2)
        self.assertEqual(self.run_spool(max_records=3)["new_events"],1)

    def test_rotation_to_new_inode_restarts_from_zero(self):
        self.raw.write_text(lines(cowrie()))
        self.assertEqual(self.run_spool()["new_events"],1)
        new=self.root/"new.jsonl"
        new.write_text(lines(cowrie("cowrie.login.success")))
        os.replace(new,self.raw)
        result=self.run_spool()
        self.assertTrue(result["file_replaced_or_truncated"])
        self.assertEqual(result["new_events"],1)
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],2)

    def test_inplace_truncation_is_detected(self):
        self.raw.write_text(lines(cowrie(),cowrie("cowrie.login.failed"),
                                  cowrie("cowrie.login.success")))
        self.run_spool()
        self.raw.write_text(lines(cowrie("cowrie.command.failed")))
        self.assertTrue(self.run_spool()["file_replaced_or_truncated"])
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],4)

    def test_corrupted_hmac_fails_verification(self):
        self.raw.write_text(lines(cowrie()))
        self.run_spool()
        with sqlite3.connect(self.store) as db:
            db.execute("UPDATE sanitized_event SET payload_json='{}'")
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            verify(self.store,KEY)
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            verify(self.store,"a-different-test-key-"+"b"*40)

    def test_unknown_event_is_counted_but_not_exported(self):
        self.raw.write_text(lines(
            cowrie("cowrie.not-recognized"),
            cowrie("cowrie.session.connect"),
            {"source":"malicious","password":"DROP TABLE"},
        ))
        result=self.run_spool()
        self.assertEqual(result["new_events"],1)
        self.assertEqual(result["rejected_rows"],2)
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],1)

    def test_bounded_batch_consumes_events_in_order(self):
        self.raw.write_text(lines(*[cowrie() for _ in range(5)]))
        a=self.run_spool(max_lines=2)
        b=self.run_spool(max_lines=2)
        c=self.run_spool(max_lines=2)
        self.assertEqual([a["new_events"],b["new_events"],c["new_events"]],[2,2,1])
        self.assertEqual(verify(self.store,KEY)["sanitized_events"],5)
        self.assertEqual(self.run_spool(max_lines=2)["new_events"],0)

    def test_symlinks_and_insecure_parent_are_rejected(self):
        self.raw.write_text(lines(cowrie()))
        linked=self.root/"input_link"
        linked.symlink_to(self.raw)
        with self.assertRaises(EvidenceError):
            spool(linked,self.store,"cowrie",SENSOR,KEY)
        self.store.parent.mkdir(mode=0o755)
        self.store.parent.chmod(0o755)
        with self.assertRaises(EvidenceError):
            self.run_spool()
        self.store.parent.chmod(0o700)
        self.assertEqual(self.run_spool()["new_events"],1)

    def test_oversized_line_and_wrong_key_do_not_store_raw_data(self):
        huge={"eventid":"cowrie.session.connect","password":"SECRET"*11000}
        self.raw.write_text(lines(huge,cowrie()))
        result=self.run_spool()
        self.assertEqual(result["new_events"],1)
        self.assertGreaterEqual(result["rejected_rows"],1)
        with self.assertRaises(EvidenceError):
            self.run_spool(max_lines=0)
        with self.assertRaises(EvidenceError):
            spool(self.raw,self.store,"cowrie",SENSOR,"short")

    def test_opencanary_mysql_ftp_without_original_ip(self):
        self.raw.write_text(lines(
           {"dst_port":13306,"logtype":1001,
            "timestamp":"2026-11-19T12:00:00Z",
            "src_host":"203.0.113.2","password":"VERY_SECRET"},
           {"dst_port":2121,"logtype":1002,
            "timestamp":"2026-11-19T12:00:05Z",
            "src_host":"203.0.113.2"}
        ))
        result=spool(self.raw,self.store,"opencanary","sensor-02",KEY)
        self.assertEqual(result["new_events"],2)
        self.assertNotIn(b"VERY_SECRET",self.store.read_bytes())
        self.assertNotIn(b"203.0.113.2",self.store.read_bytes())

if __name__=="__main__":
    unittest.main()
