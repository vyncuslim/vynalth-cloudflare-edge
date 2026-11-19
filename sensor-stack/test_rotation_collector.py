"""Rotation-aware Cowrie/OpenCanary source retention and signed health tests.

Synthetic input only. No network, no real passwords, no production deployment.
"""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_spool import EvidenceError,verify
from rotation_collector import collect,health_status

KEY="test-rotation-key-"+"z"*54
SENSOR="ci-rotation-01"


def row(event="cowrie.session.connect"):
    return {"eventid":event,"protocol":"ssh",
            "timestamp":"2026-11-19T12:02:00.000Z",
            "session":"secret-raw-session","src_ip":"198.51.100.77",
            "username":"PRIVATE-NAME","password":"PRIVATE-PASSWORD"}


def serialize(*events):
    return "".join(json.dumps(e)+"\n" for e in events)


class RotationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base=Path(self.temp.name)
        self.logs=self.base/"raw"
        self.logs.mkdir()
        self.active=self.logs/"cowrie.json"
        self.active.write_bytes(b"")
        self.db=self.base/"private"/"events.db"
        self.health=self.base/"private"/"collector.json"

    def cycle(self,**opts):
        opts.setdefault("min_free_mb",0)
        return collect(self.logs,"cowrie.json",self.db,self.health,
                       "cowrie",SENSOR,KEY,**opts)

    def test_initial_collection_and_signed_health(self):
        self.active.write_text(serialize(row(),row("cowrie.login.failed")))
        response=self.cycle()
        self.assertEqual(response["status"],"healthy")
        self.assertEqual(response["new_sanitized_events"],2)
        self.assertEqual(response["remaining_bytes"],0)
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],2)
        self.assertTrue(health_status(self.health,KEY)["healthy"])
        self.assertNotIn("PRIVATE-PASSWORD",self.db.read_bytes().decode("latin-1"))
        self.assertNotIn("198.51.100.77",self.health.read_text())
        self.assertEqual(self.health.stat().st_mode & 0o777,0o600)

    def test_rotation_preserves_unread_tail_and_drains_before_new_log(self):
        self.active.write_text(serialize(
            row(),row("cowrie.login.failed"),row("cowrie.command.input")))
        first=self.cycle(batch_size=1,max_rounds=1)
        self.assertEqual(first["new_sanitized_events"],1)
        self.assertEqual(first["status"],"backlogged")
        old=self.logs/"cowrie.json.1"
        self.active.rename(old)
        self.active.write_text(serialize(row("cowrie.session.closed")))
        second=self.cycle(batch_size=1,max_rounds=4)
        self.assertEqual(second["new_sanitized_events"],3)
        self.assertEqual(second["status"],"healthy")
        self.assertEqual(second["archives_retained"],1)
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],4)
        self.assertEqual(self.cycle()["new_sanitized_events"],0)

    def test_lost_unread_archive_is_detected_and_blocks_processing(self):
        self.active.write_text(serialize(row(),row("cowrie.login.failed")))
        self.cycle(batch_size=1,max_rounds=1)
        replacement=self.logs/"newfile.json"
        replacement.write_text(serialize(row("cowrie.command.input")))
        os.replace(replacement,self.active)
        with self.assertRaisesRegex(EvidenceError,"unread archive vanished"):
            self.cycle()
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],1)

    def test_inplace_rewrite_same_inode_cannot_hide_unread_data(self):
        self.active.write_text(serialize(row(),row("cowrie.login.failed")))
        self.cycle(batch_size=1,max_rounds=1)
        original=self.active.stat().st_ino
        self.active.write_text(serialize(row("cowrie.command.failed")))
        self.assertEqual(self.active.stat().st_ino,original)
        with self.assertRaisesRegex(EvidenceError,"unread archive vanished"):
            self.cycle()
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],1)

    def test_rename_processed_archive_no_dup_even_at_capacity(self):
        self.active.write_text(serialize(row()))
        self.cycle(max_records=1)
        self.active.rename(self.logs/"cowrie.json.1")
        self.active.write_bytes(b"")
        result=self.cycle(max_records=1)
        self.assertEqual(result["new_sanitized_events"],0)
        self.assertEqual(result["status"],"healthy")
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],1)

    def test_archived_partial_last_line_fails_closed(self):
        self.active.write_bytes(b"")
        (self.logs/"cowrie.json.1").write_text(serialize(row())[:-1])
        with self.assertRaisesRegex(EvidenceError,"incomplete JSONL"):
            self.cycle()

    def test_active_partial_line_recovers_on_next_cycle(self):
        line=serialize(row())
        self.active.write_text(line[:-1])
        first=self.cycle()
        self.assertEqual(first["new_sanitized_events"],0)
        self.assertEqual(first["status"],"backlogged")
        with self.assertRaisesRegex(EvidenceError,"backlog"):
            health_status(self.health,KEY)
        with self.active.open("a") as stream:
            stream.write("\n")
        second=self.cycle()
        self.assertEqual(second["new_sanitized_events"],1)
        self.assertTrue(health_status(self.health,KEY)["healthy"])

    def test_unknown_archive_and_compressed_archive_blocked(self):
        (self.logs/"cowrie.json.1.gz").write_bytes(b"x")
        with self.assertRaisesRegex(EvidenceError,"unrecognized archive"):
            self.cycle()
        (self.logs/"cowrie.json.1.gz").unlink()
        (self.logs/"cowrie.json.tmp").write_bytes(b"{}")
        with self.assertRaises(EvidenceError):
            self.cycle()

    def test_malicious_symlink_source_rejected(self):
        (self.logs/"cowrie.json.1").symlink_to(self.active)
        with self.assertRaises(EvidenceError):
            self.cycle()
        (self.logs/"cowrie.json.1").unlink()
        self.active.unlink()
        self.active.symlink_to(self.base)
        with self.assertRaises(EvidenceError):
            self.cycle()

    def test_missing_active_rejected(self):
        self.active.unlink()
        with self.assertRaisesRegex(EvidenceError,"active JSONL"):
            self.cycle()

    def test_queue_at_capacity_fails_and_rolls_back(self):
        self.active.write_text(serialize(row(),row("cowrie.login.failed")))
        with self.assertRaisesRegex(EvidenceError,"cap reached"):
            self.cycle(max_records=1)
        self.assertFalse(self.health.exists())
        with sqlite3.connect(self.db) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM sanitized_event").fetchone()[0],0)

    def test_health_hmac_rejects_tampering(self):
        self.active.write_text(serialize(row()))
        self.cycle()
        data=json.loads(self.health.read_text())
        data["report"]["queue_rows"]=500
        self.health.write_text(json.dumps(data))
        with self.assertRaisesRegex(EvidenceError,"tampered"):
            health_status(self.health,KEY)

    def test_health_refuses_stale_heartbeat_and_wrong_key(self):
        self.active.write_text(serialize(row()))
        self.cycle()
        later=datetime.now(timezone.utc)+timedelta(minutes=10)
        with self.assertRaisesRegex(EvidenceError,"stale"):
            health_status(self.health,KEY,current_time=later)
        with self.assertRaises(EvidenceError):
            health_status(self.health,"invalid"+"x"*40)

    def test_retained_file_count_limit(self):
        for n in range(1,33):
            (self.logs/f"cowrie.json.{n}").write_bytes(b"")
        with self.assertRaisesRegex(EvidenceError,"more than 32"):
            self.cycle()

    def test_dated_archives_are_valid(self):
        self.active.write_text(serialize(row("cowrie.login.failed")))
        (self.logs/"cowrie.json.2026-11-18").write_text(serialize(row()))
        result=self.cycle()
        self.assertEqual(result["archives_retained"],1)
        self.assertEqual(verify(self.db,KEY)["sanitized_events"],2)

    def test_out_of_disk_policy_refuses_new_evidence(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        self.active.write_text(serialize(row()))
        with patch("rotation_collector.shutil.disk_usage",
                   return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(EvidenceError,"free-space threshold"):
                self.cycle(min_free_mb=128)

    def test_no_export_of_raw_identifiers(self):
        self.active.write_text(serialize(row("cowrie.command.input")))
        self.cycle()
        stored=self.db.read_bytes()
        for secret in (b"PRIVATE-NAME",b"PRIVATE-PASSWORD",
                       b"198.51.100.77",b"secret-raw-session"):
            self.assertNotIn(secret,stored)


if __name__=="__main__":
    unittest.main()
