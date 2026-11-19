import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from event_sanitizer import clean_event, anonymous_network_marker
from sample_inventory import inventory

SENSITIVE = "user_password_must_never_leak"
IP = "198.51.100.9"
STAMP = dt.datetime(2026, 11, 19, tzinfo=dt.timezone.utc)


class SensorStackTests(unittest.TestCase):
    def test_cowrie_sensitive_fields_dropped(self):
        entry = {
            "eventid": "cowrie.login.failed", "protocol": "ssh",
            "src_ip": IP, "username": "root", "password": SENSITIVE,
            "session": "private-session", "input": "curl hidden-payload",
            "timestamp": "2026-11-19T07:00:00Z"
        }
        row = clean_event(entry, "cowrie", secret="x" * 48, now=STAMP)
        self.assertEqual(row["source"], "cowrie")
        self.assertEqual(row["protocol"], "SSH")
        self.assertEqual(row["request_path"], "/ssh/login_attempt")
        self.assertEqual(len(row["source_ip_hash"]), 64)
        out = json.dumps(row)
        for forbidden in [SENSITIVE, IP, "private-session", "curl", "username"]:
            self.assertNotIn(forbidden, out)

    def test_real_tty_close_event_can_be_indexed_without_tty_bytes(self):
        row = clean_event({
            "eventid": "cowrie.log.closed", "protocol": "telnet",
            "src_ip": IP, "ttylog": "/cowrie/cowrie-git/var/lib/cowrie/tty/real.log",
            "shasum": "f" * 64
        }, "cowrie", now=STAMP)
        self.assertEqual(row["request_path"], "/telnet/session_replay_available")
        self.assertIsNone(row["source_ip_hash"])
        self.assertNotIn("ttylog", json.dumps(row))

    def test_opencanary_protocol_and_password_sanitized(self):
        entry = {
            "dst_port": 13306, "logtype": 2000, "src_host": IP,
            "logdata": {"PASSWORD": SENSITIVE, "USERNAME": "admin"},
        }
        row = clean_event(entry, "opencanary", secret="x" * 48, now=STAMP)
        self.assertEqual(row["protocol"], "MYSQL")
        self.assertEqual(row["request_path"], "/mysql/probe")
        self.assertNotIn(SENSITIVE, json.dumps(row))
        self.assertNotIn(IP, json.dumps(row))
        self.assertIsNone(clean_event({**entry, "dst_port": 4000}, "opencanary"))

    def test_invalid_unknown_events_cannot_pollute_table(self):
        self.assertIsNone(clean_event({"eventid": "other", "protocol": "ssh"}, "cowrie"))
        self.assertIsNone(clean_event({"dst_port": 13306, "logtype": "fake"}, "opencanary"))
        self.assertIsNone(clean_event({"eventid": "cowrie.login.failed", "protocol": "http"}, "cowrie"))

    def test_daily_hash_rotates_and_is_not_username(self):
        one = anonymous_network_marker(IP, "a" * 48, STAMP)
        two = anonymous_network_marker(IP, "a" * 48, STAMP + dt.timedelta(days=1))
        self.assertNotEqual(one, two)
        self.assertIsNone(anonymous_network_marker(IP, "short", STAMP))
        self.assertIsNone(anonymous_network_marker("invalid", "a" * 48, STAMP))

    def test_sample_inventory_never_executes_or_follows_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            data = b"\x7fELF" + b"malware-not-run"
            (p / "sample").write_bytes(data)
            (p / "outside").mkdir()
            (p / "outside" / "nested").write_bytes(b"ignored")
            (p / "symlink").symlink_to(p / "sample")
            rows = inventory(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["size_bytes"], len(data))
            self.assertEqual(rows[0]["executed"], False)
            self.assertEqual(rows[0]["analyzed"], False)
            self.assertNotIn("sample", json.dumps(rows))


if __name__ == "__main__":
    unittest.main()
