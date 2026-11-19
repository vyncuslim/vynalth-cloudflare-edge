"""Privacy-safe signed SOC monitor tests. Local synthetic files only."""
from datetime import datetime,timedelta,timezone
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_spool import EvidenceError
from rotation_collector import collect,_signed_health
from delivery_monitor import monitor,verify_alert
from spool_uplink import reserve,settle

KEY="test-only-private-monitor-HMAC-"+"7"*50


def event(kind="cowrie.session.connect"):
    return {"eventid":kind,"protocol":"ssh",
            "timestamp":"2026-11-19T11:00:00Z",
            "session":"private-session-777","src_ip":"198.51.100.10",
            "username":"SECRET_USERNAME","password":"SECRET_PASSWORD",
            "input":"curl https://private.invalid/credentials"}


class MonitorTests(unittest.TestCase):
    def setUp(self):
        root=tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.root=Path(root.name)
        self.raw=self.root/"raw"
        self.raw.mkdir()
        self.file=self.raw/"cowrie.json"
        self.file.write_text(json.dumps(event())+"\n")
        self.db=self.root/"private"/"events.db"
        self.health=self.root/"private"/"collector.json"
        self.alert=self.root/"private"/"monitor.json"
        collect(self.raw,"cowrie.json",self.db,self.health,
                "cowrie","ci-monitored-01",KEY,min_free_mb=0)

    def check(self,**kwargs):
        return monitor(self.db,self.health,self.alert,KEY,min_free_mb=0,**kwargs)

    def test_healthy_signed_monitor_default_is_offline(self):
        result=self.check()
        self.assertEqual(result["status"],"healthy")
        self.assertEqual(result["pending_upload_events"],1)
        self.assertFalse(result["network_alerts_sent"])
        self.assertFalse(result["raw_telemetry_included"])
        validated=verify_alert(self.alert,KEY)
        self.assertTrue(validated["alert_verified"])
        self.assertEqual(validated["status"],"healthy")
        self.assertNotIn("SECRET_PASSWORD",self.alert.read_text())
        self.assertNotIn("198.51.100.10",self.alert.read_text())
        self.assertEqual(self.alert.stat().st_mode&0o777,0o600)

    def test_no_events_is_healthy_but_no_capture_claim(self):
        self.file.write_bytes(b"")
        self.db.unlink()
        for sidecar in ("-wal","-shm"):
            (Path(str(self.db)+sidecar)).unlink(missing_ok=True)
        self.health.unlink()
        collect(self.raw,"cowrie.json",self.db,self.health,
                "cowrie","ci-monitored-01",KEY,min_free_mb=0)
        result=self.check()
        self.assertEqual(result["status"],"healthy")
        self.assertEqual(result["pending_upload_events"],0)
        self.assertFalse(result["real_internet_attacks_verified"])

    def test_held_delivery_emits_critical_alert_without_retries(self):
        ref,_=reserve(self.db,KEY)
        settle(self.db,KEY,ref,"uncertain")
        result=self.check()
        self.assertEqual(result["status"],"critical")
        self.assertIn("delivery_requires_review",result["reason_codes"])
        self.assertEqual(result["held_for_operator_review"],1)
        self.assertEqual(verify_alert(self.alert,KEY)["status"],"critical")

    def test_pending_threshold_exceeded(self):
        result=self.check(backlog_max=0)
        self.assertEqual(result["status"],"critical")
        self.assertIn("outbox_backlog",result["reason_codes"])

    def test_stale_collector_heartbeat_is_critical(self):
        stale={
           "schema":"vynalth-collector-health-v1",
           "checked_at_utc":(datetime.now(timezone.utc)-
                 timedelta(minutes=20)).isoformat(timespec="seconds").replace("+00:00","Z"),
           "status":"healthy","remaining_bytes":0,"queue_rows":1
        }
        _signed_health(self.health,stale,KEY.encode())
        result=self.check()
        self.assertEqual(result["status"],"critical")
        self.assertIn("collector_unhealthy_or_stale",result["reason_codes"])

    def test_unavailable_spool_creates_privacy_safe_critical_alert(self):
        self.db.rename(self.root/"lost.db")
        result=self.check()
        self.assertIn("outbox_missing_or_invalid",result["reason_codes"])
        self.assertEqual(result["status"],"critical")

    def test_signature_tampering_is_rejected(self):
        self.check()
        contents=json.loads(self.alert.read_text())
        contents["report"]["pending_upload_events"]=0
        self.alert.write_text(json.dumps(contents))
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            verify_alert(self.alert,KEY)
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            verify_alert(self.alert,"bad-key-"+("q"*60))

    def test_low_disk_is_critical_without_upload(self):
        with patch("delivery_monitor.shutil.disk_usage",
                   return_value=SimpleNamespace(free=0)):
            outcome=monitor(self.db,self.health,self.alert,KEY,min_free_mb=128)
        self.assertIn("disk_capacity_low",outcome["reason_codes"])
        self.assertFalse(outcome["network_alerts_sent"])

    def test_signed_status_expires_and_refuses_bad_time(self):
        self.check()
        now=datetime.now(timezone.utc)+timedelta(minutes=8)
        with self.assertRaisesRegex(EvidenceError,"stale"):
            verify_alert(self.alert,KEY,now=now)
        with self.assertRaises(EvidenceError):
            verify_alert(self.alert,KEY,max_age=1)

    def test_reject_out_of_range_monitor_threshold(self):
        with self.assertRaises(EvidenceError):
            self.check(backlog_max=-1)
        with self.assertRaises(EvidenceError):
            self.check(min_free_mb=4097)


if __name__=="__main__":
    unittest.main()
