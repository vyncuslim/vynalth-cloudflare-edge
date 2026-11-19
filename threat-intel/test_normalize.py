import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from normalize import sanitize, write_index

def row(source="cowrie", protocol="SSH", path="/ssh/login_attempt"):
    return {
        "event_type":"suspicious_probe","source":source,"protocol":protocol,
        "source_ip_hash":"a"*64,"country_code":None,"request_path":path,
        "action_taken":"observed"
    }

class NormalizeTests(unittest.TestCase):
    def test_known_cowrie_summaries_are_only_observations(self):
        original=row()
        normalized=sanitize(original,4)
        self.assertEqual(normalized["protocol"],"SSH")
        self.assertEqual(normalized["indicator_status"],"observation_only")
        self.assertFalse(normalized["verified_intrusion"])
        self.assertFalse(normalized["sharing_allowed"])
        self.assertIsNone(normalized["observed_at"])
        self.assertNotIn("a"*64,json.dumps(normalized))

    def test_ftp_mysql_redis_summary_acceptance(self):
        for protocol in ("FTP","MYSQL","REDIS"):
            with self.subTest(protocol=protocol):
                log=row("opencanary",protocol,"/"+protocol.lower()+"/probe")
                self.assertIsNotNone(sanitize(log,1))

    def test_http_decoys_are_exact_paths(self):
        entry=row("cloudflare_worker","HTTP","/admin.php")
        entry["action_taken"]="logged"
        entry["country_code"]="MY"
        self.assertIsNotNone(sanitize(entry,2))
        entry["request_path"]="/admin.php?password=sensitive"
        self.assertIsNone(sanitize(entry,2))
        entry["request_path"]="/api/internal"
        self.assertIsNone(sanitize(entry,2))

    def test_raw_password_and_ip_can_never_enter_observation_index(self):
        suspicious=row()
        for extra in ({"password":"DEMO_SECRET"},
                      {"src_ip":"203.0.113.88"},
                      {"command":"curl remote-file"}):
            with self.subTest(extra=extra):
                self.assertIsNone(sanitize({**suspicious,**extra},3))

    def test_false_source_and_path_are_rejected(self):
        self.assertIsNone(sanitize(row("unknown","SSH"),5))
        self.assertIsNone(sanitize(row("opencanary","SSH","/ssh/connect"),5))
        self.assertIsNone(sanitize(row(path="/ssh/not-real-command"),5))
        self.assertIsNone(sanitize(row() | {"source_ip_hash":"raw-ip"},5))

    def test_local_import_has_no_network_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as temp:
            p=Path(temp)
            source=p/"safe.jsonl"
            target=p/"restricted"/"observations.json"
            source.write_text(json.dumps(row())+"\n"+
                              json.dumps({**row(),"password":"DO_NOT_LEAK"})+"\n",
                              encoding="utf-8")
            result=write_index(source,target)
            self.assertEqual(result["accepted"],1)
            self.assertEqual(result["rejected"],1)
            self.assertEqual(result["promoted_indicators"],0)
            self.assertFalse(result["sent_to_network"])
            data=json.loads(target.read_text())
            self.assertEqual(len(data["events"]),1)
            self.assertNotIn("DO_NOT_LEAK",json.dumps(data))
            if os.name=="posix":
                self.assertEqual(target.stat().st_mode & 0o777,0o600)
            with self.assertRaises(ValueError):
                write_index(source,target)

if __name__=="__main__":
    unittest.main()
