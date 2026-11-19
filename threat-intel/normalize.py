#!/usr/bin/env python3
"""Convert existing seven-column honeypot summary JSONL to internal observation index.

No network, no database connection, no raw credentials, no automatic
promotion to malicious indicators. A sensor summary without a trustworthy
timestamp must NOT be assigned an invented event time.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys
import uuid
import os

SOURCE_PROTOCOLS = {
    "cloudflare_worker": {"HTTP"},
    "cowrie": {"SSH", "TELNET"},
    "opencanary": {"FTP", "MYSQL", "REDIS"},
}
WEB_PATHS = {
    "/info.php", "/phpinfo.php", "/api/info.php", "/api/php-info.php",
    "/test.php", "/testphp.php", "/api/test.php",
    "/debug.php", "/diagnostics.php", "/health.php", "/api/debug.php",
    "/admin.php", "/administrator.php", "/login.php",
    "/admin/login.php", "/wp-login.php", "/phpmyadmin/index.php",
    "/pma/index.php", "/mysql/index.php", "/dbadmin.php", "/config.php",
    "/database.php", "/db.php", "/dbconnect.php", "/filemanager.php",
    "/files.php", "/backup.php", "/restore.php", "/wp-admin/install.php",
    "/api/phpinfo.php",
}
ACTIONS = {"connect","disconnect","login_attempt","command_observed",
           "session_replay_available","file_observed"}
FIELDS = {"event_type","source","protocol","source_ip_hash","country_code",
          "request_path","action_taken"}
NS = uuid.UUID("7172259e-5d6f-4372-b806-f5ca6f951a25")


def sanitize(row, line_no):
    if not isinstance(row,dict) or set(row) != FIELDS:
        return None
    source, proto, path = row["source"],row["protocol"],row["request_path"]
    if source not in SOURCE_PROTOCOLS or proto not in SOURCE_PROTOCOLS[source]:
        return None
    if row["event_type"] != "suspicious_probe":
        return None
    if source == "cloudflare_worker":
        if row["action_taken"] not in {"blocked","logged"} or path not in WEB_PATHS:
            return None
    elif source == "cowrie":
        if row["action_taken"] != "observed" or path not in {
            "/" + proto.lower() + "/" + a for a in ACTIONS}:
            return None
    elif source == "opencanary":
        if row["action_taken"] != "observed" or path != "/" + proto.lower() + "/probe":
            return None
    country = row["country_code"]
    if country is not None and (source != "cloudflare_worker" or not
        isinstance(country,str) or not re.fullmatch("[A-Z]{2}",country)):
        return None
    pseudonym=row["source_ip_hash"]
    if pseudonym is not None and (not isinstance(pseudonym,str) or
        not re.fullmatch("[0-9a-fA-F]{64}",pseudonym)):
        return None
    fingerprint=json.dumps(row,sort_keys=True,separators=(",",":"))
    return {
        "observation_id":str(uuid.uuid5(NS, fingerprint+"|"+str(line_no))),
        "source":source,
        "protocol":proto,
        "activity":path,
        "country_code":country,
        "action_taken":row["action_taken"],
        "network_pseudonym_present":pseudonym is not None,
        "observed_at":None,
        "verified_intrusion":False,
        "indicator_status":"observation_only",
        "sharing_allowed":False,
    }


def write_index(source, target, max_events=10000):
    if max_events<1 or max_events>10000:
        raise ValueError("max_events must be 1..10000")
    if not source.is_file() or source.is_symlink():
        raise ValueError("missing ordinary input file")
    if target.exists() or target.is_symlink():
        raise ValueError("refusing to overwrite output")
    if source.resolve() == target.resolve():
        raise ValueError("input and output cannot match")
    events=[]; skipped=0
    with source.open("rt",encoding="utf-8",errors="replace") as stream:
        for i,line in enumerate(stream,1):
            if i>max_events:break
            if len(line)>65536:
                skipped+=1;continue
            try: record=sanitize(json.loads(line),i)
            except (ValueError,TypeError):record=None
            if record is None:skipped+=1
            else:events.append(record)
    target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    body={"schema_version":"vynalth-observations-v1",
          "source_evidence":"validated_summary_records_only",
          "coverage":"partial_sampled_or_unknown",
          "events":events}
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w",encoding="utf-8") as output:
        json.dump(body,output,indent=2,sort_keys=True)
    counts=dict(sorted(Counter(e["protocol"] for e in events).items()))
    return {"accepted":len(events),"rejected":skipped,"by_protocol":counts,
            "promoted_indicators":0,"sent_to_network":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--max-events",type=int,default=10000)
    args=p.parse_args()
    try: result=write_index(args.input,args.output,args.max_events)
    except (ValueError,OSError) as exc:
        print("IMPORT_BLOCKED: "+str(exc),file=sys.stderr)
        sys.exit(2)
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
