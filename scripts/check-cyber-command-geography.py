#!/usr/bin/env python3
"""One-shot, low-volume worldwide HTTP probe of Vynalth's own public pages.

Check-Host is an external volunteer network. A 403/429 for automated probes
is NOT necessarily a real-human failure. No cookies, private IPs, API tokens,
user data, or request bodies are sent.
"""
import json
import sys
import time
import urllib.parse
import urllib.request

TARGETS = (
    "https://vynalthai.com/en/cyber-command",
    "https://vynalthai.com/api/public/cyber-command/ip-consensus",
)
BASE = "https://check-host.net"
HEADERS = {"Accept": "application/json", "User-Agent": "VynalthPublicReadOnlyGeoAudit/1.0"}

def get_json(url):
    req=urllib.request.Request(url,headers=HEADERS)
    with urllib.request.urlopen(req, timeout=12) as response:
        raw=response.read(45000)
        if response.status!=200 or len(raw)>45000: raise ValueError("check service error")
    return json.loads(raw)

def check(url):
    launch=BASE+"/check-http?"+urllib.parse.urlencode({"host":url,"max_nodes":10})
    reply=get_json(launch)
    if reply.get("ok")!=1 or not isinstance(reply.get("request_id"),str):
        return {"target":url,"status":"inconclusive","reason":"checking service refused probe"}
    request_id=reply["request_id"]
    # Never print request IDs, IPs or other potentially sensitive headers.
    nodes=reply.get("nodes") or {}
    result={}
    for _ in range(8):
        time.sleep(3)
        try:
            result=get_json(BASE+"/check-result/"+urllib.parse.quote(request_id))
        except Exception:
            continue
        if isinstance(result,dict) and len([v for v in result.values() if v is not None])>=len(nodes)*0.8: break
    records=[]
    if not isinstance(result,dict):
        return {"target":url,"status":"inconclusive","reason":"missing distributed results"}
    for server,info in nodes.items():
        value=result.get(server)
        sample=value[0] if isinstance(value,list) and value else None
        if not isinstance(sample,list):
            state="timeout" if value is None else "unknown"
            http_code=None
        else:
            http_code=str(sample[3]) if len(sample)>3 and sample[3] is not None else None
            state="http-ok" if http_code=="200" else ("http-error" if http_code else "network-error")
        country=info[1] if isinstance(info,list) and len(info)>1 else "unknown"
        records.append({"country":country,"state":state,"http_status":http_code})
    country_count=len(set(r["country"] for r in records if r["state"]=="http-ok"))
    return {"target":url,"node_count":len(records),"http_200_nodes":sum(r["state"]=="http-ok" for r in records),"http_200_countries":country_count,"records":records}

report=[]
for target in TARGETS:
    try: report.append(check(target))
    except Exception as error:
        report.append({"target":target,"status":"inconclusive","reason":type(error).__name__})
print(json.dumps(report,ensure_ascii=False,indent=2))
with open("geo-audit-results.json","w") as file: json.dump(report,file,indent=2)
# Intentionally don't assert global accessibility from automated probes.
# Operator must independently inspect failures and preserve WAF.

# Independently validate the *content*, not only HTTP 200. A 200 HTML SPA
# fallback or bot challenge is not an operational JSON intelligence API.
json_check = {"target": TARGETS[1], "status": "unverified"}
try:
    request = urllib.request.Request(TARGETS[1], headers=HEADERS)
    with urllib.request.urlopen(request, timeout=15) as upstream:
        content_type = upstream.headers.get("content-type", "")
        body = upstream.read(30000)
        if upstream.status != 200 or "application/json" not in content_type:
            raise ValueError("not-a-json-api")
    snapshot=json.loads(body)
    expected={"status":"ready","sourceId":"ipsum-public","metric":"blacklist-appearances","sourceName":"IPsum"}
    if any(snapshot.get(k)!=v for k,v in expected.items()):
        raise ValueError("wrong-source-or-metric")
    rows=snapshot.get("rows")
    if not isinstance(rows,list) or not 5 <= len(rows) <= 20:
        raise ValueError("rows-invalid")
    if not all(isinstance(r.get("ip"),str) and isinstance(r.get("listCount"),int)
        and 1 <= r["listCount"] <= 1000 for r in rows):
        raise ValueError("entries-invalid")
    json_check={"target":TARGETS[1],"status":"verified-json","rows":len(rows),
        "metric":snapshot["metric"],"sourceUpdatedAt":snapshot.get("sourceUpdatedAt")}
except Exception as error:
    json_check={"target":TARGETS[1],"status":"unverified","reason":type(error).__name__+":"+str(error)[:80]}
print("JSON_API_CHECK:",json.dumps(json_check,ensure_ascii=False))
with open("geo-audit-results.json","w") as file:
    json.dump({"httpProbes":report,"jsonApi":json_check},file,indent=2)
if json_check["status"]!="verified-json":
    print("Live API cannot be declared operational; HTTP 200 alone is insufficient.",file=sys.stderr)
    sys.exit(2)
