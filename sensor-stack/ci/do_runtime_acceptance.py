#!/usr/bin/env python3
"""Exercise the REAL SQLite Durable Object in local Cloudflare workerd.

Runs the repo's actual SensorReplayLedger class through the actual Wrangler
local runtime, kills the WHOLE Wrangler process, then boots a new process
with the SAME persisted SQLite state. No remote bindings, TiDB, public port,
production secret, Oracle/Cloudflare account, or actual attacker data used.

Result proves local workerd/Miniflare runtime persistence only, not hosted
Cloudflare account deployment, multi-region failover or TiDB transaction.
"""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


ROOT=Path(__file__).resolve().parents[2]
CONFIG=ROOT/"sensor-stack/ci/do-runtime-wrangler.toml"
WRANGLER=ROOT/"node_modules/.bin/wrangler"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0))
        return listener.getsockname()[1]


def post(port,path,obj):
    url=f"http://127.0.0.1:{port}{path}"
    body=json.dumps(obj,separators=(",",":")).encode("ascii")
    req=urllib.request.Request(url,data=body,method="POST",
                               headers={"Content-Type":"application/json"})
    try:
        with urllib.request.urlopen(req,timeout=8) as r:
            return r.status,json.loads(r.read(2048))
    except urllib.error.HTTPError as e:
        return e.code,json.loads(e.read(2048))


def ready(port):
    try:
        request=urllib.request.Request(f"http://127.0.0.1:{port}/ready")
        with urllib.request.urlopen(request,timeout=1):
            return True
    except urllib.error.HTTPError as e:
        return e.code==404
    except (OSError,TimeoutError):
        return False


def boot(port,persist,logs):
    # Wrangler spawns workerd; Linux process group lets CI terminate
    # everything on cleanup without leaking orphan listeners.
    env=os.environ.copy()
    for name in ("CLOUDFLARE_API_TOKEN","CLOUDFLARE_ACCOUNT_ID",
                 "TIDB_HONEYPOT_DATABASE_URL","HONEY_SENSOR_V2_KEY",
                 "HONEY_SENSOR_INGEST_KEY"):
        env.pop(name,None)
    env.update({
        "WRANGLER_SEND_METRICS":"false",
        "CLOUDFLARE_LOAD_DEV_VARS_FROM_DOT_ENV":"false",
        "CI":"true",
    })
    command=[str(WRANGLER),"dev","--config",str(CONFIG),"--local",
             "--persist-to",str(persist),"--ip","127.0.0.1",
             "--port",str(port)]
    proc=subprocess.Popen(command,cwd=ROOT,env=env,stdout=logs,
                          stderr=subprocess.STDOUT,start_new_session=True)
    until=time.monotonic()+60
    while time.monotonic()<until:
        if proc.poll() is not None:
            logs.flush()
            with open(logs.name,"rb") as local_log:
                # Only the synthetic, token-free CI harness is running.
                # Print bounded startup diagnostics so a real runtime
                # incompatibility cannot be misrepresented as success.
                excerpt=local_log.read()[-5000:].decode("utf-8","replace")
            for line in excerpt.splitlines()[-20:]:
                if any(word in line.lower() for word in
                       ("error","fail","cannot","not found","invalid","wrangler","entry")):
                    print("LOCAL_WORKER_STARTUP: "+line[:250],file=sys.stderr)
            raise AssertionError("workerd exited before serving localhost")
        if ready(port):
            return proc
        time.sleep(0.25)
    raise AssertionError("workerd local Durable Object did not become ready")


def stop(proc):
    if proc is None:
        return
    try:
        os.killpg(proc.pid,signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid,signal.SIGKILL)
        proc.wait(timeout=5)


def must(port,path,obj,status,outcome):
    code,response=post(port,path,obj)
    assert code==status and response=={"outcome":outcome}, (
        f"{path}: expected {status}/{outcome}, got {code}/{response}")
    return code


def exercise():
    assert CONFIG.is_file() and WRANGLER.is_file()
    with tempfile.TemporaryDirectory(prefix="vynalth-do-runtime-ci-") as folder:
        root=Path(folder)
        persist=root/"sqlite-persistent-state"
        with (root/"wrangler.log").open("w+b") as logs:
            port=free_port()
            process=None
            try:
                process=boot(port,persist,logs)
                now=int(time.time()*1000)
                a={"eventRef":"a"*64,"nowMs":now}
                b={"eventRef":"b"*64,"nowMs":now}
                c={"eventRef":"c"*64,"nowMs":now}
                d={"eventRef":"d"*64,"nowMs":now}
                must(port,"/claim",a,201,"claimed")
                print("PASS_STAGE initial_a",flush=True)
                must(port,"/claim",a,409,"duplicate")
                must(port,"/settle",{"eventRef":a["eventRef"],
                                     "state":"insert_acknowledged"},200,"settled")
                must(port,"/settle",{"eventRef":a["eventRef"],
                                     "state":"sampled_out"},409,"not_reserved")
                must(port,"/claim",b,201,"claimed")
                print("PASS_STAGE initial_b",flush=True)
                # Concurrent requests route to same actual SQLite-backed DO.
                with ThreadPoolExecutor(max_workers=16) as pool:
                    results=list(pool.map(
                        lambda _:post(port,"/claim",c),range(20)))
                codes=[x[0] for x in results]
                assert codes.count(201)==1, codes
                assert codes.count(409)==19, codes
                print("PASS_STAGE concurrent_20",flush=True)
                must(port,"/claim",d,201,"claimed")
                print("PASS_STAGE initial_d",flush=True)
                must(port,"/claim",{"eventRef":"G"*64,"nowMs":now},
                     400,"invalid_ref")
                must(port,"/claim",{"eventRef":"a"*64,"nowMs":-1},
                     400,"invalid")
                # Simulate unexpected developer/worker process termination:
                # state must reside in SQLite, never merely in memory.
                stop(process)
                process=None
                time.sleep(0.3)
                assert any(p.is_file() for p in persist.rglob("*")), (
                    "no local SQLite persistence state was created")
                process=boot(port,persist,logs)
                print("PASS_STAGE restarted_fresh_workerd",flush=True)
                # Four claims on four deterministic DO partitions survived
                # a COMPLETE process restart, including a reserved event.
                for obj in (a,b,c,d):
                    must(port,"/claim",obj,409,"duplicate")
                must(port,"/settle",{"eventRef":b["eventRef"],
                                     "state":"database_uncertain"},200,"settled")
                must(port,"/claim",b,409,"duplicate")
                # A fresh ref must still be accepted (not a global block).
                e={"eventRef":"e"*64,"nowMs":now+1000}
                must(port,"/claim",e,201,"claimed")
                print("PASS_STAGE fresh_e_after_restart",flush=True)
                print(json.dumps({
                   "runtime":"cloudflare_local_workerd_miniflare",
                   "sqlite_persist_to_reused":True,
                   "full_process_restarts_tested":1,
                   "persisted_distinct_shards":4,
                   "parallel_claim_requests":20,
                   "parallel_claims_accepted":1,
                   "parallel_duplicates_rejected":19,
                   "reserved_state_survived_restart":True,
                   "settlement_survived_restart":True,
                   "secrets_or_production_access_used":False,
                   "cloudflare_hosted_runtime_verified":False,
                   "real_tidb_insert_verified":False
                },sort_keys=True))
            finally:
                stop(process)


if __name__=="__main__":
    try:
        exercise()
    except Exception as exc:
        # No raw body, token or local source ID is included in fixed messages.
        print("DO_RUNTIME_ACCEPTANCE_FAILED: "+type(exc).__name__+" "+str(exc)[:160],
              file=sys.stderr)
        raise SystemExit(2)
