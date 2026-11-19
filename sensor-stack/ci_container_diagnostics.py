#!/usr/bin/env python3
"""Report only sanitized Docker health classifications, not raw honeypot logs."""
import json
import subprocess

NAMES=("vynalth-lab-cowrie","vynalth-lab-opencanary")
KEYWORDS={
 "permission_denied":("permission denied","permissionerror","operation not permitted"),
 "startup_traceback":("traceback","exception"),
 "port_bind_error":("address already in use","cannot listen","could not bind"),
 "config_error":("invalid config","configuration error","unknown option","no config"),
 "privilege_drop_error":("setuid","setgid","drop privileges"),
 "service_not_started":("no services configured","exited"),
}

def run(args):
    return subprocess.run(args,text=True,stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE,timeout=12,check=False)

def main():
    for name in NAMES:
        state=run(["docker","inspect","--format","{{json .State}}",name])
        try: status=json.loads(state.stdout) if state.returncode==0 else {}
        except ValueError:status={}
        logs=run(["docker","logs","--tail","500",name])
        combined=(logs.stdout+"\n"+logs.stderr).lower()
        categories=sorted(key for key,terms in KEYWORDS.items()
                          if any(term in combined for term in terms))
        print(json.dumps({
            "service":name,
            "running":status.get("Running"),
            "exit_code":status.get("ExitCode"),
            "oom_killed":status.get("OOMKilled"),
            "log_categories_only":categories,
        },sort_keys=True))
if __name__=="__main__":
    main()
