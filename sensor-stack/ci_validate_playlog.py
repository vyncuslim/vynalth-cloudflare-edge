#!/usr/bin/env python3
"""CI-only Cowrie playlog verification, with all terminal bytes suppressed.

Reads a genuine local JSONL log copied from disposable Cowrie Docker and
invokes the bundled Cowrie playlog command INSIDE that isolated container.
Never renders terminal escapes, raw commands, passwords or URLs to CI logs.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def run(logfile: Path):
    if logfile.is_symlink() or not logfile.is_file():
        raise RuntimeError("missing local Cowrie audit")
    tty_names=[]
    with logfile.open("rb") as stream:
        for i,line in enumerate(stream):
            if i>=3000:
                break
            if len(line)>65536:
                continue
            try:
                row=json.loads(line)
            except (ValueError,UnicodeError):
                continue
            if not isinstance(row,dict) or row.get("eventid")!="cowrie.log.closed":
                continue
            ttylog=row.get("ttylog")
            if not isinstance(ttylog,str) or len(ttylog)>500:
                continue
            name=Path(ttylog).name
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}",name):
                tty_names.append(name)
    if not tty_names:
        raise RuntimeError("no completed TTY recording in genuine Cowrie audit")
    for name in tty_names[:3]:
        location="/cowrie/cowrie-git/var/lib/cowrie/tty/"+name
        # Run no shell. Both command forms are confined to the Cowrie container.
        methods=[
            ["docker","exec","vynalth-lab-cowrie","playlog",location],
            ["docker","exec","vynalth-lab-cowrie",
             "/cowrie/cowrie-git/bin/playlog",location],
        ]
        for cmd in methods:
            with tempfile.TemporaryFile(mode="w+b") as output:
                try:
                    completed=subprocess.run(cmd,stdout=output,
                        stderr=subprocess.DEVNULL,timeout=20,check=False)
                except (OSError,subprocess.TimeoutExpired):
                    continue
                output.seek(0,os.SEEK_END)
                length=output.tell()
                if completed.returncode==0 and length>0:
                    return {
                      "source":"genuine_cowrie_tty",
                      "playlog_exit_zero":True,
                      "replay_emitted_bytes":True,
                      "recordings_checked":1,
                      "raw_terminal_output_printed":False,
                      "public_attacker_sessions":False,
                    }
    raise RuntimeError("Cowrie playlog could not replay any completed TTY safely")


if __name__=="__main__":
    try:
        result=run(Path(sys.argv[1]))
        print(json.dumps(result,sort_keys=True))
    except (RuntimeError,OSError,IndexError):
        print("PLAYLOG_BLOCKED: no verifiable isolated replay",file=sys.stderr)
        raise SystemExit(2)
