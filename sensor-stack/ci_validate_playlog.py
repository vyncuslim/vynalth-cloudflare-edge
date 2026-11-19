#!/usr/bin/env python3
"""CI-only local read-only Cowrie TTY frame replay, output never rendered.

This validates Cowrie's binary recording against its UML-style framing.
It does not claim the official Cowrie playlog CLI is installed or invoked.
"""
import json
from pathlib import Path
import re
import sys

from safe_tty_replay import ReplayError, safe_replay


def run(logfile: Path, tty_dir: Path):
    if logfile.is_symlink() or not logfile.is_file():
        raise RuntimeError("missing Cowrie audit")
    if tty_dir.is_symlink() or not tty_dir.is_dir():
        raise RuntimeError("missing approved TTY directory")
    names=[]
    with logfile.open("rb") as stream:
        for i,line in enumerate(stream):
            if i >= 3000:
                break
            if len(line)>65536:
                continue
            try:
                record=json.loads(line)
            except (ValueError,UnicodeError):
                continue
            if not isinstance(record,dict) or record.get("eventid")!="cowrie.log.closed":
                continue
            path=record.get("ttylog")
            if not isinstance(path,str) or len(path)>500:
                continue
            name=Path(path).name
            if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}",name):
                names.append(name)
    if not names:
        raise RuntimeError("no completed Cowrie TTY events")
    for name in names[:3]:
        try:
            replay=safe_replay(tty_dir/name)
        except (ReplayError,OSError):
            continue
        return {
          "verified_tty_replay":True,
          "parsed_frames":replay["frames"],
          "decoded_stream_frames":replay["replayed_frames"],
          "decoded_stream_nonempty":replay["replayed_bytes"]>0,
          "terminal_output_suppressed":True,
          "official_playlog_invoked":False,
          "real_public_attack":False,
        }
    raise RuntimeError("no valid Cowrie TTY replay")


if __name__=="__main__":
    try:
        output=run(Path(sys.argv[1]),Path(sys.argv[2]))
        print(json.dumps(output,sort_keys=True))
    except (RuntimeError,OSError,IndexError):
        print("TTY_REPLAY_BLOCKED: unverifiable recording",file=sys.stderr)
        raise SystemExit(2)
