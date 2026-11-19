#!/usr/bin/env python3
"""Isolated, read-only Cowrie TTY recording format validator and safe replay.

Parses Cowrie's UML-style binary frames (<iLiiLL) without launching commands,
connecting to the network, or printing attacker-controlled terminal bytes.
A replay is reconstructed into an in-memory digest sink, never a terminal.
This independently checks the recording format; it is not a claim that the
Cowrie-installed playlog executable was run.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys

FRAME = struct.Struct("<iLiiLL")
OP_OPEN, OP_CLOSE, OP_WRITE, OP_EXEC = 1, 2, 3, 4
INPUT, OUTPUT, INTERACTIVE = 1, 2, 3
MAX_FILE = 20*1024*1024
MAX_FRAME = 1024*1024
MAX_FRAMES = 100000


class ReplayError(ValueError):
    pass


def safe_replay(path: Path):
    path=Path(path)
    if path.is_symlink() or not path.is_file():
        raise ReplayError("local regular recording required")
    fd=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0)|
               getattr(os,"O_NONBLOCK",0))
    with os.fdopen(fd,"rb") as stream:
        info=os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_FILE:
            raise ReplayError("TTY recording too large or nonregular")
        source_sha=hashlib.sha256()
        output_sha=hashlib.sha256()
        output_bytes=0
        frames=output_frames=input_frames=0
        close_events=0
        tty_number=None
        chosen_direction=None
        while True:
            raw=stream.read(FRAME.size)
            if not raw:
                break
            if len(raw)!=FRAME.size:
                raise ReplayError("truncated terminal frame")
            op,tty,length,direction,sec,usec=FRAME.unpack(raw)
            if op not in {OP_OPEN,OP_CLOSE,OP_WRITE,OP_EXEC}:
                raise ReplayError("unknown terminal frame operation")
            if length<0 or length>MAX_FRAME:
                raise ReplayError("frame length exceeds limit")
            if usec >= 1_000_000:
                raise ReplayError("terminal frame microseconds out of range")
            if frames>=MAX_FRAMES:
                raise ReplayError("too many terminal frames")
            if tty_number is None:
                tty_number=tty
            elif tty!=tty_number:
                # File may contain multiplexed channels, but only one
                # channel is replayed to avoid mixing independent sessions.
                pass
            data=stream.read(length)
            if len(data)!=length:
                raise ReplayError("terminal payload truncated")
            source_sha.update(raw)
            source_sha.update(data)
            frames+=1
            if op==OP_CLOSE:
                close_events+=1
            if op==OP_WRITE:
                if direction not in {INPUT,OUTPUT,INTERACTIVE}:
                    raise ReplayError("invalid TTY stream direction")
                if direction==INPUT:
                    input_frames+=1
                if tty==tty_number:
                    if chosen_direction is None and direction!=INTERACTIVE:
                        chosen_direction=direction
                    if direction in {chosen_direction,INTERACTIVE}:
                        # Reconstruct exact stream bytes in a HASH sink. This
                        # intentionally does not interpret ANSI, execute shell
                        # commands, or render attacker controlled content.
                        output_sha.update(data)
                        output_frames+=1
                        output_bytes+=len(data)
    if frames<2 or output_frames<1 or output_bytes==0:
        raise ReplayError("TTY has no verifiable replay output")
    return {
      "validated":True,
      "source_tty_sha256":source_sha.hexdigest(),
      "replay_sha256":output_sha.hexdigest(),
      "frames":frames,
      "replayed_frames":output_frames,
      "replayed_bytes":output_bytes,
      "input_frame_count":input_frames,
      "close_frames":close_events,
      "rendered_to_terminal":False,
      "file_executed":False,
      "network_access":False,
      "official_playlog_invoked":False,
    }


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tty",type=Path,required=True)
    args=parser.parse_args()
    try:
        result=safe_replay(args.tty)
    except (ReplayError,OSError,struct.error):
        print("REPLAY_BLOCKED: malformed or unsafe terminal data",file=sys.stderr)
        raise SystemExit(2)
    # Never print replay bytes or source filenames.
    print(json.dumps(result,sort_keys=True))


if __name__=="__main__":
    main()
