#!/usr/bin/env python3
"""Offline, read-only sample inventory: metadata/hash only; never execute files.

Run only against a copied/download-only Cowrie collection within a disposable
analysis machine. Do not scan arbitrary production directories.
"""
import argparse
import hashlib
import json
import os
import stat
from pathlib import Path


def inventory(directory: Path, max_size=20 * 1024 * 1024, max_files=200):
    results = []
    if not directory.is_dir():
        raise ValueError("sample directory missing")
    for entry in sorted(directory.iterdir(), key=lambda p: p.name)[:max_files]:
        if entry.is_symlink():
            continue
        info = entry.stat(follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_size:
            continue
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        digest = hashlib.sha256()
        try:
            fd = os.open(entry, flags)
            with os.fdopen(fd, "rb") as data:
                total = 0
                while True:
                    block = data.read(65536)
                    if not block:
                        break
                    total += len(block)
                    if total > max_size:
                        raise ValueError("file grew beyond cap")
                    digest.update(block)
        except (OSError, ValueError):
            continue
        results.append({
            "sha256": digest.hexdigest(),
            "size_bytes": total,
            "classification": "UNVERIFIED_SAMPLE",
            "analyzed": False,
            "executed": False
        })
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.resolve().is_relative_to(args.directory.resolve()):
        p.error("Output must be outside the untrusted sample directory")
    result = inventory(args.directory)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wt", encoding="utf-8") as out:
        try:
            os.chmod(args.output, 0o600)
        except OSError:
            pass
        json.dump({"schema": "vynalth-sample-manifest-v1",
                   "count": len(result), "samples": result}, out, indent=2)
    print(json.dumps({"count": len(result), "metadata_only": True,
                      "executed": False}))


if __name__ == "__main__":
    main()
