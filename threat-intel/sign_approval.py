#!/usr/bin/env python3
"""Deliberate, LOCAL-only HMAC approval signing after manual analyst review.

This does not authenticate a human's identity. Real multi-party approvals
require independent authenticated back-office controls before external delivery.
"""
import argparse
import json
import os
from pathlib import Path
import sys

from intel import APPROVAL_FIELDS, ReviewError, read_json, sign_approval


def write_signed_approval(source, output, confirmed=False):
    if not confirmed:
        raise ReviewError("manual approval flag required")
    document = read_json(source)
    if not isinstance(document, dict) or set(document) != APPROVAL_FIELDS - {"signature"}:
        raise ReviewError("approval form must match exact unsigned schema")
    if document["approved"] is not True:
        raise ReviewError("review status must be approved")
    if output.exists() or output.is_symlink():
        raise ReviewError("will not overwrite an existing signed approval")
    key = os.environ.get("VYNALTH_TI_APPROVAL_HMAC_KEY", "")
    signed = dict(document)
    signed["signature"] = sign_approval(signed, key)
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(signed, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return {"signed": True, "sent": False, "approval_id": signed["approval_id"]}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--confirm-human-review", action="store_true")
    args = p.parse_args()
    try:
        info = write_signed_approval(
            args.input, args.output, confirmed=args.confirm_human_review)
    except (ReviewError, OSError) as error:
        print("SIGNING_BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(2)
    print(json.dumps(info))


if __name__ == "__main__":
    main()
