#!/usr/bin/env python3
"""Restricted evidence acquisition for authentic Cowrie/OpenCanary JSONL.

Offline by design. Never connects to Cloudflare, TiDB, VirusTotal, TAXII, MISP
or the internet. It indexes REAL source events only, and never emits plaintext
credentials, commands, URLs, IPs, uploaded bytes or TTY recordings. Actual TTY
replay and binary analysis require a separate authorized, air-gapped workflow.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

SCHEMA = "vynalth-restricted-evidence-v1"
NS = uuid.UUID("0f76ae12-c9ef-4fb1-b827-6f3064c5ba49")
COWRIE_EVENTS = {
    "cowrie.session.connect": "connection",
    "cowrie.session.closed": "disconnection",
    "cowrie.login.failed": "authentication_attempt",
    "cowrie.login.success": "honeypot_login_accepted",
    "cowrie.command.input": "shell_command",
    "cowrie.command.failed": "shell_command",
    "cowrie.log.closed": "tty_finalized",
    "cowrie.session.file_download": "file_arrival",
    "cowrie.session.file_upload": "file_arrival",
}
OPEN_PORTS = {2121: "FTP", 13306: "MYSQL", 16379: "REDIS",
              21: "FTP", 3306: "MYSQL", 6379: "REDIS"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
FILE_NAME = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
MAX_LINE = 65536
MAX_BYTES = 20 * 1024 * 1024


class EvidenceError(ValueError):
    pass


def stable_ref(key: bytes, category: str, value: str):
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    raw = (category + "|" + value).encode("utf-8", errors="strict")
    return hmac.new(key, raw, hashlib.sha256).hexdigest()


def normalized_time(value):
    if not isinstance(value, str) or len(value) > 40:
        return None
    try:
        # Cowrie uses UTC ISO8601. Never replace a missing timestamp with now.
        t = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t.tzinfo is None or not 2000 <= t.year <= 2100:
            return None
        return t.astimezone(timezone.utc).isoformat(
            timespec="milliseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError):
        return None


def network_ref(ip, key: bytes, when):
    if not when or not isinstance(ip, str):
        return None
    try:
        address = ipaddress.ip_address(ip)
        date = when[:10]
        return stable_ref(key, "network-" + date, address.compressed)
    except ValueError:
        return None


def command_class(command):
    """Coarse behavioral categories; never retain/export literal commands."""
    if not isinstance(command, str):
        return "unclassified"
    command = command[:8192].lower()
    if re.search(r"\b(?:wget|curl|tftp|ftpget|busybox\s+wget)\b", command):
        return "download_attempt"
    if re.search(r"\b(?:crontab|systemctl|rc\.local)\b", command):
        return "persistence_attempt"
    if re.search(r"\b(?:chmod|chattr|useradd|passwd)\b", command):
        return "privilege_or_access_change"
    if re.search(r"\b(?:uname|whoami|id|ip|ifconfig|ps|netstat|cat)\b", command):
        return "reconnaissance"
    if re.search(r"\b(?:rm|kill|pkill)\b", command):
        return "destructive_or_process_control"
    return "other_command"


def local_artifact(directory: Path | None, source_name, max_size=MAX_BYTES):
    """Hash referenced file within an approved local directory, no symlinks.

    The raw log can contain arbitrary paths. Only a strict basename is
    considered; no path from a source event is ever opened directly.
    """
    if directory is None or not isinstance(source_name, str):
        return None
    name = Path(source_name).name
    if name in {".", ".."} or not FILE_NAME.fullmatch(name):
        return None
    if not directory.is_dir() or directory.is_symlink():
        return None
    target = directory / name
    if target.is_symlink():
        return None
    try:
        mode = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(target, mode)
    except OSError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > max_size:
            return None
        digest = hashlib.sha256()
        first = b""
        read = 0
        while True:
            part = stream.read(65536)
            if not part:
                break
            read += len(part)
            if read > max_size:
                return None
            if len(first) < 16:
                first += part[:16 - len(first)]
            digest.update(part)
        if read != info.st_size:
            return None
    magic = "ELF" if first.startswith(b"\x7fELF") else (
        "PE_or_DOS" if first.startswith(b"MZ") else (
        "ZIP" if first.startswith(b"PK\x03\x04") else (
        "script" if first.startswith(b"#!") else "unknown")))
    return {"sha256": digest.hexdigest(), "size_bytes": read,
            "file_type_hint": magic}


def _identifier(event):
    value = event.get("session")
    return value if isinstance(value, str) and 0 < len(value) < 128 else None


def _canonical_event(raw, source, key: bytes, line_no, tty_dir, download_dir):
    if not isinstance(raw, dict):
        return None
    evidence = None
    if source == "cowrie":
        event_id = raw.get("eventid")
        kind = COWRIE_EVENTS.get(event_id)
        proto = str(raw.get("protocol") or "").upper()
        if kind is None or proto not in {"SSH", "TELNET"}:
            return None
        when = normalized_time(raw.get("timestamp"))
        session = stable_ref(key, "session", _identifier(raw))
        pseudonym = network_ref(raw.get("src_ip"), key, when)
        category = command_class(raw.get("input")) if kind == "shell_command" else None
        if kind in {"tty_finalized", "file_arrival"}:
            is_tty = kind == "tty_finalized"
            file = local_artifact(tty_dir if is_tty else download_dir,
                                  raw.get("ttylog" if is_tty else "outfile"))
            expected = raw.get("shasum")
            expected = expected.lower() if isinstance(expected, str) and HEX64.fullmatch(expected.lower()) else None
            reported_size = raw.get("size")
            size_matches = (reported_size == file["size_bytes"]) if (is_tty and file and type(reported_size) is int) else None
            # Cowrie ttylog shasum is input-only; compare SHA256 only for sample files.
            matches = ((file["sha256"] == expected) if (file and expected and not is_tty) else None)
            evidence = {
                "kind": "tty_recording" if is_tty else "quarantined_file",
                "artifact": file,
                "verification": ("source_checksum_mismatch" if matches is False else
                                 "source_size_mismatch" if size_matches is False else
                                 "locally_hashed" if file else "unavailable"),
                "cowrie_reported_input_sha256": expected if is_tty else None,
                "file_hash_verified_against_source": matches,
            }
    elif source == "opencanary":
        port = raw.get("dst_port")
        if type(port) is not int or port not in OPEN_PORTS or type(raw.get("logtype")) is not int:
            return None
        proto = OPEN_PORTS[port]
        kind = "service_probe"
        # OpenCanary may emit local-time strings without offsets. Missing UTC
        # provenance is left unset, not reconstructed from collector time.
        when = normalized_time(raw.get("utc_time") or raw.get("timestamp"))
        session = None
        pseudonym = network_ref(raw.get("src_host"), key, when)
        category = None
    else:
        return None
    record = {
        "event_ref": str(uuid.uuid5(NS, source+"|"+str(line_no)+"|"+
                                   hashlib.sha256(json.dumps(
                                       raw, sort_keys=True, default=str,
                                       separators=(",", ":")).encode()).hexdigest())),
        "source": source,
        "protocol": proto,
        "event_class": kind,
        "observed_at": when,
        "session_ref": session,
        "network_daily_ref": pseudonym,
        "command_category": category,
        "verified_intrusion": False,
        "indicator_status": "observation_only",
        "share_authorized": False,
        "evidence": evidence,
    }
    return record


def _scan(input_path, source, key, tty_dir, download_dir, max_lines):
    if not input_path.is_file() or input_path.is_symlink():
        raise EvidenceError("source must be a regular local evidence log")
    records, counts = [], Counter()
    digest = hashlib.sha256()
    rejected = 0
    with input_path.open("rb") as stream:
        for i, line in enumerate(stream, start=1):
            if i > max_lines:
                raise EvidenceError("source exceeds the authorized event limit")
            digest.update(line)
            if len(line) > MAX_LINE:
                rejected += 1
                continue
            try:
                data = json.loads(line)
                item = _canonical_event(data, source, key, i, tty_dir, download_dir)
            except (UnicodeError, TypeError, ValueError, OverflowError):
                item = None
            if item is None:
                rejected += 1
                continue
            records.append(item)
            counts[item["event_class"]] += 1
    if not records:
        raise EvidenceError("no authentic supported sensor events")
    return records, digest.hexdigest(), dict(sorted(counts.items())), rejected


def capture(input_path: Path, output: Path, source: str, key: str,
            tty_dir=None, download_dir=None, max_lines=10000):
    if source not in {"cowrie", "opencanary"}:
        raise EvidenceError("unsupported source")
    if not isinstance(key, str) or len(key) < 32:
        raise EvidenceError("protected evidence HMAC key required (32+ chars)")
    if not 1 <= max_lines <= 10000:
        raise EvidenceError("event limit must be between 1 and 10000")
    if input_path.resolve() == output.resolve() or output.exists() or output.is_symlink():
        raise EvidenceError("refusing to overwrite a file or evidence source")
    secret = key.encode("utf-8")
    records, origin_hash, counts, rejected = _scan(
        input_path, source, secret, tty_dir, download_dir, max_lines)
    # Chained hashes cover the sanitized event sequence. The HMAC protects the
    # resulting manifest from undetected edits if the secret is held separately.
    last_hash = "0" * 64
    for item in records:
        body = json.dumps(item, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        last_hash = hashlib.sha256(bytes.fromhex(last_hash)+body).hexdigest()
        item["chain_sha256"] = last_hash
    doc = {
        "schema": SCHEMA,
        "source": source,
        "raw_source_sha256": origin_hash,
        "source_event_count": len(records),
        "rejected_source_rows": rejected,
        "counts_by_class": counts,
        "last_chain_sha256": last_hash,
        "provenance": "local_sensor_jsonl_not_external_attack_attribution",
        "sharing_allowed": False,
        "raw_evidence_retained_separately": True,
        "records": records,
    }
    content = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")
    doc["manifest_hmac_sha256"] = hmac.new(secret, content, hashlib.sha256).hexdigest()
    body = (json.dumps(doc, indent=2, sort_keys=True)+"\n").encode("utf-8")
    if len(body) > 16 * 1024 * 1024:
        raise EvidenceError("manifest size cap exceeded")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(body)
    return {"source": source, "accepted": len(records), "rejected": rejected,
            "counts_by_class": counts, "last_chain_sha256": last_hash,
            "metadata_only": True, "uploaded": False,
            "sample_executed": False, "public_indicators": 0}


def verify_manifest(path: Path, key: str):
    if not isinstance(key, str) or len(key) < 32 or not path.is_file() or path.is_symlink():
        raise EvidenceError("protected HMAC key and regular manifest required")
    if path.stat().st_size > 16*1024*1024:
        raise EvidenceError("manifest too large")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise EvidenceError("manifest schema mismatch")
    signature = data.pop("manifest_hmac_sha256", None)
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key.encode(), canonical, hashlib.sha256).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
        raise EvidenceError("evidence manifest HMAC verification failed")
    chain = "0" * 64
    for row in data["records"]:
        saved = row["chain_sha256"]
        item = {k:v for k,v in row.items() if k!="chain_sha256"}
        body = json.dumps(item, sort_keys=True, separators=(",", ":")).encode()
        chain = hashlib.sha256(bytes.fromhex(chain)+body).hexdigest()
        if saved != chain:
            raise EvidenceError("event-chain verification failed")
    if chain != data["last_chain_sha256"]:
        raise EvidenceError("event-chain terminator mismatch")
    return {"verified": True, "events": len(data["records"]), "no_network": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("cowrie", "opencanary"), required=True)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tty-dir", type=Path)
    parser.add_argument("--download-dir", type=Path)
    parser.add_argument("--max-lines", type=int, default=10000)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    key = os.environ.get("VYNALTH_EVIDENCE_HMAC_KEY", "")
    try:
        if args.verify:
            result = verify_manifest(args.input, key)
        else:
            result = capture(args.input, args.output, args.source, key,
                             args.tty_dir, args.download_dir, args.max_lines)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError):
        print("EVIDENCE_BLOCKED: invalid or unsafe evidence input", file=sys.stderr)
        raise SystemExit(2)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
