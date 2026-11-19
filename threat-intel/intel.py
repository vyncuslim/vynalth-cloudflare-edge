#!/usr/bin/env python3
"""Vynalth Threat Intelligence Schema v1 — offline, fail-closed export.

Standard library only. Does NOT connect to TiDB, Cloudflare, MISP or TAXII.
The local JSON approval is a human workflow assertion, NOT cryptographic
identity proof. The destination organization must authenticate approvals
before sending files; this CLI only writes restricted local JSON.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import ipaddress
import json
import os
from pathlib import Path
import re
import sys
import uuid

VERSION = "vynalth-ti-v1"
NS = uuid.UUID("7172259e-5d6f-4372-b806-f5ca6f951a25")
ALLOWED_TLP = {"TLP:CLEAR", "TLP:GREEN", "TLP:AMBER",
               "TLP:AMBER+STRICT", "TLP:RED"}
STIX_TLP_MARKING = {
    # Standard STIX 2.1 TLP IDs. TLP:CLEAR is a TLP 2.0 extension ID.
    "TLP:CLEAR": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "TLP:GREEN": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "TLP:AMBER": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
}
INDICATOR_FIELDS = {
    "indicator_id", "indicator_type", "value", "review_status",
    "false_positive_status", "confidence", "first_seen", "last_seen",
    "valid_until", "reviewed_at", "reviewer_id", "evidence_sha256",
    "source_event_ids", "tlp", "share_authorized",
    "public_ip_release_approved",
}
APPROVAL_FIELDS = {
    "approval_id", "recipient_id", "purpose", "export_format", "tlp",
    "indicator_ids", "approved", "approved_by", "approved_at", "expires_at",
    "public_ip_release_approved", "second_reviewer_id",
}
PROTOCOLS = {"SSH", "TELNET", "HTTP", "FTP", "MYSQL", "REDIS"}
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class ReviewError(ValueError):
    """An indicator/approval was not eligible to share. Don't leak its value."""


def reject(message: str):
    raise ReviewError(message)


def read_json(path: Path, limit: int = 1048576):
    if not path.is_file() or path.is_symlink():
        reject("input file must be a normal local file")
    if path.stat().st_size > limit:
        reject("input exceeds the one-megabyte cap")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        reject("invalid JSON input")


def utc(value):
    if not isinstance(value, str) or len(value) > 40:
        reject("timestamps must be UTC ISO 8601 strings")
    if not value.endswith("Z"):
        reject("timestamp must have a trailing Z (UTC)")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        reject("invalid timestamp")
    if parsed.tzinfo is None:
        reject("timestamp requires a timezone")
    return parsed.astimezone(timezone.utc)


def stix_time(value):
    timestamp = utc(value)
    return timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def canonical_uuid(value, field):
    try:
        normalized = str(uuid.UUID(value))
    except (ValueError, AttributeError, TypeError):
        reject(field + " must be a UUID")
    if value != normalized:
        reject(field + " must be canonical lowercase UUID")
    return normalized


def valid_indicator_value(kind, value):
    if not isinstance(value, str) or not value or len(value) > 255:
        reject("invalid indicator value")
    if kind in {"ipv4", "ipv6"}:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            reject("IP indicator is malformed")
        if address.version != (4 if kind == "ipv4" else 6):
            reject("wrong IP indicator address family")
        if not address.is_global:
            reject("private, reserved or documentation IP is not exportable")
        if str(address) != value:
            reject("IP indicator must use canonical address spelling")
        return value
    if kind == "domain":
        domain = value.lower().rstrip(".")
        if domain != value or len(domain) > 253:
            reject("domain must be lowercase without a trailing dot")
        labels = domain.split(".")
        if len(labels) < 2 or not all(DOMAIN_LABEL.fullmatch(l) for l in labels):
            reject("domain contains unsafe characters")
        if labels[-1].isdigit():
            reject("numeric-only top-level domain not accepted")
        return domain
    if kind == "sha256":
        if not HEX64.fullmatch(value) or value != value.lower():
            reject("sha256 must be 64 lowercase hex characters")
        return value
    reject("unsupported indicator type")


def eligible(indicator, now):
    if not isinstance(indicator, dict) or set(indicator) != INDICATOR_FIELDS:
        reject("indicator schema mismatch")
    canonical_uuid(indicator["indicator_id"], "indicator_id")
    if indicator["review_status"] != "approved":
        reject("indicator has not been approved")
    if indicator["false_positive_status"] != "cleared":
        reject("false positive review not cleared")
    if indicator["share_authorized"] is not True:
        reject("indicator was not approved for sharing")
    confidence = indicator["confidence"]
    if type(confidence) is not int or not 70 <= confidence <= 100:
        reject("confidence needs a reviewed score between 70 and 100")
    value = valid_indicator_value(indicator["indicator_type"], indicator["value"])
    if indicator["tlp"] not in ALLOWED_TLP:
        reject("unsupported TLP label")
    reviewer = indicator["reviewer_id"]
    if not isinstance(reviewer, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,80}", reviewer):
        reject("reviewer_id must be an internal identifier")
    if not isinstance(indicator["source_event_ids"], list) or not 1 <= len(indicator["source_event_ids"]) <= 30:
        reject("indicator needs source observation IDs")
    for source_id in indicator["source_event_ids"]:
        canonical_uuid(source_id, "source_event_id")
    if len(set(indicator["source_event_ids"])) != len(indicator["source_event_ids"]):
        reject("duplicate source event IDs")
    if not isinstance(indicator["evidence_sha256"], list) or not 1 <= len(indicator["evidence_sha256"]) <= 20:
        reject("indicator needs reviewed evidence digests")
    if any(not isinstance(d, str) or not HEX64.fullmatch(d) for d in indicator["evidence_sha256"]):
        reject("invalid evidence digest")
    first, last = utc(indicator["first_seen"]), utc(indicator["last_seen"])
    expiry, review = utc(indicator["valid_until"]), utc(indicator["reviewed_at"])
    if not first <= last <= review <= now or not review < expiry or not now < expiry:
        reject("observation, review, or expiry timeline is invalid")
    if not isinstance(indicator["public_ip_release_approved"], bool):
        reject("public IP permission must be boolean")
    if indicator["tlp"] in {"TLP:RED", "TLP:AMBER+STRICT"}:
        reject("TLP red and amber+strict require a separate restricted delivery process")
    return value


def validate_approval(approval, fmt, ids, now):
    if not isinstance(approval, dict) or set(approval) != APPROVAL_FIELDS:
        reject("approval schema mismatch")
    canonical_uuid(approval["approval_id"], "approval_id")
    if approval["approved"] is not True or approval["export_format"] != fmt:
        reject("approval missing or format differs")
    if approval["tlp"] not in ALLOWED_TLP:
        reject("approval TLP is not supported")
    recipients = approval["recipient_id"]
    if not isinstance(recipients, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,120}", recipients):
        reject("recipient_id missing")
    purpose = approval["purpose"]
    if not isinstance(purpose, str) or not 12 <= len(purpose) <= 200 or any(c in purpose for c in "<>\n\r"):
        reject("purpose must be safe and specific")
    reviewer = approval["approved_by"]
    if not isinstance(reviewer, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{3,80}", reviewer):
        reject("approved_by missing")
    if not isinstance(approval["indicator_ids"], list) or sorted(approval["indicator_ids"]) != sorted(ids):
        reject("approval must match the exact indicator ID set")
    if not approval["indicator_ids"]:
        reject("empty approval")
    start, end = utc(approval["approved_at"]), utc(approval["expires_at"])
    if not start <= now < end or (end - start).days > 30:
        reject("approval expired, future-dated, or valid too long")
    if not isinstance(approval["public_ip_release_approved"], bool):
        reject("invalid public-IP approval flag")
    second = approval["second_reviewer_id"]
    if second is not None and (not isinstance(second, str) or
                               not re.fullmatch(r"[a-zA-Z0-9_.-]{3,80}", second)):
        reject("invalid second reviewer")
    if second is not None and second == reviewer:
        reject("second reviewer must be different")
    if approval["tlp"] == "TLP:CLEAR" and approval["recipient_id"] != "public":
        reject("CLEAR exports must explicitly target public audience")


def validated_batch(manifest, approval, fmt, now):
    if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "indicators"}:
        reject("manifest format mismatch")
    if manifest["schema_version"] != VERSION:
        reject("unsupported schema version")
    rows = manifest["indicators"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= 100:
        reject("expected 1..100 indicators")
    values = [eligible(x, now) for x in rows]
    ids = [x["indicator_id"] for x in rows]
    if len(set(ids)) != len(ids):
        reject("duplicate indicator IDs")
    validate_approval(approval, fmt, ids, now)
    for item in rows:
        if item["tlp"] != approval["tlp"]:
            reject("TLP mismatch or attempted downgrade")
        if item["indicator_type"] in {"ipv4", "ipv6"} and approval["tlp"] == "TLP:CLEAR":
            if (not item["public_ip_release_approved"] or
                not approval["public_ip_release_approved"] or
                not approval["second_reviewer_id"]):
                reject("public IP indicators require explicit dual review")
        if item["reviewer_id"] == approval["approved_by"]:
            reject("independent export approver required")
    return list(zip(rows, values))


def object_id(kind, seed):
    return kind + "--" + str(uuid.uuid5(NS, kind + "|" + seed))


def stix_pattern(kind, value):
    # Values have already passed strict format validation and cannot inject quotes.
    return {"ipv4": "[ipv4-addr:value = '" + value + "']",
            "ipv6": "[ipv6-addr:value = '" + value + "']",
            "domain": "[domain-name:value = '" + value + "']",
            "sha256": "[file:hashes.'SHA-256' = '" + value + "']"}[kind]


def export_stix(items, approval, now):
    tlp = approval["tlp"]
    marking = STIX_TLP_MARKING.get(tlp)
    if not marking:
        reject("STIX export does not support this marking without an extension")
    objects = []
    for row, value in items:
        created = stix_time(row["reviewed_at"])
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": object_id("indicator", row["indicator_id"]),
            "created": created,
            "modified": created,
            "name": "Vynalth reviewed " + row["indicator_type"] + " indicator",
            "description": "Evidence-backed candidate promoted by independent analyst review; not a verified intrusion.",
            "indicator_types": ["malicious-activity"],
            "pattern": stix_pattern(row["indicator_type"], value),
            "pattern_type": "stix",
            "valid_from": created,
            "valid_until": stix_time(row["valid_until"]),
            "confidence": row["confidence"],
            "object_marking_refs": [marking],
        })
    return {"type": "bundle", "id": object_id("bundle", approval["approval_id"]),
            "objects": objects}


def export_misp(items, approval, now):
    typemap = {"ipv4": "ip-src", "ipv6": "ip-src",
               "domain": "domain", "sha256": "sha256"}
    attributes = []
    for row, value in items:
        attributes.append({
            "uuid": row["indicator_id"],
            "type": typemap[row["indicator_type"]],
            "category": "Payload delivery" if row["indicator_type"] == "sha256"
                        else "Network activity",
            "value": value,
            "distribution": "0",
            "to_ids": True,
            "comment": "Analyst-reviewed; observe additional evidence before blocking.",
            "Tag": [{"name": approval["tlp"].lower()}],
        })
    # Import draft only. Even CLEAR data stays organization-only and unpublished.
    return {"Event": {
        "uuid": approval["approval_id"],
        "date": now.date().isoformat(),
        "info": "Vynalth AI curated honeypot indicators - manual review required",
        "distribution": "0",
        "threat_level_id": "4",
        "analysis": "2",
        "published": False,
        "Tag": [{"name": approval["tlp"].lower()}],
        "Attribute": attributes,
    }}


def export_to_file(manifest_path, approval_path, output, fmt, now=None):
    now = now or datetime.now(timezone.utc)
    manifest = read_json(manifest_path)
    approval = read_json(approval_path)
    items = validated_batch(manifest, approval, fmt, now)
    result = export_stix(items, approval, now) if fmt == "stix" else export_misp(items, approval, now)
    data = (json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    if len(data) > 1048576:
        reject("export exceeds the one-megabyte cap")
    if output.exists() or output.is_symlink():
        reject("refusing to overwrite an existing export")
    if output.parent.resolve() in {Path("/"), Path("/tmp")}:
        reject("use a protected dedicated export directory, not a shared root")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(data)
    return {"exported": len(items), "format": fmt,
            "payload_sha256": sha256(data).hexdigest(),
            "recipient_id": approval["recipient_id"],
            "tlp": approval["tlp"],
            "delivery": "manual_only", "uploaded": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--approval", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--format", choices=("stix", "misp"), required=True)
    args = p.parse_args()
    try:
        answer = export_to_file(args.manifest, args.approval, args.output, args.format)
    except (ReviewError, OSError) as error:
        print("EXPORT_BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(2)
    print(json.dumps(answer, sort_keys=True))


if __name__ == "__main__":
    main()
