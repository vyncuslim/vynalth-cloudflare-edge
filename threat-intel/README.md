# Vynalth Threat Intelligence Schema v1

Status: WORKING OFFLINE CODE IN A DRAFT PR, NOT PRODUCTION-DEPLOYED.
Nothing here changes production TiDB, Cloudflare, Vercel, DNS or billing.
The last independently reported TiDB row was local_test, not a real Worker event.

## TiDB: six logical tables

The existing honeypot_events table remains unchanged.
The additive migration sql/001_intelligence_v1.sql prepares FIVE new tables:
- honeypot_sessions: protocol sessions, activity totals, optional TTY hash
- evidence_artifacts: SHA-256, isolated storage reference, custody and retention
- threat_indicators: review status, expiry, confidence, TLP, false-positive status
- indicator_sightings: source event linkage, sampling, observation counts
- intelligence_shares: partner, scope, reviewer, TLP and export SHA-256

No plaintext passwords, malicious binaries or raw session tapes are stored
in these new tables. Raw evidence stays in a restricted and isolated system.
The existing honeypot_writer account must retain only INSERT on the ORIGINAL
honeypot_events table. The SQL is NOT applied by CI, GitHub merges or Worker
deploys. Check the actual TiDB Starter monthly US$0 spending cap before a
manual migration; this repository does not verify or change account billing.

## 1. Observation ingestion

PR #98 can produce seven-column, sanitized Cowrie/OpenCanary/Worker JSONL.
The offline parser in normalize.py checks exact fields and known protocol
paths; refuses credentials, commands, raw IP and arbitrary new fields; and
removes daily pseudonymous network hashes from the output.

    python threat-intel/normalize.py --input /secure/safe.jsonl --output /secure/observations.json

The output labels every item observation_only and sharing_allowed=false.
If a trusted event timestamp was not provided, observed_at is NULL, not
guessed from the export time. This is not proof of an intrusion, not a raw
session tape, and not an accurate full population count if sampling is active.

## 2. Human-reviewed indicator manifest

The offline exporter consumes a strict manifest:
schema_version = vynalth-ti-v1; indicators = array of 1..100 curated records.
Each record MUST contain:
- indicator_id, indicator_type (ipv4, ipv6, domain, sha256), value
- first_seen, last_seen, reviewed_at, valid_until, source_event_ids
- evidence_sha256 (one or more verified SHA-256 digests)
- review_status=approved, false_positive_status=cleared, confidence=70..100
- reviewer_id, tlp, share_authorized=true, public_ip_release_approved

No field is silently promoted or inferred from a scanned path.
All IP addresses must be globally routable before export. A real file hash
alone is not proof that the file is malware. Analysts supply and justify
confidence, rather than fabricating a numeric score.

## 3. Independent export approval and HMAC tamper protection

Each offline export needs a separate approval specifying:
approval_id, recipient_id, purpose, export_format, tlp, indicator_ids,
approved=true, approved_by, approved_at, expires_at (at most 30 days),
public_ip_release_approved, second_reviewer_id and HMAC signature.

The export approver must be different from each indicator reviewer.
The signed approval file is protected by environment secret
VYNALTH_TI_APPROVAL_HMAC_KEY (minimum 32 characters); the key MUST NOT be
committed, pasted into ChatGPT, or placed in internet-facing sensors.

After an actual manual human review, sign the separate unsigned approval form:

    python threat-intel/sign_approval.py --input /secure/approval.unsigned.json --output /secure/approval.signed.json --confirm-human-review

The signing tool prevents unintentional use without explicit human review;
HMAC detects tampering but does NOT prove separate humans authenticated.
An actual organizational identity service and immutable audit history must
be added before a fully automated external sharing service goes live.

## 4. Export (completely offline)

    python threat-intel/intel.py --manifest /secure/indicators.json --approval /secure/approval.signed.json --format stix --output /secure/exports/indicators.stix.json

    python threat-intel/intel.py --manifest /secure/indicators.json --approval /secure/approval.signed.json --format misp --output /secure/exports/misp.draft.json

An exported file uses mode 0600 and is never overwritten. CLI reports the
payload SHA-256 digest, count, TLP, intended recipient and uploaded=false.
There are no email, TAXII, MISP API, TiDB or Cloudflare network calls.

STIX 2.1: reviewed Indicator objects with STIX patterns, valid time interval,
confidence and standard TLP marking references. The TLP:CLEAR marking uses a
TLP 2.0 extension reference and requires recipient compatibility review.
Do not confuse raw Observed Data with reviewed malicious Indicators.

MISP: organization-only (distribution 0), unpublished JSON import draft,
TLP tag, reviewed attributes. No MISP event is published.

TLP RED and AMBER+STRICT are blocked from automatic file export pending a
stricter delivery path. Public CLEAR IP releases additionally need explicit
IP approval flags and a second reviewer. TLP mismatch refuses export.

## 5. Source trust and limitations

Raw passwords, full command text, session tapes, device fingerprints and
original IP addresses are never transferred to this offline export pipeline.
Review the lawful basis and recipient permissions for IP/domain indicators.
The system is NOT live threat intel, not an official MyCERT partnership,
not a working TAXII server and not a deployed MISP platform yet.
Any actual transmission must be separately authorized and recorded in
intelligence_shares with recipient, TLP and payload digest.

Reference standards:
OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html
OASIS TAXII 2.1: https://docs.oasis-open.org/cti/taxii/v2.1/os/taxii-v2.1-os.html
FIRST TLP 2.0: https://www.first.org/tlp/
MISP Core: https://misp-standard.org/formats/core/
TiDB SQL: https://docs.pingcap.com/tidbcloud/sql-statement-create-table/
