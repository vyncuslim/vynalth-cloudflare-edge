# Vynalth Honeypot — Isolated Sensor to TiDB Release Gate

**STATUS: REVIEW-ONLY.** Nothing in this PR launches a public sensor,
installs a service, deploys Cloudflare, creates a TiDB table or shares data.
The secure uplink is staged and **must not be enabled on production yet**.

## Architecture

  Internet (only after isolation approval)
    -> dedicated decoy ingress gateway
    -> Cowrie SSH/Telnet + OpenCanary FTP/MySQL/Redis (no egress/credentials)
    -> restricted, operator-managed raw JSONL and TTY evidence
    -> unprivileged, network-DENIED local rotation_collector.py
    -> private SQLite WAL with HMAC-signed sanitized events/checkpoints
    -> separately trusted, approved HTTPS-only spool_uplink.py --send
    -> existing Cloudflare Worker signed sensor API (currently OFF)
    -> sampled, INSERT-only TiDB honeypot_events rows
    -> independent read-only TiDB SQL confirmation

No raw IPs, passwords, usernames, shell commands, TTY tapes or binaries
are ever uploaded. This release maps only the fixed seven allowlisted
fields and sets source_ip_hash to null regardless of local daily pseudonym.

## The sender does not auto-repeat uncertain requests

The Worker currently has **no durable atomic per-event deduplication**.
Its 90-second HMAC time window is not an exactly-once or idempotency
guarantee. Enabling unlimited retries would create duplicate events.

The sender therefore reserves a local event BEFORE any HTTPS request:
- HTTP 201: insert_acknowledged; still requires independent SQL readback
- HTTP 202: sampled_out; the event did not enter TiDB
- Other HTTP codes: needs_review; no automatic retry
- Timeout/interruption or a crash after reservation: uncertain/reserved;
  never automatically retry, because the first INSERT may have succeeded

The local outbox HMAC is verified, can be inspected read-only, and blocks
all subsequent sends when an unresolved reservation is encountered.
There is currently no safe automated operator override for uncertain
events. Add a durable idempotency key and transactional server-side
deduplication (with separately approved schema or equivalent atomic store)
BEFORE routine 24/7 production forwarding.

Current Worker settings in GitHub:
- HONEY_SENSOR_INGEST_ENABLED = false
- HONEY_SENSOR_SAMPLE_RATE = 0.1

Do not infer Cloudflare runtime secrets or TiDB row creation from GitHub
configuration. The operator has previously shown TiDB SELECT queries
returning an empty set for cloudflare_worker/cowrie/opencanary.
There is still no newly verified real TiDB protocol sensor row.

## Independent staged test

The Python fixture writes to a temporary PRIVATE local SQLite spool,
reserves a sanitized Cowrie event and signs it using a TEST-ONLY HMAC key.
The JavaScript test imports the actual Cloudflare handleSensorIngest function
and verifies the signature, exact seven SQL values, accepted 201 response,
sampled-out 202 response, forged payload rejection and endpoint-off 404.
All TiDB calls are MOCKED, no actual POST is sent and no secrets are used.

  python sensor-stack/ci_signed_uplink_probe.py /tmp/ci-outbox.json
  VYNALTH_OUTBOX_CI_FIXTURE=/tmp/ci-outbox.json node --test src/sensor-outbox-crosslang.test.js

The GitHub Actions workflow destroys this fixture after testing.
This proves compatibility only; it is not production acceptance.

## Local operator-only validation

On a separately reviewed trusted host, with the dedicated evidence HMAC
key securely provisioned outside GitHub:

  python sensor-stack/spool_uplink.py --db /restricted/private/cowrie.db

This default mode is READ-ONLY and makes ZERO network requests.

A real send must NOT be enabled without (a) isolated host/network proof;
(b) separate scoped HONEY_SENSOR_INGEST_KEY on trusted uploader only,
not inside Cowrie/OpenCanary; (c) private TLS egress and no redirects;
(d) Worker intake binding/secret and TiDB least-privileged writer verified;
(e) no ambiguous reservations and a reviewed server replay strategy;
(f) an operator-approved one-event acceptance window and RM0 costs.

When separately authorized, --send performs a bounded, one-shot dispatch.
The CLI does not auto-retry and does not run as an active systemd timer.

## Continuous health and retention controls

The offline delivery_monitor.py combines signed collector heartbeat with
outbox status. It creates a signed, private, fixed-field local status and
returns a nonzero exit for stale heartbeat, queue backlog, uncertain uploads,
missing spool, tampering or low disk. No Telegram/API/webhook notification
is configured. In this project Telegram has previously returned HTTP 429;
do not bypass the service's rate limit or assume alerts were delivered.
A staged vynalth-honeypot-delivery-health@.timer checks every ~90 seconds
but is NOT installed on any host.

The retention_audit.py tool hashes every retained numeric/date JSONL
archive and verifies whether its *current file bytes* have been acknowledged
in the local SQLite collector checkpoint. It signs a private manifest and
NEVER deletes, compresses, moves or uploads evidence. A processed archive
is not automatically authorized for deletion. No legal retention period is
assumed. Source backups and independent immutable timestamp/witnessing
still need a verified infrastructure provider and approved retention policy.

## Production acceptance requirements (not yet met)

1. A dedicated, explicitly authorized, **independent** public sensor host,
   not the existing VPN/Voice systems, with ingress and outbound-pivot
   controls independently verified. No quota or payment assumptions.
2. Image provenance, least privilege, storage limits, service account,
   archive rotation, TTY retention, hard restart and incident stop tested.
3. A trusted host-only forwarder receives properly mounted restricted logs;
   sensor containers have no cloud/DB/network credentials.
4. Actual HONEY_SENSOR_INGEST_ENABLED and secret bindings verified in
   Cloudflare after a single separately approved release; rate remains 10%.
5. A durable atomically enforced replay strategy to address the current
   uncertain-delivery and duplicate event risk.
6. One harmless controlled session reaches the Worker and produces a
   **NEW** row in the real TiDB honeypot_events table. 201/202 alone
   cannot establish this; a SELECT with source='cowrie' is required.
7. Operational uptime, retention, capacity, credential rotation and alerts
   are externally validated; no sharing of indicators until reviewer
   approval and applicable TLP/partner terms.

No additional Oracle, Vercel or Cloudflare production work was performed
in this PR. All cloud tests run on disposable GitHub-hosted runners.
