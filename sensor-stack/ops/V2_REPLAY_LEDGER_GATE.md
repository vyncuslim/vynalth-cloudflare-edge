# Vynalth AI Honeypot Sensor Intake V2 — Replay Ledger Safety Gate

**Status: CODE REVIEW ONLY. Production disabled. Not merged or deployed.**

## Why V2 exists

V1 signed sensor intake supports HMAC and a 90-second timestamp window,
but a valid request can be replayed during that window or resigned with a
new nonce. The existing TiDB honeypot_events table has no dedicated
sensor event_ref uniqueness constraint.

V2 uses the independent path
  /__vynalth/honeypot/sensors/v2

V1 is left intact and disabled. V2 has separate, always-off-by-default
HONEY_SENSOR_V2_ENABLED=false, a 10% HONEY_SENSOR_V2_SAMPLE_RATE and
an independent secret HONEY_SENSOR_V2_KEY (32+ characters, NEVER in GitHub).

## Stronger signed envelope

A trusted host-side sender signs the exact UTF-8 payload with:
- Constant domain separator vynalth-sensor-v2
- UTC Unix timestamp (10 digits; +/-90 seconds)
- Fresh RFC 4122 version-4 nonce
- HMAC-keyed lowercase 64-character event reference from private spool
- Exact restricted seven-field JSON body, excluding source IPs, credentials,
  usernames, command strings, files, malicious samples and TTY bytes

A changed ref or changed body invalidates HMAC. V2 does not accept V1
signatures and never downgrades to V1.

## Durable deduplication

After authentication, schema validation and rate validation, but BEFORE
random 10% sampling or any TiDB connection:
- Compute one deterministic of 16 private SQLite Durable Object partitions
  from the event reference's first hex nibble. Same ref always maps to same
  partition, across new nonces and dates.
- A unique SQLite INSERT OR IGNORE durably reserves the reference.
- Existing ref -> 409 duplicate_held, never another TiDB INSERT.
- Missing ledger binding, full quota, or database failure -> 503 fail-closed.
- New claim -> sample once. A 202 means sampled_out and no DB insert.
- Successful TiDB serverless INSERT -> settle to insert_acknowledged, then
  respond 201. A 201 still needs independent SQL SELECT confirmation.
- DB failure / ack uncertainty -> claim stays reserved or
  database_uncertain and is not automatically resent.

Each partition retains up to 20,000 keyed references, with NO automatic
deletion or expiry. When a partition reaches its cap, no new claim is
accepted. This protects storage billing but halts collection; it is not a
permanent high-scale event store or an indefinite uptime guarantee.
A retention/archive and operator-approved migration strategy is still
required before 24/7 operations.

## Critical limitation: NOT exactly-once delivery

SQLite DO and TiDB do NOT share a distributed transaction. This gate
establishes at-most-once TiDB *attempt* for a given valid event reference,
not a guarantee that the attempt succeeded. If a Worker crashes after
reserving the event but before TiDB commits it, that record may be lost
until manual reconciliation. Conversely, if TiDB commits and the Worker
does not receive an ACK, the claim still prevents a blind replay.

Do not claim 100% telemetry capture, continuous internet collection, a
durable end-to-end deduplication proof, legal attribution, or production
SQL acceptance. There is no authorized public sensor or production
TiDB protocol-sensor row yet.

## Zero-cost release prerequisites

1. Verify actual Cloudflare Workers Free Durable Object read/write/storage
   usage and quotas. As of 2026 Cloudflare supports new SQLite DO
   namespaces on Workers Free but usage beyond quotas may fail.
   Never upgrade the plan or incur any charges without explicit owner OK.
2. Review the new Wrangler SQLite namespace migration
   SensorReplayLedger. It may create a new namespace during deployment.
   The branch changes main only to the Wrapper entrypoint, which re-exports
   the existing default Worker and the new DO class separately.
   Original routes, school rules, cookies, WAF and devices are unchanged.
3. Confirm independent host-side sender (NOT public Cowrie container) has
   private HONEY_SENSOR_V2_KEY. Uploading requires explicit --send.
4. Confirm HONEY_SENSOR_V2_ENABLED remains false until a separate,
   explicitly authorized single production deployment.
5. Check sensor host is isolated, no egress pivot, quotas/archival agreed,
   no raw logs/credential material in Internet-visible containers.
6. Test one controlled safe event with an owner-controlled identity, watch
   fixed Worker response, then inspect TiDB by SELECT for NEW source='cowrie'
   or source='opencanary'. No test loops to defeat 10% sampling.
7. Check duplicate re-signed HMAC ref rejected and its ledger claim survives
   DO restart in a disposable or authorized staging environment.
8. Confirm non-delivery handling, rate limits, database outages and pause
   procedure before public SSH/Telnet ports become reachable.

## Evidence from CI

- Python HMAC signature for event_ref passes validation in the actual
  Worker V2 function; TiDB calls are mocked.
- Existing SSH/Telnet/FTP/MySQL/Redis and Cowrie fake-shell/TTY events are
  verified on a disposable, private GitHub runner, NOT the public internet.
- Node tests cover duplicate refs, sample-once, 503 hold, forged events,
  parallel requests and capacity fail-closed.
- Wrangler dry run checks the DO class export and migration syntax.
- A Cloudflare Durable Object SQLite persistent restart test in the *actual*
  Cloudflare runtime and any production INSERT/SELECT have not yet been done.
- No cloud account resources have been created by CI.

## Official Cloudflare references

https://developers.cloudflare.com/durable-objects/platform/pricing/
https://developers.cloudflare.com/durable-objects/api/sqlite-storage-api/
https://developers.cloudflare.com/workers/wrangler/configuration/
