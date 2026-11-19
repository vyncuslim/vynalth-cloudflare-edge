# Honeypot Durable Object V2 — Actual Local Runtime Acceptance

**Release state: STAGING CODE ONLY.** This acceptance is performed in
Wrangler's local Miniflare/workerd runtime on a disposable GitHub runner.
It is NOT the Cloudflare-hosted multi-region service, NOT a production
deployment, and NOT proof of a real TiDB INSERT.

## What this new test actually exercises

- Runs the actual `SensorReplayLedger` class from
  `src/sensor-replay-ledger.js`, backed by actual SQLite through
  Cloudflare's local workerd/Miniflare runtime.
- Starts an isolated, loopback-only Wrangler development Worker using
  `sensor-stack/ci/do-runtime-wrangler.toml`. The Worker exports the
  ledger class and forwards only fixed synthetic /claim and /settle calls.
  No production Worker routing, database URL, token, IP, attacker payload
  or HTTPS sensor uplink is in this test configuration.
- Four distinct deterministic DO shard names: reserve, duplicate reject,
  settle, reserved-without-settling; 20 concurrent same-ref attempts must
  produce exactly one claim and nineteen duplicates.
- Terminate the COMPLETE Wrangler process group; restart a clean workerd
  process using the SAME `--persist-to` directory; verify the old claims
  and settlements survive, while a new reference is still accepted.
- Treat any failure as **NO-GO**. The local state is removed automatically
  from the disposable runner and must never be committed to GitHub.

Run in a separate, trusted, disposable environment:

    npm install --ignore-scripts --no-audit --no-fund
    python3 sensor-stack/ci/do_runtime_acceptance.py

The GitHub workflow named `Verify real local Cloudflare SQLite Durable
Object persistence` performs this test without remote credentials.

### Interpret outcomes accurately

- PASS: local workerd + SQLite DO initialization, concurrency, crash/restart
  persistence and idempotent stable event reference behavior were proven.
- NOT PROVEN: same behavior after real Cloudflare-hosted DO eviction,
  deployment migration, cross-region failover, Cloudflare billing counters,
  actual sensor SSH/Telnet traffic from the public internet, or any genuine
  TiDB insert/readback. These require an independently approved staging
  release and operator-controlled, nonpublic test credentials.

## Verified public Free-tier figures (2026-11-19 documentation)

Cloudflare's published Workers Free Durable Objects allowance:
- SQLite-backed objects only.
- 100,000 DO requests/day; 13,000 GB-s compute duration/day.
- 5,000,000 SQLite rows read/day; 100,000 rows written/day.
- 5 GB total SQLite stored data per account.
- Maximum 100 Durable Object classes/account; additional limits apply.

If a Free resource quota is reached, additional affected operations
**fail**. This is NOT permission to upgrade to a paid plan.
Source: https://developers.cloudflare.com/durable-objects/platform/pricing/
and https://developers.cloudflare.com/durable-objects/platform/limits/

V2 currently performs up to two internal DO calls for a new event
(claim and settlement) and at least one DO call for a duplicate. Its
10% **TiDB sampling does NOT reduce the number of DO claims**.
Even with zero other usage, 50k new events/day would consume at least
100k DO requests/day before overhead; this theoretical limit is NOT a
production SLO and real account headroom is unknown. Keep volume far
below the quotas with an operator-owned budget/alert review.

## Independent public sensor isolation — source configuration inspection

Staged infrastructure files have these static safeguards:
- OCI Terraform `launch_approved=false` and
  `public_decoys_approved=false` by default.
- New isolated VCN and subnet, no references to existing VPN/Voice.
- Public decoy listener binds to 127.0.0.1 by default in Docker Compose;
  sensor-only backend network is `internal:true`.
- Egress DROP-NEW host script is *staged*, not live. OCI network security
  list permits HTTPS/DNS for host bootstrap; **this is not complete sensor
  outbound isolation**. IPv6, metadata service, container bridge escape,
  reverse shell/pivot opportunities and real firewall behavior still require
  observation on a separate, authorized host.
- No private keys, production secrets, known company data, or malware
  samples are used in the local DO test.

**No OCI instance was created, and the Oracle account's free resources and
quotas were NOT checked**. A dedicated public hostname/VM and real egress
tests remain required for a production GO decision.

## TiDB readback — not yet verified

GitHub can verify code contracts and simulated SQL parameters, but it is
NOT an authenticated TiDB SQL Editor session. Without approved production
database read access, claiming real insertion would be incorrect.

Read-only, independently executed SQL after an approved ONE-EVENT test:

    SELECT id, source, protocol, request_path, observed_at
    FROM vynalth_honeypot.honeypot_events
    WHERE source IN ('cowrie', 'opencanary')
    ORDER BY id DESC LIMIT 10;

Never print database passwords or connection URLs. If the query remains
empty, the production write gate remains unverified even if the Worker
returned 201. Preserve `HONEY_SENSOR_V2_ENABLED=false` until a separate
release approval. Preserve 10% sampling and TiDB US$0 spending cap.
Do not repeat tests merely to beat sampling.

## Release decision

Local workerd and SQLite persistence PASS would permit **only the next
independent review phase**, not public deployment. Required later:
hosted Cloudflare staging verification of actual DO identity/persistence,
Worker secrets and plan quotas, immutable evidence retention, isolated
sensor egress blocking, least-privilege TiDB credentials, a single
controlled protocol event with a fresh read-only SQL row and documented
rollback. This PR does not create resources or alter production.
