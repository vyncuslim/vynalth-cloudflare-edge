# Sensor → Cloudflare Worker → TiDB (staged, secure, non-production)

**Do not enable this integration until the existing HTTP Worker → TiDB
connection is proven with a new `source='cloudflare_worker'` row.** At the
time this PR was created, TiDB SQL Editor showed only `local_test`.

## Pipeline

1. A **separate, disposable** host runs Cowrie for SSH/Telnet and
   OpenCanary for FTP/MySQL/Redis, with loopback-only listeners in the lab.
2. Local raw Cowrie/OpenCanary logs may contain attempted credentials;
   protect them with strict host permissions. Real SSH/Telnet session tapes
   stay offline in the Cowrie data volume.
3. Run `event_sanitizer.py` outside the attacker-exposed containers.
   It produces only the existing seven TiDB-compatible columns. An optional
   daily HMAC pseudonym replaces raw IP; absent secret means NULL.
4. A separate trusted collector process reads the sanitized JSONL and
   `send_summaries.py --send` signs each body with a fresh UUIDv4 nonce
   and Unix timestamp.
5. The existing Cloudflare Worker at `vynalthai.com` validates exact
   path, timestamp, HMAC and allowlisted schema, then uses **INSERT-only**
   TiDB account to write into the already-created
   `vynalth_honeypot.honeypot_events` table.

## Secrets (never commit)

- Cloudflare Worker existing: `TIDB_HONEYPOT_DATABASE_URL` (INSERT-only,
  non-root), existing from the previously authorized setup.
- **New secret**: `HONEY_SENSOR_INGEST_KEY`, 32+ truly random bytes encoded as
  a safe string, configured in Cloudflare Worker Secrets and **only** on the
  isolated, trusted collector host (never inside Cowrie/OpenCanary containers).
- Optional collector: `HONEY_SENSOR_NETWORK_HMAC_KEY`, distinct from the
  API signing key, used to derive rotating per-day network hashes.

## Deployment gates

The worker flag `HONEY_SENSOR_INGEST_ENABLED` is deliberately `false`.
Changing it requires an operator-approved **single** Cloudflare release.
`HONEY_SENSOR_SAMPLE_RATE` defaults to `0.1`, so ~10% of authenticated
summaries are stored. A 202 acknowledgement means the event was sampled out,
not stored; 201 means an INSERT was acknowledged.

In a trusted shell (separate from the honeypot container):

```sh
python sensor-stack/send_summaries.py --input sensor-stack/runtime/cowrie.safe.jsonl
# Only after the endpoint is enabled and BOTH secrets are configured:
python sensor-stack/send_summaries.py --input sensor-stack/runtime/cowrie.safe.jsonl --send --max-events 5
```

The command prints only counts, never secrets. It stops on errors and never
automatically retries HTTP 402/429/503, protecting the free-tier budget.

## Important limitations and security verification

- The HMAC verifies the **trusted collector's signing key**, not the identity
  of the alleged attacker or the factual truth of an event.
- The strict 90-second timestamp window reduces stale replay but does NOT
  guarantee exact once-only storage. Durable nonce replay protection requires
  separate storage and careful design before large public deployments.
- A leaked collector signing key could allow fabricated events or free quota
  exhaustion; rotate/revoke it and enforce independent Cloudflare rate limits
  if compromised. Keep key isolated from all honeypot containers.
- No bulk raw credentials, file samples or input commands cross to the Worker.
- Never expose this integration as a public vulnerability reporting API.
- TiDB Starter monthly spending cap remains **US$0**; do not change it. The
  code does not query provider billing, and sampling alone does not enforce
  a global hard usage ceiling.
- Root account connections are explicitly rejected.
- No new Cloudflare zone route is created; this uses an existing Worker route.
- A Cloudflare WAF/policy can still intercept or block the endpoint before the
  Worker sees it. Verify that the intended server-only route is reachable and
  protected before claiming sensor ingestion is Live.

## DB verification SQL (run via owner SQL Editor, never from a public web page)

```sql
SELECT id, source, protocol, request_path, source_ip_hash,
       action_taken, observed_at
FROM vynalth_honeypot.honeypot_events
WHERE source IN ('cloudflare_worker','cowrie','opencanary')
ORDER BY id DESC LIMIT 20;
```

For reliable continuous delivery, add explicit local durable checkpoints,
sensor health monitoring, an independent egress policy, durable replay
protection and hard daily quotas **before** a public release. The current
one-shot sender intentionally requires human invocation in the lab.
