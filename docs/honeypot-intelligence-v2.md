# Vynalth AI Honeypot v2: richer metadata, RM0 safety

## Status / current evidence

The existing TiDB database and table were created and the owner verified
an INSERT/SELECT via SQL Editor, but only a `local_test` row was present
after one HTTP decoy visit. Therefore **real Worker -> TiDB delivery was not
verified**. Under the existing 10% sampling, one missed visit is inconclusive.
Do not call this a real-time global attack feed before live observations arrive.

The existing PR #95 was merged and Cloudflare Workers Builds reported success.
This optional v2 change is separately gated. It never changes Vercel or TiDB
billing. The user already set the TiDB Starter monthly spending limit to $0.

## Extra fields (opt-in, no raw personal details)

| Column | Meaning |
|---|---|
| event_id | random request-scoped ID; not visitor identity |
| target_host | hostname the Worker actually handled |
| http_method | validated HTTP method |
| http_status | decoy HTTP response status |
| trap_kind | static allowlisted lure category |
| network_asn | ASN from Cloudflare metadata **only** for edge-observed client attribution |
| edge_colo | three-letter Cloudflare data center code |
| bot_score | integer 1–99 when Cloudflare Bot Management exposes the score; otherwise NULL |
| verified_bot | Cloudflare's verified bot field, if available; otherwise NULL |
| ip_attribution | provenance indicator; distinguish Cloudflare cross-zone proxy |
| bot_claim | coarse user-agent bot **claim**, never independent verification |
| sample_rate | sampling fraction used at event creation (normally 0.1000) |

Original fields remain: `event_type`, `source`, `protocol`,
`source_ip_hash` (daily pseudonym), `country_code`, `request_path`,
`action_taken`, `observed_at`.

Never store request bodies, submitted credentials, authorization headers,
query strings, full URLs, raw IP addresses, raw user-agent strings, fingerprint
vectors, or unverified bot identity.

## Release gates

1. Keep `TIDB_HONEYPOT_ENRICHED_ENABLED = "false"` (default).
2. Confirm true Worker ingestion on the current v1 table. If the DB is still
   showing only `local_test`, inspect production Cloudflare Worker logs for
   `[TIDB HONEYPOT] insert failed`. There is no evidence of success yet.
   Check the Secret *name*, URL formatting, Writer grants and Worker routing
   without exposing credential values or creating an unnecessary deployment.
3. Review and manually run `docs/sql/honeypot-events-v2.sql` with the
   database owner account in TiDB SQL Editor. This adds nullable columns;
   no deletes, no table recreation, no changes to existing grants.
4. Verify `SHOW COLUMNS` and the instance's USD $0 monthly spending cap.
5. Only after tests and operator approval, enable `TIDB_HONEYPOT_ENRICHED_ENABLED`
   via **one** planned Cloudflare release. Do NOT pre-enable the flag here.
6. Verify an enriched, newly written row; older v1 rows legitimately have
   NULL v2 metadata.

The sink continues to use parameterized SQL, only INSERT privileges and
best-effort `ctx.waitUntil` so DB failures do not break user HTTP responses.

## Example analytics queries (owner only)

```sql
-- Total captured observations by trap; not total attacks:
SELECT trap_kind, COUNT(*) AS captured
FROM vynalth_honeypot.honeypot_events
WHERE source='cloudflare_worker'
GROUP BY trap_kind ORDER BY captured DESC LIMIT 20;

-- Geographical distribution (missing attribution remains NULL):
SELECT country_code, COUNT(*) AS captured
FROM vynalth_honeypot.honeypot_events
WHERE source='cloudflare_worker'
GROUP BY country_code ORDER BY captured DESC LIMIT 30;

-- A daily series of *sampled* requests, not a population estimate:
SELECT DATE(observed_at) AS day, COUNT(*) AS captured
FROM vynalth_honeypot.honeypot_events
WHERE source='cloudflare_worker'
GROUP BY DATE(observed_at) ORDER BY day DESC LIMIT 30;
```

## Privacy and quota rules

- Retention: no automatic deletion is introduced by this migration.
  Define and approve a retention policy separately before enabling TiDB TTL.
- Sampling defaults to 10%; it is **not** a hard quota ceiling and does not
  guarantee complete coverage. Cloudflare WAF blocks do not reach this Worker.
- `source_ip_hash` is pseudonymous, **not anonymous**: protect access.
- IP/ASN/country data is at best network metadata and may describe a NAT, VPN
  or proxy, not a person's verified location.
- Bot scores are unavailable on some Cloudflare plans; NULL is correct.
- Do not publish individual network hashes in public dashboards.
- Do not call HTTP scanning an authenticated intrusion.
