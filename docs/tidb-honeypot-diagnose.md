# TiDB Worker honeypot: production write verification

**Status: production write NOT proven.** SQL Editor returned `Query OK; empty set` for source IN ('cloudflare_worker','cowrie','opencanary') as reported by the operator on Nov 19, 2026. The prior `local_test` row is not real Worker evidence. The operator reports no known `[TIDB HONEYPOT] insert failed` warning; absence of this warning is inconclusive.

## Diagnosis from current code

- `src/index.js` routes recognized PHP decoys and `/wp-admin/install.php` to `scheduleTidbHoneypotEvent` at the edge.
- GitHub `wrangler.toml` contains `TIDB_HONEYPOT_INGEST_ENABLED="true"`, sampling `0.1`, but **does not prove which version/secret is currently deployed**.
- If the event was sampled out (about 90%), the original code logged nothing.
- If the URL/secret failed validation, the original scheduler returned without logging anything.
- Only actual INSERT exceptions reached `[TIDB HONEYPOT] insert failed`.
- Therefore an empty table plus no error log does not distinguish no hit, no sampling, missing credentials, unavailable DB or disabled production logging.

## Minimal code-only release

This isolated PR changes only `src/tidb-honeypot.js`, its tests, and one optional Wrangler variable. It **does not change the existing HTTP response, static PHP decoys, database schema, Vercel, DNS, OCI or the existing non-root TiDB writer**.

`TIDB_HONEYPOT_DIAGNOSTICS_ENABLED="false"` remains OFF by default, to protect log volume, free allowance and privacy. After release review, an operator may turn it on in the SAME planned Worker production release. Do not create separate previews or repeated production deployments.

When diagnostics is enabled, each allowlisted decoy can produce only a fixed-label line prefixed `[HONEY TIDB OUTCOME]`:

| state | meaning |
|---|---|
| `disabled` | production Worker flag is disabled |
| `no_lifecycle` | missing `ctx.waitUntil` |
| `not_configured` | missing or invalid secret binding/URL |
| `sampled_out` | request reached the Worker but was skipped by 10% sampling |
| `invalid_event` | event couldn't be safely normalized |
| `inserted` | TiDB driver acknowledged INSERT (must still verify SELECT) |
| `failed` | DB error, sanitized fixed category (auth/schema/quota/transport/timeout/other) |

No raw IP address, sensitive header, request URL/query, token, SQL statement, exception content or DB URL is written. Diagnostics can increase console log volume, so turn off again after the one controlled test. Confirm Cloudflare Workers Logs collection is actually enabled and visible: https://developers.cloudflare.com/workers/observability/logs/workers-logs/ .

## After ONE approved deployment

1. Confirm the Cloudflare production Worker is `vynalth-cloudflare-edge`, the secret binding NAME is exactly `TIDB_HONEYPOT_DATABASE_URL`, and the runtime ingestion and diagnostics flags match the reviewed release. Never show the secret value.
2. Keep `TIDB_HONEYPOT_SAMPLE_RATE="0.1"`; no requests to suspicious paths outside the fixed allowlist, no mass traffic.
3. Visit `https://vynalthai.com/admin.php` with one harmless GET, then inspect **Live** Worker Logs for a fixed outcome state (a `sampled_out` is expected 90% of the time). Cloudflare WAF may intercept before this Worker.
4. If the outcome says `not_configured`, inspect the Secret NAME, least-privilege writer username, URL-encoded password syntax and exact cluster host without copying secrets. If `auth`, verify INSERT-only grants and credential rotation via TiDB owner; if `transport`, verify the serverless gateway and TiDB cluster.
5. To conclusively verify a successful write, use the TiDB owner SQL Editor:

```sql
SELECT id, source, protocol, request_path, observed_at
FROM vynalth_honeypot.honeypot_events
WHERE source='cloudflare_worker'
ORDER BY id DESC LIMIT 10;
```

An `inserted` log plus a **new** matching database row is the acceptance criterion. Do NOT count `local_test`, fake sensor events or GitHub mock inserts. If a single test is sampled out, **do not retry in a loop**.

No Oracle quota verification or VM creation is required for this phase. Cloudflare HTTP-only data can be verified before any permanent SSH/Telnet server exists.

## Change management

- **Do not merge this PR merely to trigger an uncontrolled build.**
- One authorized production deployment only, after CI passes and secrets/cost controls are confirmed.
- New diagnostics are off by default until explicitly enabled in that single release.
- No changes to TiDB US$0 monthly cap or Vercel.


## 2026-11-20 production incident: confirmed sampled INSERT failure

Owner-provided runtime evidence on 2026-11-20 at approximately 13:48 MYT:

- A genuine Worker-observed decoy GET reached the PHP honeypot and was logged as `[EDGE HONEYPOT]`.
- `[TIDB HONEYPOT] insert failed` appeared in the actual Worker production log.
- The TiDB owner ran a read-only query for `source='cloudflare_worker'`; it returned no rows.
- `SHOW CREATE TABLE` showed all seven INSERT columns exist with compatible types and defaults.
- The dedicated non-root `honeypot_writer` account has `INSERT` on only `vynalth_honeypot.honeypot_events`; its authentication string is configured. This does **not** prove the Worker secret matches its password.
- The gateway hostname matched the instance, and its public IPv4 allowlist covers the internet. This does **not** prove serverless HTTP execution or correct credentials.
- Cloudflare shows the production secret **binding name** exists, ingestion `true`, 10% sampling, and detailed diagnostics `false`.

This issue remains **unresolved**. Do not guess that password or grant is the cause or represent an empty SQL result as production success. See issue #107.

### Proposed stage-only diagnostics (review branch; not deployed)

If a **separately authorized** time-limited release enables diagnostic output, the existing fixed-label `[HONEY TIDB OUTCOME]` event would include an extra allowlisted `stage` **only when `state=failed`**:

| stage | interpretation |
|---|---|
| `normalization` | Unexpected error while constructing a privacy-safe observation |
| `connect` | `connect({url})` raised an exception synchronously |
| `execute` | Error when calling or awaiting the serverless driver's `execute(INSERT_SQL, params)` |
| `unknown` | Unexpected label, replaced with a safe default |

These labels do not expose exception contents, raw SQL, username, password, URL, IP, headers, or query strings. `stage=execute` **does not identify** whether the problem was credentials, remote network, server rejection, or SQL. The existing fixed `reason` label may help separate those classes but is heuristic, not a verified backend diagnosis.

New code **does not activate diagnostics**, extend the previously expired UTC deadline, or change sampling/SQL. A future production diagnostic requires an explicit approval, a fresh short UTC expiry, confirming all existing production security checks and no auto-created preview builds. No unlimited request loops, automatic credential rotation, new fees or public sensor activation. Finish by verifying a newly inserted TiDB row with a read-only SELECT; an SDK acknowledgment is not enough.
