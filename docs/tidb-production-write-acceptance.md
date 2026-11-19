# Worker→TiDB production write proof — release-gated

**Current result: NOT VERIFIED.** The user's last SQL query contained only a
\`source='local_test'\` row. GitHub CI's mocked INSERT and six disposable
protocol sensor events cannot establish real TiDB production delivery.

## Existing configuration

- Worker: \`vynalth-cloudflare-edge\`
- TiDB Starter database: \`vynalth_honeypot\`
- Existing table: \`honeypot_events\`
- Dedicated database writer: **INSERT on honeypot_events only** (no SELECT)
- \`TIDB_HONEYPOT_INGEST_ENABLED="true"\` in GitHub Wrangler
- \`TIDB_HONEYPOT_SAMPLE_RATE="0.1"\`
- Secret: \`TIDB_HONEYPOT_DATABASE_URL\` in Cloudflare (value MUST remain secret)
- New \`TIDB_HONEYPOT_DIAGNOSTICS_ENABLED="false"\` by default, ready for
  an **owner-approved single controlled release**.

Cloudflare Dashboard variables, deployed Worker code and Wrangler branch
configuration may be different. A GitHub file alone is not proof of runtime
configuration. This repository cannot read secrets or TiDB SQL Editor.

## Safe result telemetry

The allowlisted decoy scheduling and sampled INSERT code emits **one fixed-label,
privacy-safe outcome per eligible decoy** only when the diagnostics flag is
explicitly enabled, without raw error details. Disable after short controlled
verification: recording sampled-out events can increase log volume on active traps.

\`\`\`json
{
  "event": "tidb_honeypot_write_result",
  "state": "inserted",
  "reason": "insert",
  "event_version": "tidb-sampled-result-v1"
}
\`\`\`

Possible states: \`disabled\`, \`no_lifecycle\`, \`sampled_out\`,
\`not_configured\`, \`invalid_event\`, \`inserted\`, \`failed\`. Failure categories: \`schema\`, \`auth\`, \`quota\`,
\`transport\`, \`timeout\`, \`other\`. There is no IP, name, raw URL,
password, auth header, query string, SQL statement or exception text.
The trace is *not* an externally visible endpoint. When diagnostics is
disabled, only the existing generic error warning remains on exceptions.

**Interpreting negative results:**
- No outcome log: could be WAF interception, wrong Worker, diagnostics not
  deployed/enabled, or log visibility/sampling issues. NOT proof of success.
- \`disabled\`: production runtime's Worker ingestion switch is OFF.
- \`no_lifecycle\`: no available Worker \`waitUntil\` execution context.
- \`sampled_out\`: a decoy request reached the Worker but its TiDB INSERT
  was deliberately skipped under the existing 10% sampler. This is expected;
  it is NOT a database outage.
- \`not_configured\`: Worker cannot validate the expected dedicated connection
  URL/secret. Check secret NAME, URL percent-encoding, username and host; do
  NOT paste the password or URL into chats or logs.
- \`auth\`: use owner/admin to verify **grants**, secret rotation and account
  activation, without widening the writer's privileges.
- \`schema\`: verify database/table/column names with the owner SQL Editor.
- \`transport\` or \`timeout\`: check TiDB instance availability, HTTP
  serverless gateway and network restrictions.
- \`inserted\`: SQL driver acknowledged INSERT, but **proof requires an
  independent owner SELECT for a newly written row**.

Cloudflare Workers Logs need to be enabled for console output to be
searchable. Avoid enabling unlimited expensive retention or additional
log export under a zero-budget policy. Relevant official docs:
https://developers.cloudflare.com/workers/observability/logs/workers-logs/

## Exactly-one controlled validation

1. Confirm the Cloudflare production version and real secret binding
   \`TIDB_HONEYPOT_DATABASE_URL\` by NAME; never reveal the value.
2. Verify TiDB Starter US$0 monthly spending cap and existing writer grants.
3. Review a release that enables safe diagnostic logging for the existing
   decoy-only code, while retaining **10% sampling**. Deploy once only after
   owner approval; do not touch Vercel, DNS or database schema.
4. Open one existing, allowlisted benign decoy GET (e.g. \`/admin.php\`)
   under the site's normal access policy. Do not hammer or bypass WAF.
5. Inspect privacy-safe \`[HONEY TIDB OUTCOME]\` records: a single
   \`sampled_out\` means the path is correct and sampling skipped INSERT; an
   \`inserted\` means the driver acknowledged SQL; \`not_configured\` or
   \`failed\` distinguishes the failing phase. Do not disclose raw logs.
   Turn diagnostics OFF again after the controlled acceptance window.
6. In the **owner SQL Editor only**, execute:

\`\`\`sql
SELECT id, source, event_type, protocol, request_path, observed_at
FROM vynalth_honeypot.honeypot_events
WHERE source = 'cloudflare_worker'
ORDER BY id DESC
LIMIT 10;
\`\`\`

7. Confirm a truly NEW \`cloudflare_worker\` row after the current deployment.
   Rows from \`local_test\` or simulated GitHub CI do NOT count.
8. Record production version, outcome class, timestamp, row ID and a
   **sanitized** screenshot/attestation in the PR's private release evidence.
   Never expose SQL results containing raw identifiers or secrets publicly.

Do not assume a single harmless GET must be stored: sampling defaults to
10%. Missing one sample is not itself a connection failure.

## Separate protocol-sensor release gates

The protocol sensor endpoint remains OFF:
\`HONEY_SENSOR_INGEST_ENABLED="false"\`.
Only after real Worker writes, a dedicated VM, a trusted secret key, nonce
replay defense/rate limits, separate operator approval and a working private
collector may signed \`cowrie\` and \`opencanary\` rows be introduced.
Never transfer raw credentials, malware binaries or full TTY tape to TiDB.

This is a production validation plan and code, NOT a claim that the
production connection has been proven or activated.

## Current user-supplied evidence (2026-11-19)

The DB owner ran an authorized SELECT filtering source IN
('cloudflare_worker','cowrie','opencanary'), and SQL Editor returned
\`Query OK. empty set\`. This shows zero rows *matching those source names
at query time*, not a database error. No \`[TIDB HONEYPOT] insert failed\` is
known to have been observed, but that warning is only generated if the code
actually reaches an INSERT exception. It cannot confirm a successful insert.

At user request, **do not require Oracle quota checks** as a prerequisite to
continuing the existing Cloudflare→TiDB diagnostic. The dedicated cloud
sensor deployment remains postponed without resource/cost authorization.
