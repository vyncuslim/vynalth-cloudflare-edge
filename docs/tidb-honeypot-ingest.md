# TiDB Cloud Starter honeypot sink — deployment gate

This optional sink writes **only HTTP decoy probe observations** from the
existing Cloudflare Worker into the user's already-created
`vynalth_honeypot.honeypot_events` table. It does not emulate SSH or MySQL,
collect malware, or record requests that Cloudflare WAF blocks upstream.

## Required SQL schema (already created by operator)

```sql
CREATE TABLE IF NOT EXISTS vynalth_honeypot.honeypot_events (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(64) NOT NULL,
  source VARCHAR(50) NOT NULL,
  protocol VARCHAR(20),
  source_ip_hash CHAR(64),
  country_code CHAR(2),
  request_path VARCHAR(255),
  action_taken VARCHAR(30),
  observed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_observed_at (observed_at),
  INDEX idx_event_type (event_type)
);
```

## Secure connection

1. In TiDB Cloud create a dedicated database account restricted to **INSERT**
   on `vynalth_honeypot.honeypot_events`. The Worker refuses `.root` credentials.
   Verify the database user's actual granted rights before enabling.
2. Generate its password privately. Do not paste it into chat, GitHub,
   SQL logs, browser-visible JavaScript, or issue trackers.
3. Configure the existing Cloudflare Worker secret
   `TIDB_HONEYPOT_DATABASE_URL` using the official serverless driver format:

   `mysql://<prefixed-nonroot-username>:<percent-encoded-password>@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot`

   **Do not append port 4000:** this URL is for the TiDB HTTPS serverless driver,
   not a TCP MySQL client.
4. After tests and a successful Worker build, explicitly set
   `TIDB_HONEYPOT_INGEST_ENABLED = "true"` in Wrangler configuration.
   Default is `false`; do not enable on the PR before the live secret exists.
5. With `TIDB_HONEYPOT_SAMPLE_RATE = "0.1"` only approximately 10% of
   eligible requests are written, to reduce free quota consumption.
   It is **not** a global quota cap. The TiDB Starter $0 monthly spending limit
   should remain unchanged. Sampled counts must not be represented as totals.

## Data safety

- Uses TiDB `@tidbcloud/serverless` via HTTPS, not TCP port 4000.
- Only predetermined, normalized probe paths reach parameterized SQL.
- No original IP, body, request headers, User-Agent, tokens, or query strings.
- `source_ip_hash` is a *daily pseudonymous network hash* only if the
  existing HMAC secret is present; otherwise it is NULL. Treat hash as personal
  data in retention/privacy reviews, not a verified person identity.
- Failures happen in `ctx.waitUntil()`, do not change any HTTP response,
  and log only a generic warning.
- `suspicious_probe` means the path was probed. It is **not verified compromise**.
- The SQL driver's preview status requires an end-to-end test before enabling.
- No new Vercel deployments, domains, database migrations, or Cloudflare routes.

## Acceptance

1. GitHub CI tests and Wrangler dry-run pass.
2. Add *least-privileged* database user and secret; independently confirm host.
3. Deploy once through existing Cloudflare Workers Builds with flag OFF.
4. Set the enabled flag only when credentials and rollout are approved.
5. Trigger a harmless test GET to an existing decoy path on a **managed** host.
   With 10% sampling, repeat if needed; do not repeatedly hammer the endpoint.
6. Verify a **new** row appears in TiDB SQL Editor:
   `SELECT id, event_type, source, request_path, action_taken, observed_at
   FROM vynalth_honeypot.honeypot_events ORDER BY id DESC LIMIT 10;`
7. Restore disabled flag if observed failures, excessive traffic, or quota pressure.

Never paste any database credential into an assistant conversation.
