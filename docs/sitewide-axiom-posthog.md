# Axiom + PostHog: Vynalth AI sitewide HTTP edge logs

This implementation is **not live until enabled and verified**. It is a privacy-minimized **per-request response log** produced by `vynalth-cloudflare-edge`, in addition to the existing Telegram and threat-intelligence alerts.

## Covered managed roots

The Worker has an explicit managed-root inventory in `src/managed-domains.js`:

- vynalthai.com, vynalthai.si
- vyncuslim.com, vyncuslim.si, vyncuslim.my
- sleepsomno.com, vitamindai.online
- powiismunc.com
- vynli.xyz, vynlink.xyz, zokivo.xyz

This code only sees requests **actually routed to this Worker**; the list itself does not prove Cloudflare route ownership. Requests blocked upstream by Cloudflare WAF, zones not routed through this Worker, Vercel internal logs and Oracle system logs are **not covered**.

## Operator-controlled deployment

1. Create/reuse a scoped Axiom **ingest-only** token allowed to write to `vynalth-access-logs`.
2. Set Cloudflare Worker secret `AXIOM_ACCESS_INGEST_TOKEN` using the dashboard or `wrangler secret put AXIOM_ACCESS_INGEST_TOKEN`.
3. Set Cloudflare Worker secret `POSTHOG_PROJECT_TOKEN` with the matching PostHog project token (`phc_`, not `phx_`).
4. Ensure `POSTHOG_LOGS_ENDPOINT` points to the correct regional OTLP Logs receiver; current Wrangler example uses `https://us.i.posthog.com/i/v1/logs`.
5. Deploy code **with `EDGE_DUAL_LOGS_ENABLED=false` first**, confirm existing route/GPS/Device ID/Telegram behavior.
6. Use Cloudflare Dashboard Worker environment setting to enable `EDGE_DUAL_LOGS_ENABLED=true` for a controlled rollout, then monitor delivery status and costs.
7. Never commit tokens. Never overwrite existing Worker route bindings. Existing root domain routing remains exclusively dashboard managed.

Both destinations accept a separately formatted version of a common event; `event_id` is the Worker request UUID. PostHog uses OTLP/HTTP Logs JSON, not a PostHog analytics `/capture` event.

Axiom log path: `vynalth-access-logs`. PostHog Logs service: `vynalth-cloudflare-edge`.

## Privacy contract

Only explicitly allowlisted fields are sent: timestamp, request event ID, managed hostname, managed root, coarse route family, method, observed HTTP response status, response latency, whether a known sensitive-path pattern matched, and the source/PII policy tags.

No raw client IP, GPS, query string, user agent, cookies, auth headers, device ID, request body, response body, or user message content are included in either destination through **this new emitter**. This does not retroactively modify existing Axiom or Telegram producers.

## Delivery reliability

The two HTTP exports run in `ctx.waitUntil`, independently. Axiom's `ingested:1` response and PostHog's 2xx HTTP acknowledgment are checked. Failures are logged without tokens. They do not block the original HTTP response. **This is best effort, not durable exactly-once or 100% delivery**. Add a Cloudflare Queue with durable retries, dead-letter routing, delivery status auditing, and cost limits before promising stronger guarantees.

## Required verification

- `npm test` and `node --check src/index.js`.
- Confirm every managed root and production route actually uses this Worker.
- Hit a safe test path, record the response's `x-vynalth-request-id`, and query Axiom and PostHog for the matching event/request ID and service.
- Verify blocked and 5xx responses from inside the Worker, and confirm corresponding HTTP status (not merely a proxy-received placeholder).
- Check PostHog does not expose IP, token, cookie, query string or private path segments.
- Simulate PostHog rejection and Axiom rejection independently; neither failure changes HTTP behavior.
- Do not consider Cloudflare WAF blocks or Vercel/Oracle platform logs covered until separate Logpush / Drain / OTLP integrations pass independent tests.

See `vyncuslim/somnoai-digital-sleep-lab-backend` for the canonical server-side Axiom `ingestAxiomLog` PostHog mirror. Backend log types: access, api, security, honeypot, bot, error, audit.

For platform-side logs:
- Cloudflare WAF / HTTP logpush must be routed separately to a private sanitized collector.
- This Worker now includes a signed **Vercel team Log Drain bridge** at `https://vynalthai.com/__observability/vercel-drain`, disabled by default.
- Vercel Team Settings > Drains: create a Log Drain with schema `log.v1`, JSON encoding, selected production projects, destination URL above, and a new 32+ character signature secret. Store the same secret only as Cloudflare Worker secret `VERCEL_LOG_DRAIN_SIGNING_SECRET`.
- Set `VERCEL_LOG_DRAIN_ENABLED=true` only after a staging test; for now it is deliberately `false`.
- The drain verifies Vercel's `x-vercel-signature` HMAC-SHA1 over the **raw request body** before parsing; malformed or unsigned requests are denied.
- Only a strict allowlist is forwarded; the drain discards untrusted log message text, full URLs, proxy client IPs and user agents. Do not send raw Vercel Drain JSON directly to either OTLP endpoint.
- Each signed JSON batch must contain 1-1000 records and be under 2 MiB; larger batches require adjusting Vercel's drain or deploying a durable queue.
- For each batch, both Axiom and PostHog must acknowledge ingestion before the Worker returns HTTP 200. On failure it returns HTTP 503 so Vercel can retry; successful partial deliveries may be duplicated, so analysis must use `event_id`.
- The bridge is **not yet deployed or configured in Vercel**. The connected Vercel drain listing returned HTTP 404, and environment variable mutations returned HTTP 403; we cannot claim active Vercel delivery from this code alone.
- Oracle Ubuntu should run a protected OpenTelemetry Collector with allowlisted system/service events, persistent queues, and two independent OTLP exporters.

This PR does not change routing, access control, existing alert policies, or running Oracle services.
