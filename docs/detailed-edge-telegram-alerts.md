# Detailed per-request Telegram notifications

## Objective

The Cloudflare edge Worker now formats sitewide alerts in the multiline
**Vynalth AI Security Alert** format. When
`EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS = "true"`, it also emits one best-effort
`HTTP_REQUEST / INFO` notification for each HTTP 2xx or 3xx response that
actually passes through this Worker, in addition to its existing 4xx, 5xx,
and suspicious-path alerts.

This is **not** a guarantee of delivery or an audit log: Cloudflare WAF
decisions made before this Worker, origin subrequests made outside it, and
requests that do not reach its routes are not seen. Under heavy traffic,
Telegram Bot API may return HTTP 429 or fail. Per-request `waitUntil()` sends
are nonblocking and not durable; to guarantee eventual delivery, separately
add a Cloudflare Queue or Durable Object with retries, explicit consent,
rate-aware backpressure, and a bounded retention policy.

## Diagnostic fields

- The Worker measures elapsed wall-clock time from entry to the HTTP response
  created by the Worker: `Response Time Ms`. It does not include downstream
  processing after the response is returned or Telegram delivery time.
- `IP`, `Ip Verified`, `Ip Source` and `Ip Verification Reason` are
  **edge observations** only. They require a plausible `CF-Connecting-IP`
  and runtime-provided `request.cf` metadata. They do **not** assert the
  application's cryptographic HMAC verification has happened.
- `Country` and `Location` come only from Cloudflare IP metadata and are
  coarse, not browser GPS. Proxy location is explicitly unknown.
- `Device Id` and `User` are not authenticated by this general Edge Worker;
  optional UUID-formatted browser claims are labeled **unverified**.
- `Path` is bounded and masks UUIDs/long opaque segments. Query parameter
  **values** are never sent, only the count. Raw Cookie, Authorization,
  credentials, and request body are never read or transmitted. Content-Type
  parameters are removed. `GPS` is never inferred from IP.

## Controls

In the repo's `wrangler.toml`:

```toml
EDGE_TELEGRAM_ALERTS_ENABLED = "true"
EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS = "true"
```

The existing production Worker must also have a valid
`TELEGRAM_BOT_TOKEN` Secret and `TELEGRAM_CHAT_ID` binding, or their
edge-specific alternatives. The alert destination should be an
administrator-only Telegram chat, because even source-verified IP addresses
are personal data and unrestricted chat participants should not receive them.

To send only failure/security alerts later, set
`EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS = "false"` and deploy. This does not
disable the independent GPS denial alert pipeline.

## Verification

1. Run `npm test` and Worker `wrangler deploy --dry-run` in CI.
2. Confirm the latest code is deployed from Cloudflare Workers Builds.
3. Make a harmless authorized GET that returns HTTP 200 through the Worker.
4. Confirm the Telegram chat receives the matching `HTTP_REQUEST` /
   `Severity: INFO` message, including the real request path, host, response
   status, source-qualified IP, request ID, timing, and redacted fields.
5. Test a known 403/404 or 5xx in a controlled environment and verify severity
   remains warning/high. A sensitive-path probe is an observation, not proof
   of a successful intrusion.
6. Verify the chat has restricted membership and decide whether a Queue
   should absorb sustained traffic above Telegram Bot API delivery rates.

GitHub CI green alone does not prove a production deployment or Telegram
receipt. Never echo bot token or full Telegram API URL into logs.
