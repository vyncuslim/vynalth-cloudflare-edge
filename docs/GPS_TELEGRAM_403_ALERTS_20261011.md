# GPS 403 Telegram notifications (operator-approved)

## What triggers an alert

The existing `vynalth-cloudflare-edge` Worker sends a server-side Telegram notification when POST `/__shield/gps/verify` returns **403** with either of these *server-calculated* results:

- `CAMPUS_BOUNDARY_UNCERTAIN`: browser-reported point is mapped inside a provisional campus polygon, near the candidate boundary. This is NOT proof of wrongdoing. Severity **Warning**. Show the user a retryable denial, unchanged.
- `CAMPUS_RESTRICTED`: point is classified INSIDE under the current approximate polygon policy. Severity **High**.

A denied GPS permission, GPS timeout, clearly OUTSIDE result, normal GET challenge, and successful NEARBY/OUTSIDE verification do not emit this alert. The Telegram system is **not an access control**: failure/delay does not turn a 403 into 200, nor cause an additional block.

## Required Cloudflare Worker secrets

In Cloudflare Dashboard -> Workers & Pages -> `vynalth-cloudflare-edge` -> Settings -> Variables and Secrets, securely configure the existing bot's **Worker-bound** `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` (or `GPS_TELEGRAM_BOT_TOKEN` and `GPS_TELEGRAM_CHAT_ID`; `ADMIN_TELEGRAM_CHAT_ID` also supported). The Vercel frontend's Bot/Chat secrets are **not automatically available in Cloudflare Worker**, even when the same brand uses a Bot. Configure as **Secret** values, not a public `[vars]` item and never commit them to GitHub. Make sure the bot can message the intended admin chat and the chat ID is correct.

`GPS_TELEGRAM_ALERTS_ENABLED=true` in the Worker source configuration opts into notification when those credentials and the existing `CONSENT_KV` binding are available. The public `/__shield/gps/status` reports `telegramAlerts.enabled` and `telegramAlerts.configured` but never exposes the credentials. A value `configured:true` indicates valid *shape* and binding, **not** confirmed Telegram API delivery. Verify a permitted **staging-only** 403 request or operator-controlled test and check that a Telegram message is received. Do not publish real visitor location data.

## Alert format and flood controls

Message contains: event code, High/Warning classification, HTTP 403, hostname, Worker-generated request ID, UTC time, and a *coarse* reason statement. **No** GPS latitude, longitude, accuracy radius, user identity, raw public IP, device ID, original URL query, Cookie or access token is transmitted in the message.

Global per-host/event cooldown is ~60 seconds; per-IP/event cooldown ~15 minutes. For per-visitor cooldown only, the Worker HMAC-pseudonymizes `CF-Connecting-IP` using the existing private GPS signing key. **Only** anonymous short-lived deduplication markers are stored in Cloudflare KV; neither IP nor precise GPS coordinates are saved. The Worker uses `ctx.waitUntil()` so waiting for Telegram does not delay the user's HTTP 403. Failed sends are logged as generic delivery failures without leaking Bot token or API URL.

Cloudflare KV uses eventually consistent non-atomic get/put operations; duplicate alerts in concurrent or geographically distributed requests remain possible. The cooldown also suppresses separate people under the same campus-wide NAT egress IP. For strict global rate limits or stronger guarantees, migrate the deduplication to a dedicated Durable Object.

## Production / rollback

GitHub checks and Cloudflare Builds **do not** prove the Worker is deployed. The GitHub Actions `Deploy Worker` step has previously been skipped when `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` was absent. Confirm the active Cloudflare Worker version, environment Secret bindings, and a real authorized alert delivery. Set `GPS_TELEGRAM_ALERTS_ENABLED=false` to suspend only Telegram alerts; this does not change the GPS 403 enforcement.
