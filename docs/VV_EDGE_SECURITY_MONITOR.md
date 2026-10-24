# Personal website apex via existing vv Worker

`vyncuslim.com/*` and `www.vyncuslim.com/*` are owned by **vv**, not by `vynalth-cloudflare-edge`. The edge Worker currently owns only `*.vyncuslim.com/*` in this zone. Preserve the exact original Wrangler routes. Do not steal the apex.

The existing `vv` Service Binding `GPS_POLICY_EDGE -> vynalth-cloudflare-edge` now supports an additional, separate HMAC-signed site-monitor protocol. Incoming `X-Vynalth-Site-Monitor-*` requests are never trusted without a 32+ character shared `GPS_SERVICE_AUTH_SECRET`, a matching SHA-256 signature, and a recent timestamp; altered status, path, method, host or timestamp is rejected. Signed events return HTTP 404 for a trap and 204 for a passive or access observation without ever fetching the origin. Other GPS controls are unchanged.

## Variables / Secrets

In **vynalth-cloudflare-edge** (Cloudflare Worker):

- `SITE_MONITOR_SERVICE_ENABLED=true` — enable HMAC-verified internal telemetry
- `SECURITY_TELEMETRY_ENABLED=true` — enable Axiom security/access writes
- `SECURITY_HONEYPOT_ENABLED=true` — enable 10 active traps and passive probes
- `SECURITY_ACCESS_MONITOR_ENABLED=true` — enable signed vv access and 5xx status records
- `SECURITY_MONITOR_ALERTS_ENABLED=true` — send all classified first-party trap/probe signals to both ntfy + Telegram and create independent Axiom `SITE_ALERT_DISPATCH_OUTCOME` records
- Secret `GPS_SERVICE_AUTH_SECRET` — already shared with `vv` for signed GPS Service Binding, reused with a distinct signing purpose
- Secret `AXIOM_SECURITY_INGEST_TOKEN` — Axiom ingest-only permission for `vynalth-security-logs` / `vynalth-access-logs`
- Secret `SECURITY_MONITOR_TELEGRAM_BOT_TOKEN` and `SECURITY_MONITOR_TELEGRAM_CHAT_ID`, alternatively the existing `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID`
- Secret `SECURITY_MONITOR_NTFY_TOPIC` (private random topic, 24–64 characters); alternatively existing `NTFY_TOPIC_MONITOR`. Optional Secret `SECURITY_MONITOR_NTFY_TOKEN`.

In **vv** Worker: enable `SITE_MONITOR_EDGE_ENABLED=true` after receiving Worker is deployed. Do not change `vv` apex ownership or its GPS Service Binding.

The Cloudflare edge Worker records `host=vyncuslim.com` in security and access events. Sensitive paths are reduced, query strings, authorization headers, cookies, raw source IP and geolocation fixes are never transmitted by this monitor protocol. Site decoys return real HTTP 404 regardless of monitor outage, and passive probes do not block application routes.

## Verification / scope

1. Test both GitHub PRs' non-deploying CI. Ensure existing GPS regression remains green.
2. Deploy edge first and set configured secrets; then configure vv monitor feature.
3. Make a benign one-off GET to `https://vyncuslim.com/__vynalth-hp/hidden-link`. Expect 404, not a success screen.
4. Confirm Axiom `HONEYPOT_TRIGGER` and `SITE_ALERT_DISPATCH_OUTCOME` for `vyncuslim.com`; check real Telegram/ntfy provider acknowledgements and manually verify receipt on devices.
5. Verify unchanged pages (/ and /jingxin), contact forms, GPS policy and public DNS/Host routing. Do not claim live success until these pass.

**Notes:** per-channel deduplication is best-effort per isolate (5-minute window) rather than globally exactly-once. A provider HTTP/API acceptance is not device delivery. All classified trap/probe events can emit both channels, whereas raw HTTP access logs are stored in Axiom rather than pushed to phones. Existing PR #11's Vercel honeypots are redundant for the Cloudflare-routed apex and should not be deployed in parallel.
