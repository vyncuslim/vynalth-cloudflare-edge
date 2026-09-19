# Vynalth Cloudflare Edge

Cloudflare edge proxy and request-observability layer for the production Vynalth AI site.

## Request correlation and privacy

Every public request receives an `x-vynalth-request-id` at Cloudflare's edge. The same value, together with the Cloudflare Ray ID, is forwarded to the Vercel origin and returned in the browser response:

- `x-vynalth-request-id`
- `x-vynalth-ray-id`

Use these fields in backend structured logs and Telegram security alerts to trace one request from Cloudflare → Vercel API → Axiom → alert.

The Worker sends one non-blocking event to the `vynalth-log` Axiom dataset. It records timestamp, host, path, method, status, duration, country, ASN, cache state and a salted IP hash. It never records query strings, cookies, authorisation headers, request/response bodies, raw IP addresses or full referers.

## Required Cloudflare secrets

Add these as Worker runtime secrets in the **vynalth-cloudflare-edge** Worker dashboard. Do not commit them to this repository.

- `AXIOM_TOKEN` — Axiom ingest-only token restricted to `vynalth-log`.
- `IP_HASH_SALT` — long stable random secret for irreversible IP hashing.

The non-secret Worker variables live in `wrangler.toml`:

- `AXIOM_DATASET=vynalth-log`
- `LOG_SAMPLE_RATE=1`

## Architecture

```text
Browser
  -> https://vynalthai.com
  -> Cloudflare WAF / rules
  -> vynalth-cloudflare-edge
  -> Axiom vynalth-log (non-blocking)
  -> https://somno-ai-digital-sleep-lab.vercel.app
```

The public domain remains `vynalthai.com`. The Worker deliberately uses the stable Vercel production alias as its origin. Do **not** change `ORIGIN_HOST` to `vynalthai.com`, because once the apex is proxied through this Worker that would create a proxy loop.

## Verification

After deployment:

```bash
curl -I https://vynalthai.com
```

Expected response headers include:

```text
cf-ray: ...
x-vynalth-edge: cloudflare-worker
x-vynalth-origin: vercel
x-vynalth-request-id: ...
x-vynalth-ray-id: ...
```

Search Axiom for the returned `x-vynalth-request-id` to find the matching edge event.

## Retention and access control

- Keep routine edge logs for 30 days; keep confirmed security incidents and audit records for 90 days.
- Limit `vynalth-log` query access to security administrators.
- Use a separate ingest-only Axiom token; rotate it and the IP salt after suspected exposure.
- Axiom failure is fail-open: visitor traffic continues even when logging is unavailable.

## Local commands

```bash
npm install
npm run dev
npm run deploy
npm run tail
```
