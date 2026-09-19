# Vynalth Cloudflare Edge

Cloudflare edge proxy and privacy-safe request-observability layer for Vynalth AI and its approved public domains.

## What this Worker does

Every accepted request receives an `x-vynalth-request-id` at Cloudflare's edge. The Worker forwards it and Cloudflare's Ray ID to Vercel, and returns both to the browser:

- `x-vynalth-request-id`
- `x-vynalth-ray-id`
- `x-vynalth-edge: cloudflare-worker`

It asynchronously writes one event to Axiom's `vynalth-log` dataset, including `site`, `host`, path (without query string), method, status, duration, country, ASN, cache state and a salted IP hash. It never records raw IPs, query strings, cookies, authorization headers, bodies, or full referers.

Only exact hostnames listed in `src/index.js` receive an origin. An unknown hostname returns 404 instead of being sent to the wrong website. Add a hostname and its correct Vercel Origin together in a pull request.

## Approved origins

| Public host group | Vercel Origin |
| --- | --- |
| Vynalth AI main, www, trust, status, partner, cf-test | `somno-ai-digital-sleep-lab.vercel.app` |
| Vynova | `social-puce-nine.vercel.app` |
| Shield | `vita-shield.vercel.app` |
| Navigator | `vynalth-ai-navigator.vercel.app` |
| Pedia | `pedia-peach.vercel.app` |
| Search | `vynalth-ai-search.vercel.app` |
| SleepSomno main, www, trust, status | `somno-ai-digital-sleep-lab.vercel.app` |
| SleepSomno Shield | `vita-shield.vercel.app` |
| VitaminD AI | `somno-ai-digital-sleep-lab.vercel.app` |
| Vyncus Lim main and www | `vv-seven-tau.vercel.app` |
| POWIIS MUN main and www | `powiis-mun-2027.vercel.app` |

## Required Cloudflare secrets

Set these on the **vynalth-cloudflare-edge** Worker as runtime secrets; never commit them.

- `AXIOM_TOKEN` — ingest-only token restricted to `vynalth-log`.
- `IP_HASH_SALT` — long, random stable salt. Replace it immediately if it has been exposed.

Non-secret variables in `wrangler.toml`:

- `AXIOM_DATASET=vynalth-log`
- `LOG_SAMPLE_RATE=1`

## Deploy and verify

Merge the pull request, then ensure every listed DNS record is proxied (orange cloud) in its own Cloudflare Zone. The Worker routes declared in `wrangler.toml` cover the five zones.

For each public hostname:

```bash
curl -I https://HOSTNAME
```

Expected response headers:

```text
cf-ray: ...
x-vynalth-edge: cloudflare-worker
x-vynalth-request-id: ...
x-vynalth-ray-id: ...
```

Search Axiom for the returned `x-vynalth-request-id`. Its matching edge event must have the same `request_id`, `ray_id`, `host` and `site`.

## Retention and access control

- Keep routine edge logs for 30 days; retain confirmed security incidents and audit records for 90 days.
- Restrict `vynalth-log` queries to security administrators.
- Use a distinct ingest-only Axiom token and rotate it and the salt after suspected exposure.
- Logging is fail-open: an Axiom outage never blocks visitors.

## Local commands

```bash
npm install
npm run dev
npm run deploy
npm run tail
```
