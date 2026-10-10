# Vynalth Cloudflare Edge

Unified Cloudflare edge Worker for Vynalth-managed web properties.

## Managed zones

The Worker is configured for the apex and all HTTP/HTTPS subdomains of:

- `vynalthai.com`
- `vyncuslim.com`
- `sleepsomno.com`
- `powiismunc.com`
- `vitamindai.online`
- `vynalthai.si`
- `vyncuslim.si`

Mail transport hostnames that are used for SMTP/IMAP/POP should remain DNS-only and are not expected to use HTTP response headers.

## Architecture

```text
Browser / API client
  -> Cloudflare edge
     -> DDoS protection
     -> WAF / custom rules
     -> bot and rate-limit controls
     -> zone security policy
  -> Vynalth Cloudflare Edge Worker
     -> preserves the original public hostname / Host header
     -> adds x-vynalth-* tracing headers
  -> the hostname's configured Cloudflare DNS origin
  -> application origin (Vercel or another backend)
```

The Worker does not hard-code a single Vercel hostname. Each domain and subdomain keeps its own DNS origin, so multiple sites can safely share the same edge Worker.

## Response tracing headers

HTTP/HTTPS responses traversing the Worker receive:

```text
x-vynalth-edge: cloudflare-worker
x-vynalth-edge-host: <public hostname>
x-vynalth-zone: <root zone>
x-vynalth-request-id: <unique UUID>
x-vynalth-ray-id: <Cloudflare Ray ID when available>
x-vynalth-origin: vercel | fastly | dns-origin
```

`x-vynalth-request-id` is generated at the edge for every request.

## Canonical redirect

Only `www.vynalthai.com` is canonicalized by this Worker:

```text
https://www.vynalthai.com/*
  -> 301
https://vynalthai.com/*
```

Certificate and Vercel ownership validation paths are exempt from this redirect:

```text
/.well-known/acme-challenge/*
/.well-known/vercel/*
```

## Worker routes

`wrangler.toml` attaches this Worker to both the apex and wildcard route for every managed zone:

```text
vynalthai.com/*
*.vynalthai.com/*

vyncuslim.com/*
*.vyncuslim.com/*

sleepsomno.com/*
*.sleepsomno.com/*

powiismunc.com/*
*.powiismunc.com/*

vitamindai.online/*
*.vitamindai.online/*
```

A hostname must still have a valid Cloudflare DNS record and its HTTP/HTTPS traffic must actually enter Cloudflare for the Worker route to execute.

## vynalthai.com partial DNS setup

`vynalthai.com` currently uses a Cloudflare Partial/CNAME setup with Dynadot remaining authoritative.

External authoritative DNS should send proxied web hostnames to Cloudflare's partial hostname. Examples:

```text
@            ANAME -> vynalthai.com.cdn.cloudflare.net
www          CNAME -> www.vynalthai.com.cdn.cloudflare.net
partner      CNAME -> partner.vynalthai.com.cdn.cloudflare.net
status       CNAME -> status.vynalthai.com.cdn.cloudflare.net
```

Inside the Cloudflare zone, each hostname keeps its real application origin, for example a Vercel CNAME.

Do not point public authoritative DNS directly at Vercel if the hostname is intended to traverse Vynalth Edge.

## Other managed zones

For zones using Cloudflare as authoritative DNS, web-facing A/AAAA/CNAME records should normally be proxied (orange cloud) when they are intended to use Vynalth Edge.

Do not proxy ordinary mail transport records such as MX targets used for SMTP/IMAP/POP.

## Files

- `src/index.js` — multi-zone edge Worker and tracing logic.
- `wrangler.toml` — Worker configuration and multi-zone routes.
- `.github/workflows/deploy.yml` — GitHub Actions deployment workflow.

## GitHub repository secrets

Automatic deployment requires:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

The Cloudflare API token must be allowed to deploy Workers and manage Worker routes for all managed zones.

## Verification

Examples:

```powershell
curl.exe -I https://vynalthai.com
curl.exe -I https://vyncuslim.com
curl.exe -I https://sleepsomno.com
curl.exe -I https://powiismunc.com
curl.exe -I https://vitamindai.online
curl.exe -I https://partner.vynalthai.com
```

Expected Cloudflare/Vynalth indicators include:

```text
server: cloudflare
cf-ray: ...
x-vynalth-edge: cloudflare-worker
x-vynalth-edge-host: ...
x-vynalth-zone: ...
x-vynalth-request-id: ...
x-vynalth-ray-id: ...
x-vynalth-origin: ...
```

## Local commands

```bash
npm install
npm run dev
npm run deploy
npm run tail
```

## POWIIS candidate IP policy integration (observe only)

This Worker owns all **seven** configured zone Routes. It calls the separate `website-block-by-school-powiis` policy Worker through an internal **SCHOOL_POLICY** Service Binding, rather than assigning the policy Worker a Custom Domain over an existing website.

1. The policy Worker has the `SCHOOL_IP_KV` binding to namespace `website-block-by-school-powiis-school-ip-kv`.
2. The edge Worker passes only the Cloudflare-observed source IP, the hostname, path and HTTP method; URL query parameters, cookies and request bodies are not forwarded.
3. The policy Worker records only unverified candidate IPs on root GET requests and reports an allowed response (204). It can return a tagged 403 only if `MODE=enforce` **and** a `blocked:IP` key is manually created.
4. The edge Worker retains the existing origin proxy, tracing headers, redirects, validation-path exceptions and all upstream Cloudflare WAF controls. Unknown policy failures fail open to avoid taking down the website.
5. The added `.si` routes activate only on hosts with Cloudflare-proxied web DNS records and correct zone permissions. Never point SMTP/IMAP/MX transport hostnames to Workers.
6. Review Cloudflare deployment / GitHub Actions logs to confirm routes actually deployed. Updating a GitHub config does not alone prove the live Cloudflare routes changed.

The service binding and routes are declared in `wrangler.toml`. Test before deployment with `npm test`.


## Proposed Guest GPS Verification Gate (draft, OFF by default)

This branch is an **opt-in rollout**, not a production change. It does not add real-time tracking, permanently disable accounts, or change existing school-IP `blocked:` records.

### User experience

- Non-exempt guest website requests receive a 403 HTML verification screen that explains GPS access and asks the visitor to press **Allow precise location / 允许位置并验证**.
- A denied/unavailable/low-accuracy location shows a 403 *Access blocked* screen with a retry button. Browser/device location permission is **always under the visitor's control**.
- Granting high-accuracy geolocation calls `/__shield/gps/verify` with lat/lon/accuracy **only for the request**. No persistent GPS coordinate record, Cookie value or third-party lookup is made.
- When the reported location is clearly **outside** the configured campus circle, a per-host HMAC-signed HttpOnly Secure 15-minute Cookie allows navigating that site. One root domain's Cookie does not work on another.
- When reported location is inside the circle, or its 95% accuracy range overlaps the boundary, access remains restricted. GPS can be spoofed or inaccurate; this is **not a proof of school membership** or a suitable sole basis for a permanent account ban.
- An account with **server-authenticated `status=trust` or `status=contact`** is exempt **from the GPS gate**. No other statuses are exempt. The browser cannot self-declare this status in JavaScript, query params or unsigned Cookies.
- Existing signed school IP Policy, Cloudflare WAF, and explicit host route rules remain independent. This GPS gate does not promise to exempt accounts from unrelated security blocks.

### Campus reference (not a surveyed geofence boundary)

Official school address:

**POWIIS Balik Pulau, 1 Jalan Sungai Air Putih 6, Bandar Baru Air Putih, 11000 Balik Pulau, Penang, Malaysia.**

An OpenStreetMap-based school feature located by Mapcarta has approximate reference coordinates **5.3677, 100.21995**. This represents an approximate campus location, **not a verified boundary**. Do **not** automatically substitute it for surveyed coordinates; confirm the campus footprint and radius on a map and obtain a supervised on-site accuracy test. The school has a separate Tanjung Bungah campus; do not treat that as the same geofence.

### Mandatory production settings and integration

In the `vynalth-cloudflare-edge` Cloudflare Worker, the `GPS_GATE_ENABLED` variable is `"false"` by default. Before enabling, set *all* of these, applying changes in the Worker production environment rather than only GitHub:

- `GPS_GATE_SESSION_SECRET` — Cloudflare **Secret**, independent cryptographic string 32+ characters.
- `GPS_ACCOUNT_STATUS_SECRET` — Cloudflare **Secret**, another independent cryptographic string 32+ characters. **Its signed status Cookie must be issued by the trusted Vynalth authentication backend after validating the account's actual status**.
- `GPS_CAMPUS_LAT`, `GPS_CAMPUS_LON` — approved campus geofence **center**, numeric strings. The approximate Mapcarta reference above is only for assisted review, not an authoritative campus survey.
- `GPS_CAMPUS_RADIUS_METERS` — campus-specific distance in meters, from 50 to 1000. Use mapped property boundaries or a more precise polygon when available.
- `GPS_GATE_ENABLED` — only set to `"true"` **after** testing required browser flows, auth exemptions, WAF and DNS Edge routes, and explicit production authorization.

Without valid configuration (including **both** secrets) the gate **fails open**, avoiding accidental lockout. The approval token signing secret and account-status signing secret must never be exposed in the frontend.

#### Account backend contract (not wired to the existing Vynalth auth yet)

The authentication backend (NOT a browser and NOT this public Worker) must issue an HTTPS first-party Cookie named `__Host-vynalth-status` **after server-side authentication and status lookup**. Valid token format:

`<expUnixSeconds>.<status>.<nonceBase64url>.<signatureBase64url>`

Sign UTF-8 bytes of `<expUnixSeconds>|<status>|<nonceBase64url>|<hostname>` using HMAC-SHA256 with `GPS_ACCOUNT_STATUS_SECRET`. Valid status is exactly `trust` or `contact`; all other account statuses are treated like guests by the GPS gate. Expiry maximum 60 minutes ahead. Set `Secure; HttpOnly; Path=/; SameSite=Lax`, omitting the Domain attribute. Account status changes must invalidate/expire the signed Cookie, otherwise the exemption lasts until expiry. This signed Cookie is a dedicated *location exemption* token, not a primary authentication token. An attacker cannot claim contact/trust by setting an arbitrary status Cookie.

**Critical prerequisite:** Vynalth's live account system must mint and clear these tokens correctly across **each distinct root domain**. The current draft only verifies them; it does not know how to access the actual account database. Do not enable the gate until this integration works, otherwise real trust/contact users might be challenged.

### Endpoints, no GPS storage

- `/__shield/gps/client.js` — same-origin challenge JS.
- `POST /__shield/gps/verify` — returns a 403 or a short-lived signed site Cookie after precision and distance checks. Request body is not logged.
- `GET /__shield/gps/status` — status only; never returns coordinates.

OAuth/auth endpoints, ACME validation and essential webhook callbacks are excluded so login and infrastructure can continue. Cloudflare route/DNS coverage still must be audited. Some subdomains may be application APIs or dashboards for which guest GPS prompts are not appropriate; verify before enabling globally.

### Testing and safety

```sh
npm test
node --check src/guest-gps.js
```

**No automatic production deployment or account blocking.** Review and test with real browsers on iOS, Android and desktop, ensure location permission denial shows the intended screen, test existing account `trust` and `contact`, and verify auth callback flows. Externally provided browser GPS positions are **self-reported and spoofable**; use signed account status and your separate server-side policy checks when strong protection is needed.
