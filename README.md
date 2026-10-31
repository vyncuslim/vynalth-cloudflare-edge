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

## Worker routes — Dashboard-owned (avoids 10020)

The operator's production routes are managed at **Cloudflare Dashboard → Workers & Pages → vynalth-cloudflare-edge → Settings → Domains & Routes**. They are **not** declared in `wrangler.toml` because Wrangler's re-registration of already-existing patterns returned Cloudflare error `10020` and caused partial deployment errors.

- **Do not delete or reassign** an existing route to resolve error 10020 without verifying its current owner. That could interrupt other services.
- The historical intended coverage is the apex `vynalthai.com/*` and seven wildcard patterns (`*.vynalthai.com/*`, `*.vyncuslim.com/*`, `*.sleepsomno.com/*`, `*.powiismunc.com/*`, `*.vitamindai.online/*`, `*.vynalthai.si/*`, `*.vyncuslim.si/*`). **This is an intended inventory, not a claim that every pattern is currently active.** Review every live route and its assigned Worker in Dashboard.
- `workers_dev = true` remains enabled to preserve the existing `vynalth-cloudflare-edge.ongyuze1401.workers.dev` entrypoint. Cloudflare's no-route dashboard workflow typically recommends disabling workers.dev; this project intentionally preserves the existing URL and validates that direct endpoint separately.
- The route regression script verifies that Wrangler cannot re-register any routes and leaves all original GPS, School Policy, and privacy controls unchanged.
- After deploying, verify the actual Worker route mapping and an `x-vynalth-edge` response header on the intended website endpoints. Do not assume a clean build proves every route is assigned correctly.

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
- `wrangler.toml` — Worker configuration; existing routes are managed in Cloudflare Dashboard.
- `.github/workflows/deploy.yml` — GitHub Actions verification workflow (tests, route checks, Wrangler dry-run only).

## Deployment ownership and credentials

**Cloudflare Workers Builds is the sole automatic production deployer.** Cloudflare's Git integration watches the `main` branch and invokes `npx wrangler deploy` using the build token configured in Cloudflare Workers Builds.

GitHub Actions does **not** deploy the Worker and does **not** require a `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_ACCOUNT_ID` repository secret. The GitHub verification workflow executes unit/security tests, checks zone routes, and performs an offline Wrangler dry-run.

**Important:** Passing GitHub verification does not prove a Cloudflare production deployment succeeded. Check the Cloudflare Workers Builds status and the full deploy log separately. The Cloudflare build token must have sufficient privileges for the Worker and all seven configured zones; do not bypass safeguards or remove routes to conceal deployment errors.

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


## Universal Cookie Consent — Cloudflare Workers KV only (draft)

**No Supabase integration.** One existing vynalth-cloudflare-edge Worker serves these four registrable domains and all their subdomains: vynalthai.com, vyncuslim.com, vynalthai.si, vyncuslim.si.

Each root domain receives an independent first-party __Secure-vynalth-consent Cookie, scoped using Domain=<root>, Secure, HttpOnly, SameSite=Lax, Path=/. Cookies are stored by the browser, **not literally in KV**. Workers KV stores the related consent preferences, version, timestamp, withdraw timestamp, site/share scope, and append-only history events.

Anonymous guests use random per-domain identifiers, issued only after they save a preference; no device fingerprinting, third-party cookies or cross-domain anonymous linking. Optional purposes (analytics, personalization, marketing) default to OFF. Essential cookies remain ON.

**Authenticated cross-domain consent** uses the existing SSO backend, not an unrelated database. A user signed into the same verified account on each of the four root domains obtains a fresh, first-party, HMAC-signed SSO assertion for that root domain. The Worker verifies identity, reads the common pseudonymous account preference in KV, and sets that site's own first-party Cookie. The browser never reads a different domain's Cookies. Existing SSO backend issuance is a REQUIRED integration step, not yet implemented or verified in this repository.

Affirmative choices are written to shared scope only if the user is authenticated and explicitly ticks a notice mentioning ALL FOUR domains and purposes, with notice version vynalth-four-domains-v1. Without this, consent is local to the site. A subsequent withdrawal of a shared grant writes a new shared-revocation event; after new authenticated state sync, all four domains receive revoked choices. Local denials may override earlier affirmative shared choices.

### API paths

- GET /__vynalth/consent — multilingual manage/update/revoke page
- GET /__vynalth/consent/client.js — first-party consent UI script
- GET /__vynalth/consent/session — generate site-specific CSRF cookie and token
- GET /__vynalth/consent/state — return effective consent; refresh first-party Cookie
- POST /__vynalth/consent/preferences — save or withdraw; requires matching Origin, same-site fetch checks, and X-Vynalth-Consent-CSRF
- GET /__vynalth/consent/history?scope=site or scope=shared — read own consent history

Consent records live in dedicated CONSENT_KV Workers KV binding. Materials to configure IN THE EXISTING Cloudflare Edge Worker:

1. Create a consent-only KV namespace; bind it as CONSENT_KV. Namespace ID is account-specific and has not been invented. For reproducible wrangler deploys, commit the real KV binding ID only after provisioning and review.
2. Cloudflare Secret CONSENT_COOKIE_SECRET — unique, random, 32+ characters.
3. Cloudflare Secret CONSENT_SSO_SIGNING_SECRET — separate, unique, 32+ characters, shared with trusted SSO backend issuer only; never frontend.
4. CONSENT_CMP_ENABLED — defaults to false; change to true ONLY AFTER integration and tests.
5. SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED — separate, defaults to false. After true and valid SSO assertions, trust, contact, status accounts are exempt from SCHOOL IP WORKER only. They are NOT exempt from unrelated Cloudflare WAF, abuse detection or application authorization.

### Signed first-party SSO assertion contract (not wired yet)

Existing SSO backend, AFTER actually checking login and account status, issues a Cookie named __Secure-vynalth-sso with value:

Base64url(JSON({sub, sid, status, host, exp})).Base64url(HMAC_SHA256(secret, payloadBase64url))

Use the SSO signing secret only on trusted server infrastructure. The status and stable user ID must not be browser-supplied or taken from user-editable metadata. host must equal the root domain and exp must be a future UNIX timestamp no more than 15 minutes away. sub and sid must each be validated opaque IDs of 8–128 safe characters. Issue via HTTPS with Secure, HttpOnly, SameSite=Lax, Path=/, Domain=<root> and short lifetime.

**Canonical identity source: vynalthai.com only.** Other sites obtain their own short-lived, first-party, root-bound assertion through the explicit first-party SSO redirect described below; the user's browser never reads the vynalthai.com Cookie while on another root domain. Never mint an assertion based solely on a browser-submitted user ID or status. If SSO is not linked, the module treats the browser as a guest.

### KV state and legal caveats

KV snapshot keys use the prefix vynalth:consent:v1 with separate subject-pseudonym and anonymous site IDs. Event keys include timestamp and unique event ID; histories include consent version, categories, update and withdrawal times and scope. Audit events expire after 365 days by default; data deletion/retention policy requires review.

KV is eventually consistent, not transactional. Concurrent updates can race, and permission withdrawal may take time to propagate. This does not provide a strictly atomic compliance audit or instant global revocation. For stronger guarantees use Cloudflare Durable Objects as a per-account coordinator, still without Supabase.

Production acceptance is currently BLOCKED on provisioning CONSENT_KV, implementing and validating the actual SSO issuer, reviewing privacy/security policy, confirming four-zone routes, and passing unit/integration tests. Do not deploy or merge this draft until reviewed.

### Tests

npm test
node --check src/universal-consent.js
node --check src/index.js

The tests cover all four registrable domains and subdomains, anonymous denial, consent saving, CSRF and origin rejection, SSO impersonation, explicit sharing, history/withdrawal and Safari/Firefox third-party-cookie isolation.


### Canonical SSO source and cross-domain login handoff (vynalthai.com)

This amendment implements the operator's requirement that **all SSO identity and account status originate from vynalthai.com**. Existing Vynalth AI Auth on vynalthai.com must authenticate the person and issue the signed first-party `__Secure-vynalth-sso` cookie there. Only that canonical root is allowed to initiate linking of the other roots.

The target domain displays a first-party `Connect vynalthai.com account` link. The browser uses a visible top-level navigation, not a cross-site iframe or a third-party cookie:

1. `GET https://vyncuslim.si/__vynalth/consent/link` sets a **signed 5-minute state cookie scoped to vyncuslim.si**, then redirects to the main site.
2. `GET https://vynalthai.com/__vynalth/consent/authorize?client=vyncuslim.si&state=...` verifies the **existing** trusted vynalthai.com first-party login cookie and creates a **60-second opaque KV ticket** containing the verified user ID, session ID, status, target, expiry and originating hub.
3. The hub redirects to `https://vyncuslim.si/__vynalth/consent/callback?code=...&state=...`.
4. The target verifies the original signed state cookie, target hostname, exact KV ticket, expiry and issuer; it deletes the ticket and mints **its own signed `__Secure-vynalth-sso` first-party cookie for at most 10 minutes**. The target then opens its first-party consent manager and reads preferences for the verified, linked account from the common KV namespace.

This same approved flow applies to all three non-hub roots and their subdomains: vyncuslim.com, vynalthai.si, vyncuslim.si. `trust`, `contact`, and `status` roles are verified on the canonical site and are carried only in signed, host-bound cookies; the browser cannot choose its own role. The exemption flag is separate from consent, and existing Cloudflare WAF, DDoS and other compulsory protections remain in force.

**Important limitations before production:**
- Existing `vynalthai.com` auth has NOT yet been verified as issuing the expected canonical signed SSO assertion. The Worker does NOT invent a logged-in identity.
- The KV ticket is deleted after redemption, but **Workers KV is eventually consistent; redemption is best-effort single-use, not atomic**. Global concurrent replay can happen during its 60-second lifetime. For strong single-use security, a Durable Object coordinator is preferable. This is still entirely within Cloudflare and does not involve Supabase.
- Authenticator logout/revocation is not yet wired. The target session survives until its 10-minute expiry unless keys are rotated; verify acceptable revocation delay before production.
- Secrets are separate: `CONSENT_COOKIE_SECRET` signs consent identifiers and state; `CONSENT_SSO_SIGNING_SECRET` verifies the central authority and signs target-limited cookies. Neither can be exposed to the browser.
- First-party top-level navigations use `SameSite=Lax` and need no Safari/Firefox third-party cookie allowance. Cookie acceptance depends on the destination browser's first-party policy.
- The 60-second ticket appears in a redirect URL; keep `Referrer-Policy: no-referrer`, do not record sensitive query strings in edge/app/observability logs, and consider short-lived code revocation and anti-replay protection.
- This feature remains in a **DRAFT PR, OFF by default**, until the real existing Auth issuer is linked and acceptance tests pass.


## October 11 — Integrated GPS + Cookie Consent Review (Draft, not live)

This branch combines `review/universal-consent-kv-20261011` and
`review/consent-gps-guest-gate-20261011` into **one** existing
`vynalth-cloudflare-edge` Worker. The order is:

1. Universal consent endpoints (`/__vynalth/consent/*`);
2. GPS Guest Gate endpoints and optional campus gate (`/__shield/gps/*`);
3. Existing POWIIS School IP Policy service binding;
4. Original hostname routing and origin proxy.

Upstream Cloudflare WAF and DDoS protections are separate and cannot be
unconditionally bypassed by a downstream Worker. `trust`, `contact` and
`status` are exempt from **both school-IP and GPS feature-specific blocking**
when backed by a valid, server-issued, root-bound canonical SSO assertion.
The GPS module also recognizes its independent legacy signed exemption
Cookie. No untrusted client-provided role can activate an exemption.

**All feature flags remain OFF by default** in `wrangler.toml`:
`CONSENT_CMP_ENABLED=false`,
`GPS_GATE_ENABLED=false`, and
`SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED=false`.
This branch is for code review and isolated tests only. Do not merge or
deploy to production until the actual Auth issuer, KV resources, logging,
legal/privacy impact assessment, supported DNS routes and browser flows
are confirmed. It contains no officially validated school boundary.

### Two POWIIS campuses: test-only geometry

POWIIS **official contact page**:
https://www.powiis.edu.my/contact-us/

- Balik Pulau: 1 Jalan Sungai Air Putih 6, Bandar Baru Air Putih,
  11000 Balik Pulau, Penang, Malaysia; **+604 868 9999**.
- Tanjung Bungah: 88 Jalan Loh Poh Heng, 11200 Tanjung Bungah, Penang;
  **+604 893 9999**.

Operator-provided OSM references, **not school-certified perimeters**:
- Tanjung Bungah: https://www.openstreetmap.org/way/790940312 ;
  draft center `5.46113,100.28420`; farthest checked node about 111.76 m;
  one vertex not yet checked.
- Balik Pulau: https://www.openstreetmap.org/way/808258869 ;
  draft center `5.36770,100.21995`; farthest checked node about 129.78 m.

**111.76 m, 129.78 m and 180 m must not be used as certified production
radii.** Neither school campus has a confirmed authoritative perimeter
or radius in the available project evidence. A 180-m circle may include
people outside campus and would be an unacceptable sole criterion for
enforced blocking.

Temporary test-only configuration, in an isolated non-production Worker:
```env
GPS_GATE_ENABLED=true
GPS_CAMPUS_GEOFENCES_JSON=[{"id":"tanjung-bungah","lat":5.46113,"lon":100.28420,"radius":180},{"id":"balik-pulau","lat":5.36770,"lon":100.21995,"radius":180}]
```

Requires test-only `GPS_GATE_SESSION_SECRET` and
`GPS_ACCOUNT_STATUS_SECRET` values, each 32+ characters and distinct.
No GPS point is saved in a Cookie. The site issues signed short-lived
per-host verdicts, not browser-shared cross-root cookies. The browser
uses an explicit first-party redirect-based signed handoff.

To check the single-Worker draft:
```sh
npm test
node --check src/index.js
node --check src/guest-gps.js
node --check src/universal-consent.js
```

**Release blockers:** verified account-status issuer and lifecycle;
production KV and cryptographic secrets; a replay-safe consent handoff;
WAF and School IP Policy interaction; code review; privacy of minors;
accurate school polygon vertices and onsite measurements; accessible
GPS-denial alternatives; browsers and subdomains; functional photo access
authorization. DO NOT turn on campus blocking while any remain open.
