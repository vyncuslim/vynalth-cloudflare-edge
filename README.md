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
