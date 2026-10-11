# Vynalth AI security activation plan — 2026-10-11

**Status: staging-ready source, NOT production-enabled.**
Keep this PR out of `main` until all deployment blockers are resolved.
Do not disclose school students' email addresses, GPS coordinates, or
private photos in logs, analytics, client-visible errors or cookies.

## 1. Universal Cookie Consent (four registrable roots)

Managed consent roots: `vynalthai.com`, `vyncuslim.com`,
`vynalthai.si`, `vyncuslim.si`, and their subdomains.

Create a **real** Cloudflare Workers KV namespace, e.g.:

```sh
npx wrangler kv namespace create CONSENT_KV
```

After creation, copy the actual returned namespace ID into the EXISTING
Worker's Wrangler config (do **not** invent an ID):

```toml
[[kv_namespaces]]
binding = "CONSENT_KV"
id = "<ACTUAL_KV_NAMESPACE_ID>"
```

Set different 32+ character high-entropy Cloudflare Worker secrets; do
not paste them into git, PR text, Vercel public variables or logs:

```sh
npx wrangler secret put CONSENT_COOKIE_SECRET
npx wrangler secret put CONSENT_SSO_SIGNING_SECRET
```

The canonical `vynalthai.com` Auth backend, after verifying the actual
login, must issue the short-lived HMAC SSO Cookie for the current root.
Each root receives only its own first-party Cookie. The Worker does not
have access to a login database and cannot mint an identity by itself.
For a four-domain handoff, the canonical SSO issuer and target must
agree on the `CONSENT_SSO_SIGNING_SECRET`; rollout must consider
rotation, logout, invalidated sessions and replay-safe SSO tickets
(Cloudflare KV `delete` alone is not transactionally single-use).

Require explicit purpose-specific opt-in, no analytics/ads before consent,
and effective withdrawal. The 365-day event retention needs legal and
minors/privacy review. Use separate staging/prod namespaces.

**Only when the KV binding, real issuer and browser tests pass** should
`CONSENT_CMP_ENABLED` be set true. All other feature flags stay false.

Cloudflare docs:
- https://developers.cloudflare.com/kv/concepts/kv-namespaces/
- https://developers.cloudflare.com/kv/get-started/

## 2. POWIIS school account sign-in gate

Exact restricted *verified* email domains:
- `@student.powiis.edu.my`
- `@powiis.edu.my`

Canonical identity issuer must check the authenticated provider or a
server-owned, verified email record; **never** the user-submitted address,
an unverified identity, browser-edited `user_metadata`, the Host
header, a forged request header or a client-issued token. Use exact
domain matching, never `contains("powiis")`.

Auth backend must enforce the block DURING the login/callback before
creating the normal app session or granting protected API/database
access. It must clear/revoke any existing session, enforce account
status on sensitive APIs, and allow logout/account recovery/appeals.

The existing signed SSO assertion contract is extended to:

```json
{
  "sub":"opaque-server-owned-user-id",
  "sid":"opaque-server-owned-session-id",
  "status":"normal",
  "host":"vynalthai.com",
  "exp":1800000000,
  "email":"student@student.powiis.edu.my",
  "email_verified":true
}
```

The above is only a **format example**, NOT a usable assertion. Existing
HMAC SHA-256 signs the complete encoded JSON, and the `exp` must be
near-future. A signed assertion from canonical Auth, not a forged
Cookie, is the authority. The Cross-domain SSO ticket preserves
verified email fields when linking .com and .si first-party sessions.

After a verified school SSO, the Worker can return 403 and set a
5-minute `__Host-vynalth-school-restricted` Cookie using a **separate**
Cloudflare secret `SCHOOL_EMAIL_BLOCK_SECRET` (32+ characters).
This Cookie contains only expiry, nonce and HMAC, not an email or
GPS position; it is HttpOnly, Secure, SameSite=Lax and exact-host bound.
The Cookie is a TEMPORARY DENIAL REMINDER, not proof of identity.
Removing Cookies, switching browsers, using a personal identity,
spoofing location, or bypassing Cloudflare can evade client-side
signals. Only authoritative Auth/API/database enforcement protects
signed-in accounts reliably. A user-claimed trust/contact/status role
must never override a verified school-email denial.

Release preflight:
- Auth issuer verified and emits trusted `email_verified:true` claim;
- Auth callback actually denies school accounts and revokes sessions;
- no false positives for `powiis.edu.my.attacker.example` or unverified
  emails; forged Cookie/HMAC/IP and alternate host tested;
- each participating domain passes an end-to-end login test;
- signed denial Cookie injected and validated server-side; logout,
  privacy and human appeal are accessible;
- `SCHOOL_EMAIL_GATE_ENABLED=true` **only after** completing preflight.

No school email is stored by the signed denial Cookie and no extra
fingerprinting/device-identity method is added by this change.

## 3. GPS campus gate — staging only, not an official boundary

Two draft OSM center points:
- Tanjung Bungah `5.46113, 100.28420`, farthest *checked* point
  111.76 m; OSM node 7394089600 remains unverified.
- Balik Pulau `5.36770, 100.21995`, OSM-derived farthest vertex
  about 129.78 m.

A 180 m test circle is an engineering **estimate**, not a certified
school perimeter and could encompass residents, streets and visitors
off campus. Do not use it to deny production customers.
Use isolated staging secrets with explicit, voluntary browser
Geolocation permission. No precise GPS in cookies, KV or analytics.

Production requires verified complete polygons, point-in-polygon with
accuracy uncertainty buffer, privacy/minors impact review, an alternate
manual challenge/appeal, spoofing and device/browser simulations,
and explicit location-decision audit. Browser GPS alone does not
prove a person's school identity or prevent proxy/GPS spoofing.

Keep `GPS_GATE_ENABLED=false` on production.

## 4. Jingxin photo — private R2 migration

The `/jingxin` story text remains publicly readable, but private
photos are currently **not** guaranteed private. Existing
`vyncuslim/vv` assets include:

- `assets/jingxin-memory.jpg`
- `assets/jingxin-memory-hq.avif`
- `assets/mce-kuala-lumpur-real.webp`
- `assets/.jingxin-hq/part-00.txt` and `assets/.jingxin-hq2/*`
- any Vercel/preview, Cloudflare CDN, repo history, copied/derived images

Provision a private bucket, for example:

```sh
npx wrangler r2 bucket create vynalth-jingxin-private
```

Upload only appropriately authorized originals via Wrangler **after**
confirming their exact local source files and cryptographic hashes:

```sh
npx wrangler r2 object put vynalth-jingxin-private/jingxin/shared-memory.jpg --file ./private-originals/shared-memory.jpg --content-type image/jpeg --remote
npx wrangler r2 object put vynalth-jingxin-private/jingxin/mce-kuala-lumpur-real.webp --file ./private-originals/mce-kuala-lumpur-real.webp --content-type image/webp --remote
```

Then bind the actual bucket on the *existing* Worker (never expose
public `r2.dev` or a public custom-domain endpoint):

```toml
[[r2_buckets]]
binding = "JINGXIN_PRIVATE_MEDIA_R2"
bucket_name = "vynalth-jingxin-private"
```

Important: **NO R2 provisioning or upload has been done by this PR**.
Do NOT delete existing photo files before verifying a complete private
backup and integrity. Then remove/restrict all public static copies
and thumbnails from deployed Vercel/public CDN and invalidate permitted
caches and reachable previews, test bypass on every origin and
subdomain; previously downloaded copies cannot be revoked.

Worker code now intercepts known legacy asset paths **once private
media is explicitly enabled**, without falling back to the public
Vercel origin. It intentionally does not intercept the historical
paths while the feature is disabled, to avoid breaking the existing
site before safe migration.

**Route blocker:** the approved Worker `wrangler.toml` currently
contains `*.vyncuslim.com/*` but **NOT `vyncuslim.com/*`**. The
apex `https://vyncuslim.com/jingxin` cannot be considered Worker-
protected until the actual root route / origin ownership is
verified and configured. A wildcard does not cover the root.

Release requires private R2 objects present, binding valid, apex
routing verified, all old public URLs returning no image bytes,
and full HTTP GET, HEAD, Range, Cache, content-type, signed-session,
logout, forged/tampered Cookie, wrong-host, no-location, and failure
tests. Only then enable `JINGXIN_PRIVATE_MEDIA_ENABLED`.

Cloudflare docs:
- https://developers.cloudflare.com/r2/api/workers/workers-api-reference/
- https://developers.cloudflare.com/workers/wrangler/commands/r2/
- https://developers.cloudflare.com/workers/configuration/routing/

## 5. Ordered release (never flip all flags together)

1. Back up source, run `npm test`, `node --check`, route parser,
   `npx wrangler deploy --dry-run` and verify CI green.
2. Provision consent KV and signing secrets; test live canonical
   SSO on a staging hostname without changing production.
3. Complete **Auth backend** school-email login denial and
   account/API-level enforcement, then enable the school gate behind
   a reviewed rollout on correctly routed hosts.
4. Migrate private original photos and backups to R2; prove all
   static-origin bypasses closed, add/prove apex routing, then enable
   private-photo service.
5. GPS enforcement only after authoritative perimeter and minors
   privacy/accuracy review; otherwise retain staging only.
6. Enable optional Cookie Consent in production only after positive
   and negative consent/browser tests and service notice review.
7. Canary host -> logged checks -> rollback triggers -> remaining hosts.
   Roll back by disabling the corresponding flag and redeploying
   the known-good Worker, not by weakening signatures or WAF.

Security tests MUST cover: tampered/bypassed SSO and denial Cookies,
wrong host, expired token, school trusted-role override, logout,
consent withdrawal, GPS spoofing/unreliable accuracy, campus polygons,
photo asset alias and source-origin bypass, R2 outage, preview URLs,
rate limits, repeat and cross-domain replay.

Cloudflare zone ownership, resources and production SSO issuer have
NOT been verified through a Cloudflare account connection in this PR.
No claim of 100% anti-bypass security is justified.
