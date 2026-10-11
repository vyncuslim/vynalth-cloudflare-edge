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

## 4. Jingxin photos — preserve existing ASSETS/chunks (NO R2)

The user explicitly selected **the existing non-R2 architecture**.

- The `vyncuslim/vv` repository and its **separate** Cloudflare Worker
  named `vv` own `vyncuslim.com/jingxin`.
- That Worker uses its existing `ASSETS` binding and reconstructs
  the original HQ AVIF from 8 Base64 chunks at
  `assets/.jingxin-hq2/part-00.txt` through `part-07.txt`.
- The `/jingxin` story stays public; the Worker checks the school
  IP/KV and signed school-browser Cookie **before fetching any image
  parts**. The admin session needs a signed one-hour first-party Cookie.
- NO Cloudflare R2 bucket, R2 binding, Supabase storage, or R2
  credentials should be provisioned.
- The dormant `JINGXIN_PRIVATE_MEDIA_ENABLED=false` module in this
  repository came from a previous R2 proposal and MUST remain disabled.
  Do not use it to handle `/jingxin`; `vv` already has its own route
  and the correct ASSETS-backed image logic.
- Specifically do NOT add `vyncuslim.com/*` to `vynalth-cloudflare-edge`
  without a route-owner review, because `vv/wrangler.jsonc` declares
  that apex route. Wildcard `*.vyncuslim.com/*` is separate.

Companion security patch and detailed no-R2 checklist:
https://github.com/vyncuslim/vv/pull/7

**Critical limit:** Public GitHub/preview/static `assets/` chunks and
originals may be retrievable without either Worker. Base64 splitting
is not encryption. Test direct origin, historical preview, GitHub asset
copies, Range/HEAD and all aliases; you cannot guarantee privacy or
retroactively revoke copies while the origin/public repository retains
unencrypted image material.

## 5. Ordered release (never flip all flags together)

1. Back up source, run `npm test`, `node --check`, route parser,
   `npx wrangler deploy --dry-run` and verify CI green.
2. Provision consent KV and signing secrets; test live canonical
   SSO on a staging hostname without changing production.
3. Complete **Auth backend** school-email login denial and
   account/API-level enforcement, then enable the school gate behind
   a reviewed rollout on correctly routed hosts.
4. Keep the existing `vv` ASSETS/chunks solution; deploy the signed
   admin-cookie fix only after Cloudflare secrets and all direct-origin
   photo bypass tests pass. Do NOT enable dormant R2 media mode.
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
photo asset alias and source-origin bypass, missing ASSETS part, preview URLs,
rate limits, repeat and cross-domain replay.

Cloudflare zone ownership, resources and production SSO issuer have
NOT been verified through a Cloudflare account connection in this PR.
No claim of 100% anti-bypass security is justified.
