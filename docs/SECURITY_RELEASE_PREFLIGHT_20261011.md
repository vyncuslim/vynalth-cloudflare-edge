# Vynalth AI security activation plan — 2026-10-11

**Status: staging-ready source, NOT production-enabled.**
Keep this PR out of `main` until all deployment blockers are resolved.
Do not disclose school students' email addresses, GPS coordinates, or
private photos in logs, analytics, client-visible errors or cookies.

## 1. Universal Cookie Consent — all seven domains (one Edge Worker)

**No R2 and no Supabase required.** The ONE existing
`vynalth-cloudflare-edge` Worker handles the seven registrable roots
and their subdomains:

- `vynalthai.com`
- `vyncuslim.com`
- `vynalthai.si`
- `vyncuslim.si`
- `sleepsomno.com`
- `powiismunc.com`
- `vitamindai.online`

Each root receives a **different first-party Cookie** with `Domain=<root>`,
`Secure`, `HttpOnly`, `SameSite=Lax`; sibling subdomains under the same
root can receive it. Browser standards do NOT permit one Cookie whose
Domain spans seven unrelated roots.

The Worker uses a single `CONSENT_KV` namespace. This stores
the consent categories, revision, timestamps and withdrawal history;
the actual browser Cookies are not stored literally in KV.

### What requires SSO?

**Local first-party Cookie Consent works for guests WITHOUT SSO.**
Guests can reject, grant, withdraw and manage choices at each domain.
Essential cookies continue to work even after optional rejection.

**Optional account-linked synchronization:** the canonical
`vynalthai.com` Auth backend can issue verified, host-specific signed
SSO assertions. After a separate explicit seven-domain sharing
acknowledgment, all seven roots can read one pseudonymous account
choice from Workers KV when the visitor signs in. The
`CONSENT_SSO_SIGNING_SECRET` is required only for this account-linked
feature; never create sessions from unverified browser claims.

**Explicit SSO-free guest synchronization:** guests who save their
choices on `https://vynalthai.com/__vynalth/consent` may click
the separate **Sync saved guest choices across all 7** button.
After a same-origin POST with a CSRF token and explicit notice, an
opaque, 180-second KV ticket carries a SNAPSHOT through six sequential
first-party redirects:
`consent.vyncuslim.com`,
`consent.vynalthai.si`,
`consent.vyncuslim.si`,
`consent.sleepsomno.com`,
`consent.powiismunc.com`,
`consent.vitamindai.online`.
Each target sets its OWN root-scoped Cookie and locally persists the
three optional categories. No SSO, third-party Cookies or persistent
shared guest identifier is needed. This is NOT automatic ongoing
background synchronization: after guest changes or withdrawals,
repeat the explicit synchronization. Do not promise instant global
revocation or strict one-time use from eventually consistent Workers KV.

**IMPORTANT ROUTE/DNS PREREQUISITE:** every `consent.<root>` host
MUST have Cloudflare-proxied DNS and match the existing
`*.root/*` `vynalth-cloudflare-edge` Worker route, and
`vynalthai.com/*` must reach the same Worker.
`vyncuslim.com/*` apex belongs to the separate `vv` Worker in its
own repo; do not take over its route or break photo ASSETS.
The Consent endpoint at `consent.vyncuslim.com` sets a
`Domain=vyncuslim.com` first-party Cookie for the root and siblings.
Actual route ownership, DNS, host authority and settings MUST be tested.

### Real bindings and secrets, on the existing Edge Worker

Create a real Cloudflare KV namespace; bind it as `CONSENT_KV`
(the returned namespace ID must be copied into `wrangler.toml`):

```toml
[[kv_namespaces]]
binding = "CONSENT_KV"
id = "<REAL_ACCOUNT_KV_NAMESPACE_ID>"
```

Add **unique independent high-entropy secrets**, not committed to Git:

```sh
npx wrangler secret put CONSENT_COOKIE_SECRET
npx wrangler secret put CONSENT_SSO_SIGNING_SECRET
npx wrangler secret put GPS_GATE_SESSION_SECRET
# Optional ONLY when the separate trusted-account GPS status
# issuer exists and you need account exemptions:
npx wrangler secret put GPS_ACCOUNT_STATUS_SECRET
```

`CONSENT_COOKIE_SECRET` protects first-party anonymous Cookie
identifiers, CSRF/link state and guest transfer signing state.
`GPS_GATE_SESSION_SECRET` signs 15-minute host-specific location
allow/block outcomes. A GPS API key or Google Maps key is NOT required:
the browser uses its standard Geolocation API and explicit permission.
`GPS_ACCOUNT_STATUS_SECRET` verifies an OPTIONAL trusted status
Cookie and is not needed for normal guest GPS verification.

Each secret should be generated as a different random 32-byte
(or stronger) value; never copy secret values into GitHub,
logs, public env variables, screenshots or chat.

**Always separately validate** verified school email restrictions,
cross-domain SSO, CSRF rejection, wrong-host replay, opt-in choices,
denial/withdrawal, first-party top-level redirects and
Safari/Firefox/Chrome cookie restrictions before enabling Consent.
Only set `CONSENT_CMP_ENABLED=true` after real KV, DNS, SSO
(if account-linking is enabled) and browser acceptance tests pass.
Keep `GPS_GATE_ENABLED=false` until the school boundaries are
verified, regardless of whether Consent is ready.

Workers KV is eventually consistent (up to 60 seconds or longer
after cached reads); it is not transactional. If immediate global
withdrawal is legally required, add a serializing Durable Object
or authoritative revocation coordinator rather than pretending
KV can enforce it. Review 365-day event retention and minors/privacy
requirements before production.

Cloudflare docs:
- https://developers.cloudflare.com/kv/concepts/kv-bindings/
- https://developers.cloudflare.com/kv/concepts/how-kv-works/
- https://developers.cloudflare.com/workers/configuration/secrets/

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
Geolocation permission. In the staged code, guest GPS only requires
`GPS_GATE_SESSION_SECRET`; the separate account status key is optional.
An enabled but malformed GPS configuration returns 503 instead of
silently passing the request. No precise GPS in cookies, KV or analytics.

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
2. Provision one consent KV namespace and signing secret on existing Edge;
   configure all six `consent.<root>` hosts with proxied DNS; test
   anonymous guest first-party handoff on staging. Test optional
   canonical account SSO separately without changing production.
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
