# Anonymous Browser ID Bridge — VynLink ↔ ZoKivo (approved association)

## Scope

This feature **keeps** \`https://vynlink.xyz\` and \`https://zokivo.xyz\` as separate public websites. It does **not** redirect their home pages to another domain, synchronize third-party cookies, use fingerprinting/IP, or bypass browser anti-tracking.

The anonymous visitor initiates linkage at each host once, reviews a visible approval screen hosted as a first-party page at \`https://vynalthai.com\`, then approves. A signed grant is delivered as a URL **fragment** on the way back, stripped from the browser address before a same-origin POST. Each site retains its own first-party cookie and stores a *pseudonymous ID alias* in the existing \`CONSENT_KV\` namespace.

No Vynalth account or password is needed. **One deliberate approval on each target website is required**; there is no invisible cross-browser or cross-site association.

## Public user flow

| Step | First-party URL | Purpose |
| --- | --- | --- |
| 1 | \`https://vynlink.xyz/__vynalth/browser/bridge\` | Begin optional identity link from VynLink |
| 2 | \`https://vynalthai.com/__vynalth/browser/bridge?request=...\` | Show visible consent page; click Approve |
| 3 | \`https://vynlink.xyz/__vynalth/browser/bridge/complete#grant=...\` | Validate host, local browser cookie, host-only nonce, MAC, expiration; store alias |
| 4 | \`https://zokivo.xyz/__vynalth/browser/bridge\` | Independently request link for ZoKivo; approve again on central page in the **same browser profile** |
| 5 | \`GET https://vynlink.xyz/__vynalth/browser\` and \`GET https://zokivo.xyz/__vynalth/browser\` | After both approvals, \`globalBrowserId\` should be the same as the central ID |
| 6 | \`https://vynlink.xyz/__vynalth/browser/bridge/unlink\` | Confirm unlink; the site's root browser ID remains unchanged |

These are **paths under existing domain hostnames**, not redirects of the user's main website. Browser storage and anti-tracking restrictions may prevent or expire the association.

Before association, normal anonymous traffic receives an unrelated per-root signed \`globalBrowserId\` with \`scope: "first-party-root"\` and \`crossRootLinked:false\`. After approval, the central alias is visible with \`scope:"consented-cross-root"\`, \`siteBrowserId\` unchanged, and \`crossRootLinked:true\`. The browser ID remains *unverified hardware*, and is never an account identity or security-ban authority.

## Security and privacy properties

- \`request\` MAC is purpose-separated and binds destination hostname, locally signed browser ID, random nonce, and five-minute issuance time. \`grant\` MAC adds the central signed browser UUID and is host- and nonce-bound.
- Only \`vynlink.xyz\` and \`zokivo.xyz\` can participate as targets. \`vynalthai.com\` hosts the central approval screen.
- Central approval requires explicit \`consent=yes\` over **same-origin form POST** with valid \`Origin\` and \`Sec-Fetch-Site\`; it does not accept a silent cross-origin form or automatically forward ordinary site visitors.
- Callback grant travels in the fragment, not query / access-log URL; on the destination it is removed from history and submitted to the same origin by a static first-party script. Destination checks its own host-only HttpOnly nonce and HMAC-signed first-party Browser ID. Grants do not confer any authenticated action.
- \`CONSENT_KV\` stores revocable aliases without IP, User-Agent, fingerprint, location or account ID. Mapping keys include target host and local UUID; mappings expire after 90 days.
- Clicking Unlink removes the mapping and sets a root-scoped, Secure+HttpOnly \`__Secure-vyn_browser_bridge_optout=1\` Cookie immediately, preventing a stale KV replica from displaying the old cross-root alias in that browser. New explicit approval clears the local opt-out.
- If a browser blocks or deletes cookies, is in private mode, or changes browsers, no reliable hardware linkage or identity continuity is guaranteed. Chrome and Firefox remain independent unless separately, explicitly associated; they are **not proven to be the same physical device**.
- A current browser credential can be copied if stolen; HMAC prevents forging new valid tokens, but does not make a cookie hardware-bound.

**KV eventual consistency:** Different Cloudflare points of presence can briefly disagree on new links or deletion. The local opt-out cookie avoids displaying a stale mapping on the browser that revoked it. Cloudflare KV is not an atomic/strong-consistency grant ledger; do not use this feature for login, fraud decisions, security banning, entitlements or any action requiring guaranteed one-use semantics. For security-grade atomic redemption, use a Durable Object or a transactional database and an authenticated service exchange.

## Release and verification

1. Run \`npm test\` and the existing Cloudflare Worker dry-run. The associated pull request must be green.
2. Confirm \`ANON_BROWSER_BRIDGE_ENABLED="true"\`, \`ROOT_BROWSER_ID_ENABLED="true"\`, \`EDGE_DEVICE_ID_ENABLED="true"\` and the existing \`CONSENT_KV\` namespace binding in \`wrangler.toml\`.
3. Ensure a minimum 32-character Worker secret is available (\`EDGE_DEVICE_ID_SIGNING_SECRET\` or the explicitly approved derived key). Do not commit secret values.
4. **Cloudflare Workers Builds** is the only production deployment source for this repository. Existing routes are maintained in Cloudflare Dashboard. Do not add \`routes\` to \`wrangler.toml\` (duplicate-route failure 10020).
5. Confirm \`vynlink.xyz/__vynalth/browser/bridge\`, \`zokivo.xyz/__vynalth/browser/bridge\`, and \`vynalthai.com/__vynalth/browser/bridge\` reach the expected Worker. A 403/404/503, WAF denial or GPS denial is a release blocker to diagnose; do not silently bypass the rule.
6. In normal Chrome: open both target URLs one after another and explicitly approve each on the central page. Confirm both target JSON endpoints return identical \`globalBrowserId\`, but different \`siteBrowserId\`. Confirm both brand URLs are unchanged for their homepages.
7. In Firefox with clean storage: confirm no automatic Chrome identity or prior association appears; perform separate approval if desired. Confirm a browser with a shared-campus IP is not silently linked.
8. Attempt bad signature, wrong host, wrong nonce, expired grant, denied consent and cross-site POST; must fail without writing an alias.
9. Click Unlink; test current-browser result immediately, even if KV has a stale copy. Verify ordinary app sessions, WAF, security Device IDs, media protection and bot access are unchanged.

## Disable / rollback

Set \`ANON_BROWSER_BRIDGE_ENABLED="false"\` in the Cloudflare Worker environment and deploy. Existing per-root anonymous Browser IDs continue to work. Bridge requests fail closed and will not create new links or expose old aliases. KV data still expires after its own TTL; if a privacy incident requires immediate global deletion, purge the relevant keys through approved operator tooling.
