# Device Federation v3 — production closure (2026-11-14)

## Verified facts and limits

- The Cloudflare Worker repository has the opt-in federation and global policy switches set to true in wrangler.toml. This does **not** prove every production hostname routes through it.
- Canonical frontend and backend show READY Vercel production deployments.
- Central Supabase project ojcvvtyaebdodmegwqan contains federation links, codes and control tables with RLS enabled. A 2026-11-14 read-only query found **0 active links, 0 total links and 0 canonical global control policies**.
- Earlier evidence reported a 404 at vyncuslim.com/__vynalth/device/link and a 403 at vyncuslim.my/__vynalth/device/link. Public network access was unavailable during this inspection; these are not fresh HTTP rechecks.
- Vercel production environment variable metadata returned 403 (insufficient permission); do not assume signing key parity and never print secret values.
- No web implementation can silently and durably identify a physical browser device across unrelated site roots. Federation uses explicit account consent and a host-bound, one-use pairing code.

## Non-invasive preflight

From this Worker repository, using Node.js 20+:

    node --test scripts/check-device-federation.test.mjs
    node scripts/check-device-federation.mjs
    node scripts/check-device-federation.mjs vyncuslim.com vyncuslim.my

The probe issues GET requests only. It does not retain returned Set-Cookie, store identifiers, authenticate, or claim any pairing. It verifies the Worker response markers, JSON device status, global enforcement flag and real consent page. A 200 alone is insufficient. A READY result is **routing preflight only**, not proof of federation.

| Probe result | Interpretation |
| --- | --- |
| NO_DEVICE_ROUTE / NOT_PROVEN_EDGE_RESPONSE | Intended Worker route absent or origin fallback |
| DENIED_BEFORE_OR_IN_WORKER | WAF/Access/GPS/application may be blocking; check security events |
| REDIRECT_BEFORE_DEVICE_HANDLER | Redirect prevents first-party consent handler |
| FEDERATION_OR_SIGNING_UNAVAILABLE | Required edge configuration is unavailable |
| DEVICE_STATUS_INCOMPLETE | Deployed endpoint does not report global policy enforcement |
| NETWORK_ERROR | DNS/egress/connectivity failed; cannot infer production status |

## Fix vyncuslim.com routing (previously 404)

1. Inspect the Cloudflare zone, proxied DNS record and the **actual Worker route/custom-domain assignment**.
2. Find any redirect, transform or Worker route matching /__vynalth/device and /__vynalth/device/link. Cross-origin redirects cannot preserve the source site's first-party cookie.
3. Assign the existing vynalth-cloudflare-edge Worker to those **minimum necessary routes only if they are unowned**. Its wrangler.toml deliberately omits routes due to past duplicate-route error 10020. Do not add broad wildcard routes or seize another Worker's paths.
4. Repeat the preflight for the exact hostname.

## Fix vyncuslim.my denial (previously 403)

1. Inspect Cloudflare Security Events using timestamp, hostname, path and Ray/request ID. Distinguish WAF, Bot Management, Access and application/GPS enforcement.
2. Correct only the relevant false-positive rule. Never disable site-wide WAF, IP security, GPS gates or CSRF protection. A narrow exception, if justified, should still preserve secure POST origin, Sec-Fetch-Site, host-bound one-use codes and signed backend assertions.
3. Re-run both GET checks. A challenge or 403 is not a PASS.

## Consenting browser E2E acceptance

Using a dedicated test account and test browser, not a real user:

1. Before pairing, each host should report accountLinked=false and scope=host-only. Separate anonymous hosts must remain unrelated.
2. At https://vynalthai.com/cn/security/device-link log in, select the exact host, explicitly consent and generate the five-minute single-use code.
3. In the same browser open https://HOST/__vynalth/device/link and submit the code via that page.
4. GET https://HOST/__vynalth/device should report accountLinked=true, scope=account-linked-global, and the same expected global ID for a second explicitly paired host. Host-specific local signed cookies remain distinct.
5. Verify wrong-host, replayed and expired codes fail; revoke one host and confirm stale global cookies no longer authorize linkage.
6. For a dedicated test identity only, verify canonical block, revoke, temporary_block and restricted policy enforcement on two hosts, while anonymous browsers, public assets and recovery flows remain correct.
7. Simulate central-status downtime for the test identity: known linked browsers should get a predictable 503; restore and monitor before release.
8. If linked production accounts unexpectedly receive 503, roll back GLOBAL_DEVICE_CONTROL_ENABLED to false and redeploy the established reviewed Worker configuration.

**Release gate:** Do not claim full multi-domain Device ID deployment without independently verified routing, consent, matching backend secrets, cross-host ID consistency, revocation and enforcement. Never infer physical hardware identity using IP, browser fingerprinting or hidden cross-site correlation.
