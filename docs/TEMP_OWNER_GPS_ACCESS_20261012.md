# Temporary owner GPS access — 10 minutes (2026-10-12)

## URL and scope

- Exact portal URL: `https://vynalthai.com/admin/121@121.1234.vynucslim`
- Host: **vynalthai.com only**. This is a first-party, `__Host-` host-only Cookie and will not automatically work on `www`, `.si`, `vyncuslim.com` or other domains.
- Correct code -> 303 to `https://vynalthai.com/`, setting a signed **Secure, HttpOnly, SameSite=Strict, Path=/, Max-Age=600** Cookie.
- The server verifies HMAC, exact host, expiration not exceeding 10 minutes, and the original `CF-Connecting-IP` plus User-Agent before skipping **only the GPS gate** on subsequent page/document requests. The existing requirement to recheck GPS on every document remains in effect for everyone without a valid owner pass; after expiry it applies again.
- This pass **does not authenticate an application administrator**, mint SSO, bypass WAF, block/deny rules, school-IP policies, private photos, consent preferences, application RBAC, or other security middleware.

## Required production configuration (secret never checked into GitHub)

Two Cloudflare **Worker Secrets** on `vynalth-cloudflare-edge`:
- `VYNALTH_TEMP_ACCESS_CODE`: the owner-chosen new high-entropy access code (length >= 12). The code previously pasted into chat is exposed and should be **rotated to a new unique value** before deployment.
- `VYNALTH_TEMP_ACCESS_SIGNING_SECRET`: a separate cryptographically random secret (at least 32 bytes/characters, not equal to the access code). Do not reuse GPS signing or SSO credentials.

The **existing** `CONSENT_KV` binding is required for login throttling. It stores HMAC-derived per-IP attempt counters (5 failures per 15 minutes) and never the input code, full IP, precise GPS location, or signing key. For a global adversary with distributed IPs or concurrent requests, KV is not strongly consistent; configure Cloudflare WAF/rate limits for this exact URL for stronger protection.

After confirming both Secrets and `CONSENT_KV` in the **active production Worker**, change **only** `VYNALTH_TEMP_ACCESS_ENABLED` from `"false"` to `"true"` in `wrangler.toml`, deploy, and verify production route activation. It is intentionally disabled in GitHub by default; the portal will return 404 until the flag is enabled. Missing secrets/KV after enabling return 503 (fail closed).

## Testing

1. Unauthenticated GET on the exact path displays an English-only code form and an anti-CSRF cookie.
2. Wrong code returns 403; after 5 failures from one exit IP returns 429 with 15-minute Retry-After.
3. Correct code returns 303 to homepage, with host-only 600-second HttpOnly Cookie. Subsequent `/en/...` page requests within 600 seconds from the same network/browser skip the **GPS** challenge.
4. Cookie never grants access on any other hostname, on a different IP or browser User-Agent, or 600 seconds after issuance.
5. POST requires matching Origin and CSRF form token; forged cookie signatures are rejected.
6. Independently blocked school IP, separate WAF or application authentication remains blocked. E.g., a 403 from `SCHOOL_POLICY` must still be 403 even with this Cookie.
7. If the public site is blocked by the **earlier** temporary IP-restriction step, the portal is also blocked; this feature does not override it.
8. Existing `trust/contact/status` recovery continues; GPS status endpoint remains independent.

## Emergency rollback

Set `VYNALTH_TEMP_ACCESS_ENABLED="false"` and deploy, or rotate/remove the signing Secret. All previously minted owner-pass Cookies will stop working immediately after the rollback is active. No new routes, DNS, Vercel projects, account profiles or database tables are required.

## Note

This portal is a temporary GPS-only override, not a full replacement for admin authentication. A shared code alone is weaker than an existing account with MFA; consider migrating to canonical SSO admin + MFA.
