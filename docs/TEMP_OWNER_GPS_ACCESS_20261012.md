# Owner access portal — no reusable credentials committed (2026-10-12)

## Repository visibility — verified

GitHub repository `vyncuslim/vynalth-cloudflare-edge` currently reports **`private:false`, `visibility:"public"`**. A publicly readable repository must not include the operator's plaintext access code or a reusable Cookie-signing secret.

This revision fulfills a code-based setup **without Cloudflare Worker Secrets**:

- Code verification uses a public **PBKDF2-HMAC-SHA256 180,000-iteration** salted one-way verifier. The entered owner code never appears as plaintext in source, page HTML, logs, or a runtime environment variable.
- The verified browser receives a **random 256-bit opaque session token** in a first-party `__Host-vynalth-owner-pass` Cookie with `Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=600`. The token itself does not contain reusable signing keys.
- `CONSENT_KV` stores **only SHA-256(token)-indexed, server-side** session records with 600-second expiry and a SHA-256 fingerprint binding the token to Cloudflare's originating IP, User-Agent, and hostname. The same stored expiry is checked server-side. Invalid/expired/moved sessions are rejected even when the client sends a forged Cookie.
- `CONSENT_KV` separately stores SHA-256(IP)-indexed failed login counters, with 5 incorrect attempts / 15-minute TTL. Set an independent Cloudflare WAF/rate limiting rule to help prevent distributed brute force.
- Code verifier fallback may be rotated by committing a new salt/verifier (neither contains the code itself); alternatively set **both** `VYNALTH_TEMP_ACCESS_CODE_SALT_HEX` and `VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX` to a new derived pair in Wrangler configuration. A partial/malformed override denies all code submissions.

## Operational prerequisites

1. The existing Cloudflare Worker `vynalth-cloudflare-edge` must have `VYNALTH_TEMP_ACCESS_ENABLED="true"`, configured in `wrangler.toml`.
2. Existing binding `CONSENT_KV` must point to the intended production KV namespace; missing KV gives HTTP 503 **and never bypasses GPS**.
3. The latest `main` Worker version must actually be deployed and active on `vynalthai.com/*`. A successful GitHub Action that says `Deploy Worker: skipped` is not evidence of a production rollout. Use Cloudflare Dashboard to check **Active Deployment**.
4. Test from a browser without a privileged SSO session:
   - GET `https://vynalthai.com/admin/121@121.1234.vynucslim` returns code form with CSRF cookie;
   - wrong code returns 403, fifth failure triggers next-attempt 429, expiration within 15 minutes;
   - correct operator code returns 303 to `https://vynalthai.com/` with 10-minute host-only HttpOnly Cookie;
   - allowed browser can access GPS-protected pages for at most 600 seconds; then reverts to regular GPS challenge;
   - application admin auth, Cloudflare WAF, independent school-IP restriction, private photos and all other protection are **not** waived.
5. Global KV is eventually consistent: recent sessions may be briefly unavailable from another Cloudflare POP. Such conditions deny access, they do not allow unauthenticated entry.

## Security constraints

- This portal is a **GPS-only temporary exemption**, never an application administrator login or permanent access mechanism.
- A public PBKDF2 verifier can be attacked offline. Rotate the code if shared, and prefer genuine account SSO + MFA for administrator access. The original operator code has already been disclosed in chat and should be rotated when convenient.
- Do not submit the plaintext code, session token or KV values to frontend JavaScript, GitHub, logs or chat.
- To revoke all outstanding sessions immediately: disable `VYNALTH_TEMP_ACCESS_ENABLED` and deploy. To revoke an individual session: delete its hashed KV session key.
- On misconfiguration, KV exception, invalid host, bad Origin, bad CSRF or missing client-IP authority, **fail closed**.
