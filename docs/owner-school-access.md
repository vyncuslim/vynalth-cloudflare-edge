# Permanent owner-only campus access (account-based)

> Status: proposed in PR #40. Do not claim the feature is live until GitHub
> regression tests, production Worker deployment, and the real login issuer
> have all been independently verified.

This feature grants an **indefinite entitlement** to exactly one verified
Vynalth AI account, including when the account is physically at POWIIS. It is
not a non-expiring login session. The owner must be signed in, and their normal
SSO session must be valid and renewed by the Vynalth authentication backend.
Other school students are still denied by GPS / School IP Policy.

## Permanent access setup (recommended)

1. Identify your account's **immutable user ID** from the actual Vynalth AI
   authentication backend (e.g. the verified `auth.users.id` / SSO `sub`). Do
   not use the email address, display name, school IP, MAC address, or
   unauthenticated browser metadata. Never guess the user ID.
2. On a trusted computer, run
   `node scripts/owner-sso-fingerprint.mjs "<verified-user-id>"`.
   Copy its one-way fingerprint output.
3. Configure these **Cloudflare Worker secrets** on
   `vynalth-cloudflare-edge`:

   - `VYNALTH_OWNER_SSO_SUBJECT_SHA256` = generated 64-character hex digest
   - `VYNALTH_PERMANENT_OWNER_ENABLED` = `true` (default absent/false)
   - `CONSENT_SSO_SIGNING_SECRET` = same existing signing secret used by the
     legitimate Vynalth AI SSO issuer (must be >= 32 characters).

   Never put the SSO signing secret, live login tokens, or owner login credentials
   in GitHub or chat. The fingerprint is not an authentication credential.

4. **Required identity integration:** the Vynalth AI login backend must issue
   and refresh the existing `__Secure-vynalth-sso` cookie after verified login
   on `vynalthai.com`. Its HMAC-SHA256-signed base64url JSON payload must use
   `{sub,status,host:"vynalthai.com",exp,sid}`, with stable authenticated
   `sub`, valid session `sid`, and an expiry within 900 seconds of now.
   Cookie flags: `Secure; HttpOnly; SameSite=Lax; Path=/`. Do **not** make
   the cookie unlimited or issue it from the browser. Renew it via server-side
   authentication while the app login session remains valid. `signedSSO()`
   is a **validator**, not a login issuer; merely configuring the Worker
   is insufficient if the application has not implemented issuance/renewal.
5. Deploy the reviewed Worker. Sign out and in again on the real Vynalth AI
   account, then open `https://vynalthai.com/c`.

**Permanent means:** the account stays allowlisted until you revoke its
fingerprint or switch the feature flag off. The short-lived SSO cookie still
expires and requires normal reauthentication/renewal; this prevents stolen
cookies from granting access indefinitely.

**Scope:** only `vynalthai.com` on the Worker; other registrable domains and
school users remain blocked. Cloudflare WAF, separate abuse restrictions,
application authorization, and upstream services keep their rules.

**Emergency revoke:** remove `VYNALTH_OWNER_SSO_SUBJECT_SHA256` or set
`VYNALTH_PERMANENT_OWNER_ENABLED=false`. Rotate the SSO signing secret
and revoke identity-provider sessions if credentials are compromised.

---

## Optional temporary owner-code fallback (10 minutes)

The existing 10-minute owner portal is preserved for recovery or deployments
that do not yet issue server-verified SSO claims. It is not the permanent path.

# Owner-only access while on a restricted campus

The existing Vynalth AI owner portal grants a **600-second** GPS-only exception.
This patch adds a separate, **opt-in** exception to the School IP Worker, on
the exact host `vynalthai.com` only. Other school visitors remain blocked.

## Set up a unique code locally

1. In this repository, run `node scripts/generate-owner-access-code.mjs` on
   your own computer (Node.js 22+).
2. Save the printed **PRIVATE OWNER ACCESS CODE** in your password manager.
   Never paste or commit the code to GitHub or a public chat.
3. In Cloudflare > Workers & Pages > `vynalth-cloudflare-edge` > Settings,
   configure both generated values as Worker **secrets**:
   - `VYNALTH_TEMP_ACCESS_CODE_SALT_HEX`
   - `VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX`

   Use the exact lowercase hex values generated. Both are required.
   Existing code-based owner access may stop working once these are changed.

4. After the reviewed code is deployed and checked, add one more **secret**
   with name `VYNALTH_OWNER_SCHOOL_EXEMPT_ENABLED` and value `true`.
   Keep it absent or `false` to turn the school exception off.
   A fresh owner login **after** enabling is required. Existing GPS-only
   passes cannot be upgraded to a school pass by changing settings.

5. Open the existing portal at
   `https://vynalthai.com/admin/121@121.1234.vynucslim?return=%2Fc`
   and enter your new private access code. Your cookie is valid for 600 seconds
   on `vynalthai.com` on the same browser and source IP.

## Security boundaries

- Only exact-host `vynalthai.com` receives this exception. It does not cover
  the `www` host, related subdomains, or other company domains.
- All ordinary visitors remain subject to GPS and School IP Policy.
- Cloudflare WAF, separate 12-hour IP restrictions, and application login
  remain enforced. Being admitted through the edge does not log the owner in
  to Vynalth AI Chat.
- Never add a school public IP/subnet allowlist or trust user-provided headers.
- Do not use the static built-in owner-code verifier to enable school access.
- If the code is lost or suspected leaked, turn
  `VYNALTH_OWNER_SCHOOL_EXEMPT_ENABLED` off, rotate the verifier, and
  invalidate existing KV passes if immediate revocation is required.
- If the school IP is blocked by a Cloudflare WAF rule *before* the Worker,
  this patch does not bypass it; adjust WAF using authenticated Cloudflare
  Access or a similarly strong owner identity check, never a shared campus IP.

## Production deployment caveat

The GitHub Actions deploy workflow currently reports success even when its
`Deploy Worker` step is **skipped** due to missing GitHub secrets.
Cloudflare's own build separately failed after starting `wrangler deploy`.
Do not assume this patch is live just because GitHub CI is green.

Check the deployed version, `/c` and protected APIs in a real owner session,
then verify an ordinary school session still receives a denial.
