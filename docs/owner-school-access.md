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
