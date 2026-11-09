# School IP Policy → Unified Edge Worker

This migration copies the **functions** of `website-block-by-school-powiis` into `vynalth-cloudflare-edge`; it does **not** copy Cloudflare account secrets or prove that Dashboard routes are assigned.

## Included functions

- Same seven-zone school network policy, IPv4/IPv6 validation, candidate observation, manual-only blocklist, temporary runtime activation and emergency OFF
- Existing `SCHOOL_IP_KV` namespace ID (no data migration); records `observed:*`, `blocked:*`, `student-report:*`, `policy:runtime-enforcement-v1`
- Admin login/session, CSRF checks, login throttling, adding/removing/listing blocked IPs and enforcement control
- Consent-based exit IP report and read-only IP diagnostics
- Isolated read-only health check
- Original GPS, Trust/SSO, Telegram and origin proxy modules remain unchanged

## Canonical endpoints (only on vynalthai.com)

| Old standalone route | Unified Edge route |
| --- | --- |
| `/admin/ip` | `https://vynalthai.com/admin/ip` |
| `/admin/ip/app.js` | `https://vynalthai.com/admin/ip/app.js` |
| `/admin/ip/api/*` | `https://vynalthai.com/admin/ip/api/*` |
| `/block-ip` | `https://vynalthai.com/block-ip` |
| `/ip-status` | `https://vynalthai.com/ip-status` |
| `/health` | `https://vynalthai.com/__vynalth/school/health` |
| `/` (302 to report) | `https://vynalthai.com/__vynalth/school` (302 to `/block-ip`) |

Do not reassign the site's root `/` or generic `/health` route; both belong to the main application.

## Configuration and deployment

`wrangler.toml` contains:

- `SCHOOL_POLICY_INLINE_ENABLED = "true"`
- `SCHOOL_MANAGEMENT_INLINE_ENABLED = "true"`
- `MODE = "observe"` (manual runtime enforcement can override)
- `SCHOOL_IP_KV` bound to the existing shared school namespace
- The original `SCHOOL_POLICY` Service Binding retained for rollback; only used when inline policy is disabled

**Do not copy secrets into the repository.** An authorized Cloudflare administrator must separately provision `ADMIN_IP_PASSWORD` (at least 12 characters) and `ADMIN_IP_SESSION_SECRET` (at least 32 characters) as **secrets on the Edge Worker**. The admin API correctly returns HTTP 503 if they are absent. Do not assume secrets attached to the old Worker automatically transfer.

The policy applies to the original **seven** root domains and their subdomains, not all eleven managed roots. An allowlist entry alone does not prove actual Cloudflare routing, DNS proxying or WAF behavior.

## Release acceptance and rollback

1. GitHub Actions must pass `npm test`, route configuration safety check and Wrangler dry-run; the added parity tests run against the in-process Edge entrypoint.
2. Verify the admin page's CSP response header, signed session/CSRF, login throttling, add/list/remove, emergency OFF and rate-limited ON using test IPs only.
3. Confirm `SCHOOL_IP_KV` and both admin secrets are bound to `vynalth-cloudflare-edge` in the Cloudflare Dashboard. Verify no other site's `/admin/ip`, `/block-ip` or `/ip-status` routes were taken.
4. Verify actual DNS/Cloudflare route assignments for each intended host, and test GPS Butterworth exemption, trusted SSO and public crawler behavior with the School Policy enabled.
5. Confirm manual block entries apply only while live enforcement is explicitly enabled and expire according to their TTL. Public volunteer reports **never** auto-block.
6. Verify logs and Telegram separately, including a confirmed delivery acknowledgement. Avoid logging raw IPs, browser GPS, cookies or credentials.

Rollback: set `SCHOOL_POLICY_INLINE_ENABLED = "false"` to use the original `SCHOOL_POLICY` Service Binding, and set `SCHOOL_MANAGEMENT_INLINE_ENABLED = "false"` to disable new admin/report endpoints. Keep the original Worker and its KV namespace until the release acceptance is complete. Cloudflare Dashboard routes are never changed by this PR.
