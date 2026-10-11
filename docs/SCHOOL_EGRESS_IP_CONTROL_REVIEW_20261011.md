# Vynalth AI — Temporary School Network Egress Restriction (Draft, 2026-10-11)

**Not deployed / NOT active.** Production `SCHOOL_EGRESS_BLOCK_ENABLED="false"`.
This feature detects and optionally denies the **observed public source IP** of the
Founder's phone on school Wi-Fi. It is a **network-level** restriction, not proof
that a visitor is a student. GPS can be spoofed and is shown locally only as a
non-authoritative location advisory.

## Architecture — three separate GitHub Draft PRs

1. Existing Cloudflare Worker `vynalth-cloudflare-edge`: first-party `GET /__shield/network/egress-ip` on `vynalthai.com` measures `CF-Connecting-IP`, signs a 120-second attestation when the server secret is available. It NEVER accepts arbitrary submitted IPs as the target.
2. Vercel auth backend: `POST /api/admin/school-egress/authorize` runs behind the existing Supabase `requireAdminRequest`, additionally requires founder/superowner, verifies that same Edge observation, checks same-origin and returns short-lived HMAC authorization. `POST /api/admin/school-egress/revoke` authorizes a recovery token.
3. Existing Edge Worker: `POST /__shield/network/egress-ip/block` verifies founder signature, first-party origin, **same current CF-Connecting-IP**, observation age and explicit `confirmedSchoolNetwork:true`. Records **only an HMAC digest of that IP**, timestamps and expiration in the existing `vynalth-consent-prod` KV namespace, under an independent `school-egress:current-v1` key. KV TTL=10,800 seconds (3h).
4. Every subsequent protected request on routes **actually assigned to this Worker** compares the observed source IP's keyed digest against the stored active digest and returns `403 SCHOOL_NETWORK_RESTRICTED` until expiry.
5. `POST /__shield/network/egress-ip/clear` accepts only a fresh founder-signed revocation token, can work even with blocking flag switched OFF, and deletes the policy key. Revocation may propagate with Cloudflare KV cache delay.
6. The mobile-only founder page `https://vynalthai.com/en/network-egress` checks IP, displays a GPS proximity advisory **without sending GPS coordinates to servers**, requires explicit Wi-Fi confirmation, and periodically revalidates **the same IP**. A changed IP pauses automatic restriction and requires founder reconfirmation.

## Known limits — DO NOT MISREPRESENT

- Shared public IP blocking impacts ALL users sharing that exit (including non-students). Students on mobile data, VPN, alternate ISP exit IPs, or IPv6 instead of a shared IPv4 may not be affected. Do not claim all students or all campus devices are blocked.
- Browsers cannot reliably determine Wi-Fi SSID. Neither IP nor client GPS proves school membership. Operator manual confirmation is required.
- A mobile website cannot perform guaranteed every-three-hours background work while closed or suspended. While tab stays running, it checks about every 2h55m and on resume; if offline or suspended at due time, expiry happens naturally. A native background service/managed on-site probe is needed for reliable unattended changes.
- This stores one active IP digest, not all campus NAT egresses. New IP replaces old; automatic refresh only happens while IP unchanged and founder session remains valid.
- Host coverage is limited to routes **actually assigned to `vynalth-cloudflare-edge`**. Existing `wrangler.toml` routes cover `vynalthai.com/*`, most `*.<domain>/*` routes, but NOT the apex of the other six domains. Do not claim full seven-apex coverage. Do not take ownership of zones/routes without explicit review.
- Server endpoints for first-party auth recovery, admin revoke/authorize, static assets, legal privacy and owner control UI are exempt from this particular temporary block to prevent irrecoverable lockout. Other independent WAF/Shield rules still apply. These exceptions mean this is not a literal all-path site outage.
- The active source IP is not placed in KV, but the operator's browser UI intentionally keeps a local history of observed IPs for up to seven days/24 entries. Clear history from the UI.
- During KV outage the restriction fails open; it does not lock the whole website.
- Rate limiting, alert logging and independent review are recommended before production. Edge status codes do not imply official POWIIS certification.

## Production activation gates (all required)

- Obtain independent authorization to operate site-level blocks, confirm route ownership for the exact hostnames. No GPS geofence certification is assumed.
- Review the three PRs, ensure HMAC protocol parity, including `observedAt`, `expiresAt`, `proof`, `authorization`.
- Generate an **independent** strong random key, `SCHOOL_EGRESS_SIGNING_SECRET`, and set its **same secret value** in the **traffic-serving** Cloudflare Worker and Vercel backend Production. Never print, publish, or expose it in `VITE_*` variables. Do not repurpose SSO / GPS secrets.
- Ensure the existing KV namespace `f687e465ac0441d7a6ca18aaa9ed91f8` is attached as `SCHOOL_EGRESS_KV`. This does not require creating another KV namespace or overwriting Consent keys.
- Deploy reviewed backend, frontend, and Edge versions with a human-monitored rollback plan.
- Explicitly enable **both** Cloudflare `SCHOOL_EGRESS_BLOCK_ENABLED="true"` and backend `SCHOOL_EGRESS_APPROVAL_ENABLED="true"` only after dry-run and staging acceptance.
- From an authorized founder test account, connect to a controlled test network, verify actual CF IP, authorize short TTL block and verify 403 on website protected pages from the same IP. Verify mobile/cellular switch does NOT cause automatic block. Test 3h expiry and emergency revoke. Other normal origin routes and WAF must remain safe.
- Deploying code / passing CI does **not** enable the feature. Do not auto-merge or deploy this Draft PR.

## Explicit rollback

Immediately disable backend `SCHOOL_EGRESS_APPROVAL_ENABLED` and Edge `SCHOOL_EGRESS_BLOCK_ENABLED`, then use owner-authorized `/revoke` and Edge `/clear`. Verify the KV policy is deleted and the same source IP can access a normal protected page. KV eventual consistency may delay propagation. Existing Cloudflare WAF IP Access Rules are unrelated; this mechanism never creates such a rule.

## Coexistence with SSO/GPS Draft PR #10

This network feature is developed from `main` in a **separate branch** and will need a normal merge/rebase conflict review of `src/index.js` and `wrangler.toml` if combined with Draft PR #10. Do not replace SSO/GPS changes by overwriting one branch with another. `GPS_GATE_ENABLED` remains `false`; GPS advisory on the founder page is not a production geofence.

## Browser-session continuity

The frontend stores the operator-confirmed active IP and TTL **only in localStorage** while unexpired, so reloading the admin page does not silently lose the renewal candidate. On every renewal it contacts the Cloudflare Edge again: if the actual observed source IP differs, the controller clears its local approval and refuses to arm the new network until the founder explicitly reconfirms. This does not guarantee background execution while Android suspends or kills the tab. No IP history, raw user GPS, or privileged session credential is placed into the Edge KV.

Existing independently signed `trust/contact/status` account exemptions remain in the optional Edge check; unverified user-supplied role/status fields never bypass it. This needs live browser acceptance on a controlled network before production.
