# Vynalth AI location gate eligibility — Malaysia country/timezone (2026-10-12)

## Operator policy

The branded GPS location verification page is required when **either** Cloudflare identifies the visitor IP country as Malaysia (`request.cf.country === "MY"`) **or** the browser reports a Malaysian timezone (`Asia/Kuala_Lumpur`, `Asia/Kuching`). When the IP country is missing, unknown (XX), or Tor (T1), GPS remains required (conservative default).

Foreign country IPs first see a lightweight dark-themed **Checking regional access** screen that reads the browser's timezone with `Intl.DateTimeFormat().resolvedOptions().timeZone`. **It does not request GPS**, and it POSTs only the timezone identifier to `/__shield/gps/region-check` with an origin check. The Worker mints a short, HttpOnly, host/IP/country-bound HMAC cookie (120 seconds) for either `required` or `foreign`, so browser claims cannot simply be changed by manually editing Cookie. Foreign IP + recognized foreign timezone skips GPS for the cookie TTL. Malaysian timezone forces the existing GPS checks and per-document refresh policy.

This country/timezone filter is **not authentication, a VPN detector, nor proof of location**. Neither browser timezone nor IP country is perfectly reliable; a person can change timezone or use a VPN. A visitor using an overseas VPN **while retaining Malaysia timezone** will be prompted for GPS. A VPN user with an overseas IP **and overseas timezone** cannot reliably be identified using these two signals alone. Claiming all VPN traffic is detected would be incorrect; an independent, licensed and verified VPN-IP classification service or suitable Enterprise-tier Cloudflare WAF managed list would be needed for additional coverage. Bot score/ASN alone should not be presented as a definitive VPN label.

## Protections and exceptions

- The existing 12-hour temporary IP deny remains in front of the GPS gate until its absolute expiration; country/timezone bypass does **not** remove it.
- Signed trust/contact/status identity exemptions and existing legal, consent and authentication recovery paths remain unchanged.
- Country must come from the Cloudflare request.cf property, never a client-supplied `CF-IPCountry` header.
- Unknown or invalid timezone => GPS required. If browser JavaScript is off, an unknown foreign visitor cannot complete the preflight; it must not silently open protected content.
- The signed regional claim binds country, host, and observed `CF-Connecting-IP`; changes to IP/country require a fresh decision. Signed metadata stores no GPS coordinates, and normal GPS cookies never contain coordinates.
- A short-lived foreign timezone verdict is accepted for 120 seconds. Browser timezone can change during that window; this is an inherent limitation of timezone-based policies.
- Exemptions do not override independent WAF checks or normal application auth.
- The regional policy only applies to hosts that actually route through `vynalth-cloudflare-edge`; not every registrable apex uses this Worker.

## Verification

Run Worker unit tests and Cloudflare dry-run. In Cloudflare production, compare behavior from:
1. MY IP + any timezone -> original GPS challenge.
2. Overseas IP + Malaysia timezone -> regional preflight then GPS challenge.
3. Overseas IP + overseas timezone -> regional preflight then normal content (without GPS).
4. Unknown ingress country, invalid timezone, and Tor -> GPS challenge.
5. Previously approved foreign cookie used from a changed IP or from Malaysia -> no bypass.
6. Trusted account, legal/privacy, public status and IP deny policy -> unchanged.

Successful Cloudflare Build is **not** proof of live deployment: review and verify actual Workers deployment, zones, and Browser Network traces. Do not put GPS coordinates in screenshots/logs.
