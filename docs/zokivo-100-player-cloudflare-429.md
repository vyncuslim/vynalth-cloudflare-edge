# ZoKivo 100-player Cloudflare HTTP 429 remediation — 2026-10-17

## Verified symptoms

- `https://zokivo.vercel.app`: 100/100 real API joins, 100/100 answer writes, 100/100 scoreboard reads successful against an isolated QA room.
- `https://zokivo.vynalthai.com`: 100/100 region handshakes, 100/100 joins, but 100/100 answers got HTTP 429 after a burst of joins.
- A separate read-only 25+25 request probe: first 25 returned expected HTTP 401; the next 25 returned HTTP 429 with `Server: cloudflare`, `cf-ray` present, `Retry-After: 10`, and no Vynalth Worker or Vercel response identifiers.
- Test rooms were marked finished; no real user data was deleted.

Evidence: [production game run](https://github.com/vyncuslim/ZoKiVo/actions/runs/39030491104), [read-only 429 probe](https://github.com/vyncuslim/ZoKiVo/actions/runs/39030638818).

## Required Cloudflare administrative action

1. Open Cloudflare Security Events for zone `vynalthai.com`, around **2026-10-17 11:55–11:58 UTC** (19:55–19:58 MYT).
2. Filter on host `zokivo.vynalthai.com`, HTTP status 429, and action Block / Rate Limit. Identify the **actual rule ID, source policy, rate threshold, time window, counting characteristics, and mitigation timeout**. A 429 before the Worker is evidence of an upstream rate limit, but is not sufficient to identify a specific rule.
3. **Do not disable all rate limiting, GPS, School Policy, bot protection, or Cloudflare WAF.** Do not whitelist a school public IP as a permanent universal exception.
4. If the offending rule counts by source IP only, account for 100 distinct classroom devices sharing a NAT IP. Where available (Business plan or higher), consider Cloudflare **IP with NAT support** (`cf.unique_visitor_id`). Verify plan availability in dashboard. Otherwise calibrate a narrowly scoped rate limit for the exact host + gameplay endpoints with a threshold high enough for 100 concurrent legitimate players and separate stricter rules for sign-in, password reset, session issuance, and suspicious unauthenticated calls.
5. If a zone-wide rule matches all subdomains, **do not simply increase its threshold**: that could weaken other Vynalth AI services. Instead split its scope so the existing protection remains unchanged for unrelated hostnames and sensitive routes. Change only the confirmed offending policy.
6. Preserve application authorization (separate host/player tokens), 100-player room limit, duplicate-answer protection, CSRF/origin validation, and geofencing decisions.
7. Validate 100 real simulated clients via `zokivo.vynalthai.com`: region check, join, 100 answers, scoreboards during/after a round, player 101 blocked, duplicates blocked, unauthorized requests blocked, tests with shared NAT and realistic mobile-network arrivals.
8. Log the new rule ID and tested threshold in the private admin change record. Do not commit API tokens or sensitive visitor data to this public repository.

## Optional safe audit

The read-only [audit workflow](../.github/workflows/audit-zokivo-waf.yml) can list zone-level WAF and rate limit *summaries* if you provide GitHub Actions secrets `CLOUDFLARE_WAF_AUDIT_TOKEN` and `CLOUDFLARE_ZONE_ID`. Use a least-privileged read-only token scoped to the `vynalthai.com` zone. It does **not** modify a rate limit or reveal credentials.

Cloudflare docs: [rate limits](https://developers.cloudflare.com/waf/rate-limiting-rules/), [rate counting characteristics](https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/), [Security Events](https://developers.cloudflare.com/waf/analytics/security-events/).
