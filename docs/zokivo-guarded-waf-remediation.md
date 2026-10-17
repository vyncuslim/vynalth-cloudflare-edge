# ZoKivo 100-player Cloudflare rate limit — guarded rule-specific remediation

This PR **does not change live Cloudflare settings by itself**. A matched WAF Rate Limiting rule must be located in **Security Events** (not general Traffic Analytics). The tested official-domain error was HTTP 429 prior to the Worker.

## Scope and safety
- Production incident at `zokivo.vynalthai.com`, ~2026-10-17 **19:55:02 MYT**, failed `/api/rooms/967651/answer`, example Ray `a4bf1caafefb98a7` source `64.236.144.96`; second read-only 429 from `158.23.27.2` ~19:57:27 MYT.
- Guard accepts only an **enabled, block-action, zone-level IP-counted rule** whose expression is **exactly limited to `zokivo.vynalthai.com` and `/api/rooms/`**.
- If actual offending rule is zone-wide/account-level, fail closed. **Split/review that shared rule manually** before any change; never weaken unrelated services.
- Patch changes only rate counter `ip.src` → `cf.unique_visitor_id` (Cloudflare IP with NAT support). Preserves request ceiling, counting window, mitigation timeout, expression, block action and custom response. Requires `cf.colo.id`. Never turns off GPS, school blocks or WAF.
- Cloudflare can issue the `_cfuvid` cookie when this characteristic is used. **Visitors without `_cfuvid` can still share one counter**. Distinct test sessions must retain *all* Cloudflare Set-Cookie values, not just `__Host-vynalth-region`. Browser-only QA may be needed.
- This change is relevant to the **one proven offending rule only**; other rule(s) could still issue 429.

## Operator procedure
1. In Cloudflare `vynalthai.com` **Security Analytics → Events** filter hostname, source IP `64.236.144.96`, time **19:55:02 MYT**, `/api/rooms/967651/answer`. Copy the enforcing **Rate Limiting Rule ID** and confirm it belongs to zone `vynalthai.com`, not an account-level shared rate ruleset. Confirm rule expression and characteristics.
2. If the matched rule is a shared zone-level rule or account-level rule, do **not** run apply. Review and split it with an administrator, preserving protection on all other hosts.
3. Set GitHub Actions secrets for repository `vyncuslim/vynalth-cloudflare-edge`: `CLOUDFLARE_ZONE_ID` and `CLOUDFLARE_WAF_WRITE_TOKEN` (dedicated, least-privilege **Zone WAF Write** scoped ONLY to `vynalthai.com`; also Zone Read for verification). Never paste token into chat or source.
4. Merge this PR after successful checks. In `Actions → Guarded ZoKivo NAT-aware WAF remediation → Run workflow`, select `PREVIEW_ONLY`, provide confirmed rate rule ID. The script reads the real rule and prints a SHA-256 fingerprint and before/after counter. **No write occurs**.
5. Review the proposed rule against real Security Events. Require production environment approval. Re-run with `APPLY_REVIEWED_ZOKIVO_RULE`, the exact Rule ID and the exact fingerprint. The script performs Cloudflare API dry-run, refetches current rule to prevent stale edits, PATCHes **only that one rule** and rereads to verify.
6. Start fresh disposable QA room; replay 100 distinct visitor sessions through official domain, preserve `_cfuvid` and region cookies, join → answer → in-round and settled scoreboard. Validate 101st player blocked, duplicates blocked, invalid tokens rejected, HTTP 429 = 0, and report P95/P99 across one shared IP and actual school devices. Do not claim success before this check.

## Limitations
- The expression allowlist is deliberately strict. Complex or generic rules will refuse automated edits; this is **intentional**.
- If the rate limit is account-level, or due to a managed provider rule, this zone-scoped procedure cannot repair it.
- Changing to NAT-aware counting alone may not solve all classroom load if cookies are rejected, threshold is below per-player request rate, or another rule matches.
- Do not use a request-supplied `x-player-token` as an independent WAF count characteristic without cryptographic verification: arbitrary forged values would evade quota.

References: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/ and https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/
