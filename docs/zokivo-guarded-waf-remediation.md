## 2026-10-17 CONFIRMED live rule configuration (owner's Cloudflare Edit Rate Limiting Rule view)

The **exact** enforcing rule `5704ae8e4b2a4460b4ad8d31a7353d4b` ("Vynova API edge rate limit") presently has:

- Match expression: `starts_with(http.request.uri.path, "/api/") and not cf.client.bot`
- Matching host restriction: **NONE** (this is the root cause; every `/api/` under the zone is counted)
- Counting characteristic: `ip.src` (IP); threshold: **20 requests per 10 seconds**
- Mitigation: **Block, HTTP 429, for 10 seconds**; enabled and first in order.
- A shared-IP 100-player room generates more than 20 requests in 10 seconds, so this rule blocks joins, answers and some room reads, regardless of application authorization.

### Lowest-risk manual correction for existing shared rule

**Change only the existing expression** to:

```text
starts_with(http.request.uri.path, "/api/") and not cf.client.bot and http.host ne "zokivo.vynalthai.com"
```

This preserves the rule's existing 20/10s IP rate limiting on all OTHER zone hostnames, including `vynova.vynalthai.com`; it removes just the mistaken match for ZoKivo. Do **not** change the shared rule's rate threshold, action, cooldown, or enabled state. The original protection of unrelated sites remains in force. Verify this is the exact rule with the ID above before saving.

**In the same change window**, create a SEPARATE rate-limiting rule targeting `http.host eq "zokivo.vynalthai.com" and starts_with(http.request.uri.path, "/api/rooms/") and not cf.client.bot`. Prefer Cloudflare's `IP with NAT support` counting characteristic (not `ip.src` in the same rule). Choose traffic limits from the measured legitimate request rate, with sufficient shared-IP / cookie-less fallback capacity for 100 devices; a single specific limit cannot be guaranteed without measuring polling frequency. Retain separate, tighter protections on login/session/API endpoints and all Cloudflare WAF + GPS policies. Visitors not accepting `_cfuvid` may share a counter. Cloudflare doc: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/

**CRITICAL:** The existing `scripts/remediate-zokivo-rate-limit.mjs` automated tool is intentionally **incompatible** with the live shared rule above: its guard only accepts a precisely ZoKivo-scoped match expression. Do not try to force it by bypassing its expression guard. Use the dashboard to split rules safely or develop a separately audited shared-rule migration.

**Status:** These are **instructions/documentation only**, not a deployed production configuration. Verify the actual saved expression and retest official-domain 100-player end-to-end before calling the issue resolved.

---

## 2026-10-17 CONFIRMED Cloudflare blocking rule

Cloudflare **Security Analytics → Events** export (500 sampled records, 182 matches) directly identifies the policy that blocked the 100-player ZoKivo answer waves:

- Rule display name: **Vynova API edge rate limit**
- Exact `ruleId`: `5704ae8e4b2a4460b4ad8d31a7353d4b`
- Event `rulesetId`: `56779882b35e4a3eb23af48fd9c38463`
- Enforcement: `source=ratelimit`, `action=block`
- Proven 2026-10-17 21:22:13 MYT, `20.171.3.39`, `POST /api/rooms/976802/answer`, Ray `a4bf9c5f9faa4896`.
- Matches in this partial export: 96 latest QA answers, 60 earlier QA answers, 25 earlier room reads, 1 latest QA join. **These are sampled records, not all requests.**

**CRITICAL:** The event export does **not** contain the rule expression, counting characteristics, period, threshold, or mitigation timeout. The name “Vynova API edge rate limit” does **not** establish that the rule is actually scoped to Vynova, and this export cannot establish which other hosts it could match. Do not run the guarded APPLY action until the exact rule configuration is read.

### Production administrator decision tree

1. Open Cloudflare `vynalthai.com → Security → Security Rules → Rate Limiting rules`; locate the exact Rule ID above. Inspect `expression`, `counting_expression`, `characteristics`, `requests_per_period`, `period`, `mitigation_timeout`, action, rule precedence and whether it is a zone or account-level ruleset.
2. **If shared or Vynova-intended:** preserve its original intent, narrow its scope with a reviewed hostname constraint so it no longer counts ZoKivo gameplay requests. In the *same maintenance change*, introduce a separately scoped ZoKivo gameplay limit (matching only `http.host eq "zokivo.vynalthai.com"` and `/api/rooms/` endpoints) with NAT-aware visitor characteristics where supported, and apply separate protections for login/host controls. Confirm the final rule order and no gap in protections; this cannot be achieved with the single-rule guard script.
3. **If the existing rule already matches only ZoKivo gameplay:** use `PREVIEW_ONLY` with its verified rule ID and approved read-only fingerprint. The guard is fail-closed if the expression is broader or more complex than its allowlist, and keeps thresholds unchanged when it changes `ip.src` to `cf.unique_visitor_id`.
4. Preserve school-location access decisions, original WAF, origin authentication, unauthorized-token rejection, 101st-player application 409 and duplicate-answer application 409.
5. After **confirmed deployed policy change**, test a fresh disposable room with 100 independent cookies and player tokens (including Cloudflare `_cfuvid`), joining and answering through the **official hostname**. Require 100/100 accepted answers and 100/100 validated settled scoreboards, and independently check negative security cases. **No current production acceptance PASS has been observed.**

Cloudflare reference: https://developers.cloudflare.com/waf/rate-limiting-rules/parameters/

---

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
