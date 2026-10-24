# Security Monitor 2.0 — opt-in edge sensors (2026-10-24)

This review branch adds **ten low-interaction decoy routes** and real-response access telemetry to `vynalth-cloudflare-edge`. It DOES NOT make real login forms, database consoles, backups, PHP files or credentials available. No production deployment is implied by GitHub commits or a green CI run.

## Privacy and routing invariants

- Decoys have paths under `/__vynalth-hp/` only. They return HTTP **404**, `Cache-Control: no-store` and never touch origin. Disabled decoys do not intercept any request.
- Common external scans at `/.env`, `/api/.env`, `/phpinfo.php`, `/api/phpinfo.php`, `/.git/config`, `/wp-admin/`, `/xmlrpc.php` and `/backup.zip` are **observed only**; they continue to their original site handler without invented `REQUEST_BLOCKED` claims. WAF may independently block requests before the Worker and such events will not be visible here.
- Honeypot signals include the verified edge host, request ID, observed method, decoy classification, Cloudflare country/ASN when present, and HTTP 404 status **only for our own decoys**.
- No raw IP, cookies, Authorization, passwords, query parameters, entire user agents, coordinates, full request bodies or raw response bodies are sent. Optional `SECURITY_TELEMETRY_HASH_KEY` (Secret, 32+ chars) HMACs the Cloudflare-edge visitor IP into a daily pseudonymous `actor_id`. Treat this as pseudonymous personal data with an appropriate retention policy.
- Access events use actual HTTP response status (rather than WAF rule-creation status). Successful requests are sampled; 5xx responses are logged at 100%. `response_time_ms` is edge response time-to-headers, **not** full response transfer time or verified user latency.
- All Axiom writes use `ctx.waitUntil()`, so telemetry failure does not break the website. Monitor Axiom ingestion and request logs for loss; this is not guaranteed delivery.

## 10 active decoy routes

`/__vynalth-hp/admin/login`, `/__vynalth-hp/phpinfo.php`, `/__vynalth-hp/.env`, `/__vynalth-hp/.git/config`, `/__vynalth-hp/db-admin`, `/__vynalth-hp/api/internal`, `/__vynalth-hp/backup.zip`, `/__vynalth-hp/form-submit`, `/__vynalth-hp/token-check`, `/__vynalth-hp/hidden-link`.

The decoy form, token and hidden-link endpoints are **sensors only** in this phase. They do not deploy a fake login form, seed real tokens, or inject links into public pages. Their names describe the planned detection categories, not completed browser-side integrations.

## Setup and safe activation

1. In Axiom, create an **ingest-only API token** scoped to `vynalth-security-logs` and `vynalth-access-logs`. Dataset `vynalth-access-logs` already exists, but had **zero events in the observed 72h window** before this change.
2. In Cloudflare Worker `vynalth-cloudflare-edge` add Secret `AXIOM_SECURITY_INGEST_TOKEN`; optionally add unique secret `SECURITY_TELEMETRY_HASH_KEY` to enable daily pseudonymous actor IDs. Do not reuse token/signing keys from other subsystems.
3. After deploying this reviewed branch, set runtime Vars: `SECURITY_TELEMETRY_ENABLED=true`, `SECURITY_HONEYPOT_ENABLED=true`, `SECURITY_ACCESS_MONITOR_ENABLED=true`. A flag alone without a valid ingest token has **no effect**. `SECURITY_ACCESS_SAMPLE_RATE=0.02` is a starting suggestion; adjust for ingest quotas.
4. Verify on a **covered hostname**: (a) known normal page still works, (b) `/__vynalth-hp/.env` returns 404 without any credentials or stack trace, (c) passive probe `/api/phpinfo.php` produces the same HTTP result as before, (d) Axiom has rows with `host`, `event`, `request_id`, `trap`/ `status_code`.
5. Roll back immediately by setting `SECURITY_HONEYPOT_ENABLED=false`, `SECURITY_ACCESS_MONITOR_ENABLED=false` if an issue appears. Do not change GPS, consent, school restrictions or app auth as part of this rollout.

## Caveats and monitoring coverage

- Worker routes do not automatically cover every apex domain or application Worker, e.g. a separately deployed Vynova CDN. Do not label the fleet 100% covered. Check Cloudflare route coverage first.
- No Cloudflare WAF request is guaranteed to reach the Worker; use WAF logs separately for actual `REQUEST_BLOCKED` evidence.
- Use the Axiom monitor Worker in `vyncuslim/bug` for quiet aggregation and opt-in `NTFY_TOPIC_MONITOR` notification routing. Never claim ntfy Android delivery without device acknowledgement.
- The system is not itself evidence that a genuine compromise occurred.

## Axiom starter APL queries

```apl
['vynalth-security-logs'] | where _time > ago(72h) | summarize hits=count() by ['host'], ['event'], ['trap'] | top 30 by hits
```

```apl
['vynalth-security-logs'] | where _time > ago(72h) | summarize hits=count() by ['country'] | top 20 by hits
```

```apl
['vynalth-access-logs'] | where _time > ago(24h) | summarize requests=count(), p95=percentile(['response_time_ms'], 95), errors=countif(['status_code'] >= 500) by ['host']
```

All computed counts are **events**, not proven unique individuals. Sampled access logs are not exact complete site-wide counts; if estimating totals, account for `sample_probability` and separately report 5xx complete coverage.
