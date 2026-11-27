# Vynalth WAF Core v1.0.0

First-party request inspection in the existing edge Worker, independent of the provider's managed signatures and attack score. Cloudflare remains the hosting, DDoS and outer WAF layer; the new module is portable JavaScript using Fetch/URL APIs.

## Scope and behavior

- Exact host rollout: vynalthai.com and search.vynalthai.com only.
- Initial mode: observe. Explicit enforce mode blocks deterministic hard rules, not accumulated heuristic scores. Off/unknown configuration makes no changes.
- Rules: private SCM, credentials, runtime artifacts, non-PHP application paths, Search development paths, private diagnostics, unsafe methods and path control characters. Bounded SQL/script/file-inclusion query signals and traversal signals are observation only. Never rewrite URLs or inspect request bodies.
- At most two percent-decoding passes, 8 KiB path budget, 4 KiB query budget, 32 structured query pairs and 512 characters per value. These are inspection limits, not origin size limits; large inputs are observed and remain subject to existing protections.
- Structured privacy-safe event: fixed rule IDs, categories, score, mode, action, would_block, approved host and server correlation ID. No raw path, query, body, cookies, IP, fingerprint or device ID in this module's events. Existing edge logging is separate. No per-hit new external requests.
- Existing rate limits and signed-device controls run first; the new WAF runs before normal origin forwarding. Dedicated honeypots, signed drain endpoint and non-pilot hosts retain their original behavior. No change to Cloudflare configuration, access rules, route ownership, secrets or authentication.

## Acceptance and rollout

Run npm test and Wrangler dry run. Review exact commit and preview build; do not enable enforce before production observation/false-positive evaluation. Compare VYNALTH_WAF_DECISION by host, rule_ids and action; correlate only by server request ID. Stop on regression, set VYNALTH_WAF_MODE to off to disable only this layer. Existing managed WAF/auth remain active.

The v1 engine does not implement comprehensive OWASP body inspection, distributed DDoS mitigation, independent reputation feeds, automatic IP or device bans, or origin-bypass prevention. Integrations with the existing verified-device risk state, centralized policy and incident alerts require separate acceptance. A heuristic score is not proof of attack or intrusion. Never disable existing controls to force traffic through the new layer.
