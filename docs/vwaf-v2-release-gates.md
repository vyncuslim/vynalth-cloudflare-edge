# VWAF v2.0 release qualification (RC1)

No claim of a certified enterprise WAF. The source, CI, deployment and independent qualification are separate gates.

## Scope and acceptance

| Gate | Target | Required evidence |
|---|---|---|
| Known attack prevention | >= 99% | Independently labeled holdout, representative route/body/protocol cases, including observational and unsupported cases as misses. |
| False positives | < 0.1% | Representative consented/redacted benign cases; report counts and confidence bounds, include free text, localization, uploads, callbacks and authenticated flows. |
| Inspection latency | P95 < 5 ms | CPU/wall time on actual runtime, report pure core, content and remote state separately; cold/warm, concurrent load. |
| Availability | 99.99% | Defined SLI and observation window (30 days), end-to-end checks including origin, not mere Worker deploy status. At 30 days error budget is 4.32 minutes. |
| Critical vulnerabilities | 0 known unfixed | Independent audit scoped to code, deployment, auth, origin bypass, parser differential, supply chain and incident response. Fix and retest. |

Use npm run vwaf:acceptance for the offline synthetic fixture report and npm run vwaf:release-gate for the intentionally blocked formal gate. No live attack traffic or real credentials. Corpus is not independent and does not estimate real protection. Advisory cases count as unblocked attacks. Production availability and independent audit are unverified (null) and cannot be declared passed by this tool.

## RC1 capability
- Existing core, state, evidence, alerts and static decoy unchanged. No new origins, routes, secrets, migrations or public console. Body inspection remains bounded, after rate denial, and restricted to reviewed APIs.
- Contracts from backend commit 0fb9f74407c69f584002726d225b04dbd91497fc: image prompt 1–2000 characters after trim and ratios 1:1, 16:9, 9:16. Reject only invalid strings/falsy prompt already rejected by handler. Query truncation, stricter types and other ambiguous parameters are advisory. Unknown fields remain allowed. No reading credentials, no general SQLi/XSS deny for text. Other API schemas and content types need route inventory and owner review. Schema admission skips unsupported framing/over-budget requests; origin validation remains essential.
- Portable Fetch middleware runs without CF globals, stateless, explicit host allowlist, application retains authorization. Validated with Node 22 tests; can embed in a Node, Deno, Bun or compatible runtime, but those other runtimes and distributed state/archival ports are not yet qualified. No automatic proxy or origin egress, no deployment outside Cloudflare.
- Signed intel envelope: Ed25519 verification, 64 KiB bounded payload, fixed schema, exact canonical address+host, expiry, caller-provided high-water mark, only advisory match. CLI verifies a locally obtained approved manifest; feed URL, trust key, protected persisted sequence and a scheduled ingestion pipeline are not provisioned. Never auto-block or attribute a person from a feed. Existing first-party behavioral signals and independently operated IP containment remain.
- Release gates not met: full OWASP Top 10 prevention includes application controls beyond WAF (broken access control, business logic, supply chain, cryptography, authentication, SSRF origin checks). Schema only selected routes. Full SQLi/XSS enforcement cannot be safely applied to arbitrary user text. Main backend identity integration, durable global cost budget, origin lockdown, independent external audit, full live automated response evidence and multi-cloud distributed deployment remain separate work. Third-party review skipped is not audit completion. Existing Telegram notification code and credentials untouched.

Schema response uses the reviewed backend error code and message; edge pre-validation can reject invalid data before the backend's authentication check. Non-JSON, malformed, unframed or budget-skipped bodies still require backend validation. The offline corpus counts an ordinary invalid enum separately from malicious scenarios; the benign variations are not independent samples or a confidence-bound estimate.
