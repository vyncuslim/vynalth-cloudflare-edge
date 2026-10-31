# Multi-domain Worker compatibility and telemetry inventory (2026-10-31)

The operator's Cloudflare Dashboard lists existing Worker route ownership for
the following **eleven** root domains. Code recognition is distinct from
Cloudflare routing and DNS.

| Root | Included in Worker host recognition | Security probe forwarding |
| --- | --- | --- |
| vynalthai.com | yes | yes |
| vynalthai.si | yes | yes |
| vyncuslim.com | yes | yes |
| vyncuslim.si | yes | yes |
| vyncuslim.my | yes | yes |
| sleepsomno.com | yes | yes |
| vitamindai.online | yes | yes |
| powiismunc.com | yes | yes |
| vynli.xyz | yes | yes |
| vynlink.xyz | yes | yes |
| zokivo.xyz | yes | yes |

For each root, the source code also recognizes subdomains **if requests reach
this exact Worker**. No new `routes` are inserted into `wrangler.toml`
because Cloudflare error 10020 occurred when deploying duplicate routes.

**Dashboard audit still required:**
- User's latest route list explicitly shows `vynalthai.com/*`, but not
  `*.vynalthai.com/*`; subdomain routing is **not verified**.
- User's route list displays `*vynlink.xyz/*` without a dot after the
  asterisk, which is not the conventional `*.vynlink.xyz/*`. Audit the
  stored pattern before claiming subdomain coverage; do not delete it blindly.
- No recent screenshot confirms every apex + wildcard (for example
  `powiismunc.com/*` or `*.powiismunc.com/*`).
- A Cloudflare WAF block **before** Worker execution is not observable to
  `src/threat-telemetry.js`. WAF security events need a separate authorized
  feed; never disable WAF just to collect them.

Security and privacy invariants:
- Keep existing GPS gate, school-policy checks, canonical main-site redirect,
  origin Host handling, private media and SSO protections unchanged.
- Extend the preexisting GPS bridge allowlist, but DO NOT expand consent/SSO
  shared-cookie domains (that remains a separate four-root consent policy).
- Only fixed suspicious probe path categories are forwarded. No full URL,
  sensitive path segments, IP address, cookie, body, user agent or credentials.
- The receiver is `https://vynalthai.com/api/security/ingest` and uses
  the same server-side Bearer secret, with no anonymous write grant.
- The receiving site must separately allowlist these eleven roots; its
  `THREAT_INTEL_ALLOWED_HOSTS` environment variable, if set, may be
  intentionally narrower than its default allowlist.
- No event delivery or database write is established by build success alone.
