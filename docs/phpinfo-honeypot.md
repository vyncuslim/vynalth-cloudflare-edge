# PHP information decoy (`/api/phpinfo.php`)

The Cloudflare edge serves a **static simulated** phpinfo() page on the exact URL on hostnames already routed to the shared Worker. This is an isolated deception surface: no PHP runtime is invoked, no origin request occurs, no actual configuration is read, and no form submissions or JavaScript run.

- `GET` → 200 HTML. `HEAD` → 200, no body. Other methods → 405.
- Only the exact phpinfo URL (and normalized case/encoded separator variants) is handled; unrelated APIs are unaffected.
- The page's version, directories, loaded modules and directives are **fixtures**, never production facts. The page does not reflect query strings, headers, cookies, IPs, user agents, GPS or user identities.
- It ships with CSP, noindex, no-store, nosniff and referrer protections.
- One Cloudflare console event uses `HONEYPOT_TRIGGER`; existing Telegram warning logic recognizes the visit as `SUSPICIOUS_PROBE` even with HTTP 200.
- The existing threat-intelligence collector receives only the static path, host, method, timestamp, request/ray ID and response status; source=`honeypot`. Delivery requires existing secrets and is best-effort, not an Axiom/Telegram delivery guarantee.
- All upstream WAF and route controls remain effective. The decoy only works on the domain patterns actually assigned to this Worker and when not preblocked upstream. No WAF bypass or deployment route is created.
- Run `npm test` for contract checks; after Cloudflare Workers Builds deploys, verify exact-path GET, HEAD and POST in production, then confirm the console event and downstream telemetry receipt before marking done.

If you later want the PHP decoy disabled, remove the Worker handler and deploy the prior revision. Avoid exposing real `phpinfo()` anywhere.
