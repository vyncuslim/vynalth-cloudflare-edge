# School IP Volunteer Reporting — opt-in, no laptop required

## Purpose

The public route **https://vynalthai.com/school-ip-report** allows authorized volunteer classmates to help Vynalth Shield observe changing school internet egress IPs while physically connected to school Wi-Fi. The Cloudflare Worker receives the connection and records the **edge-observed public IP**, not an IP typed by a visitor.

A volunteer's checkbox is a **self-declaration only**; browsers cannot reliably attest which Wi-Fi SSID is active. Reports are **unverified leads, not authorization to ban an IP**. A malicious outsider could submit from a non-school network and claim school affiliation. No report ever alters a WAF List by itself.

### Routes

- `GET https://vynalthai.com/school-ip-report`: standalone accessible HTML with Chinese, English and Malay guidance. Does not require signing in.
- `POST https://vynalthai.com/school-ip-report`: opt-in report after the student confirms school Wi-Fi. Cloudflare Worker reads `CF-Connecting-IP` from its own edge request (does not accept client-supplied IP field), checks same-origin browser POST and body length, stores a daily per-IP candidate in KV. Up to four observations per IP/day, 72-hour sliding TTL; **no passwords, names, fingerprints or SSIDs**.
- `GET https://vynalthai.com/_shield/school-egress/candidates`: private read route secured by a long server-only bearer secret (minimum 32 characters). No browser token. Used by existing Owner API on production Vercel; never expose this secret to frontend JavaScript.

### Worker configuration (not currently configured)

Create a **new dedicated** Cloudflare KV namespace and bind it to `SCHOOL_EGRESS_REPORTS` in the `vynalth-cloudflare-edge` Worker (Cloudflare dashboard or checked-in environment-specific Wrangler config), then add a Worker secret:

- `SCHOOL_EGRESS_REVIEW_TOKEN`: unique random 32+ character secret.
- In the **backend Vercel project**, add `VYNALTH_SCHOOL_VOLUNTEER_READ_TOKEN` with the **same secret**, using encrypted server-side environment variables. Do not add it to `VITE_` variables or any source-control file.

Once the Worker, backend Owner API PR #51, frontend dashboard PR #37, KV binding, and secrets are deployed, the Owner School Access Control panel displays volunteer candidates marked **NOT VERIFIED**. The Owner must corroborate source network independently before using the existing audited, explicit-confirmation, MFA-protected `add_ip` action.

### Important Cloudflare WAF interaction

Any campus WAF deny rule MUST exempt **only** `vynalthai.com/school-ip-report` from the school-IP block so blocked classmates can still submit an updated candidate. The narrowly scoped, authenticated `vynalthai.com/__shield/campus-beacon` exception is separate. All other paths and hosts stay protected. Do not allow skip-all or bypass for `/api/*`.

The installer in `security/setup-verified-school-waf.mjs` contains the precise path carve-outs. If another zone-level or account-level WAF rule denies before the custom rule, check the actual precedence and allow equivalent strictly scoped access to the report page only.

### Data and reliability

- Consent-based collection; clearly communicate IP/time retention and purpose to volunteers. Only collect from networks/devices they are allowed to use. A teacher-confiscated mobile phone **cannot** be used unless lawfully returned and its use is permitted.
- Cloudflare KV TTL garbage-collects candidate records after 72 hours since the last submission; this is **not the same** as the separate verified IP List expiry reconciler.
- Friends can help even when the Owner's laptop is shut down; the Cloudflare Worker and KV persist on the edge. But new changes are only observed when **someone visits and submits**. No report means no new evidence.
- This design intentionally does not auto-block unverified report IPs, because doing so could deny service to ordinary Telekom Malaysia users. An authorized, always-on campus beacon with strong credential + replay protection can later support a separately approved automatic process.
- **No files in this draft PR are deployed to production by themselves.** Do not share the public URL with friends as a live service until Worker route and KV binding tests pass.

### Acceptance tests

1. Open route on non-campus Wi-Fi; GET renders but volunteer is instructed not to submit.
2. A consenting user on authorized campus Wi-Fi submits; Cloudflare KV creates a pending candidate with the observed public IP and 72-hour TTL.
3. Anonymous requests to private candidate route return HTTP 403.
4. Owner dashboard retrieves pending report from backend with server secret; another logged-in non-owner cannot.
5. No Cloudflare IP list item appears without a separate, MFA-authenticated Owner approval.
6. A verified campus IP can access the exempt report path but gets blocked on other protected paths; normal external users can access ordinary site routes.
7. Disconnect campus observations for >72h and confirm the pending record expires; separately confirm WAF list expiry and rollback behavior.
