# Vynalth PHP Honeypot v3 — realistic decoys + Axiom correlation

## Scope and trust boundary
- 29 *explicitly allowlisted* PHP scanner paths on already assigned Worker routes.
- The older `/wp-admin/install.php` remains a hard `403` block.
- PHP configuration and filesystem content are static synthetic fixtures. They are
  **not production facts** and may never come from `process.env`, backend
  introspection, actual PHP, R2, Supabase, or any user-controlled request.
- PHP aliases reuse the full phpinfo-style page; other profiles use distinct
  management, database, backup, and file-browser layouts. Login fields remain
  disabled and no HTML form, JavaScript, fetch, or credentials are collected.
- HTML CSP disallows scripts, forms, outbound connections and framing.
- No new domain routes, redirects or WAF bypasses are configured.

## Direct Axiom security events
File: `src/axiom-honeypot.js`

The Worker can asynchronously send a fixed-shape event to the existing
`vynalth-security-logs` dataset via Axiom's documented edge endpoint:

`https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-security-logs`

It sends **only explicit PHP decoy visits and the known WP installer block**,
not every ordinary website request. Response status and the safe allowlisted
canonical path are logged. Telegram and existing origin threat telemetry remain
separate channels with independent success/failure.

Example fields: `_time, event, source, event_version, host, path, http_method,
status_code, action, trap, request_id, country, ip_source,
ip_attestation_status, origin_ip_verified, network_actor_id, actor_scope,
bot_claim, bot_verified, intrusion_verified`.

No raw source IP, query parameters, cookies, token, request body, user/device ID,
raw UA string or GPS are sent. `network_actor_id` is a
**daily-rotating, domain-separated HMAC of the network IP**, not a human identity.
Shared NAT/proxies can cause unrelated visitors to have one network actor ID.
If the source is the special Cloudflare cross-zone Worker proxy
`2a06:98c0:3600::103`, the actor ID is **NULL**, with
`ip_attestation_status=cloudflare_cross_zone_worker_proxy`.
No "origin verified" claim is made by the edge Worker.

User-agent names (such as Twitterbot) are explicitly marked _claimed,
never accepted as proof of a verified crawler. Bot Verification requires actual
Cloudflare Bot Management metadata when available.

### Required private configuration (NOT performed by the GitHub commit)

1. In Axiom, create an **ingest-only API token** for the existing
   `vynalth-security-logs` dataset. Do not use a broad personal token.
2. Bind it to the current Cloudflare Worker, **as a secret**:
   `npx wrangler secret put AXIOM_INGEST_TOKEN`.
3. Preferably bind an independent random 32+-byte
   `AXIOM_HONEYPOT_ACTOR_SECRET` via
   `npx wrangler secret put AXIOM_HONEYPOT_ACTOR_SECRET`.
   Without this, the previously configured `VISITOR_IP_SIGNING_SECRET`
   can be used with **domain-separated HMAC messages**; if both are missing,
   network correlation is disabled, but nonidentifying events can be ingested.
4. Only after the token exists, set
   `AXIOM_HONEYPOT_INGEST_ENABLED = "true"` in Worker
   configuration (or an equivalent protected deployment configuration).
   Committed default is **false** to avoid falsely claiming collection works.
5. Verify actual Worker production deployment and real Axiom response with
   `ingested=1, failed=0`, then query the dataset. Without this,
   code-level PASS is not production delivery proof.
6. For guaranteed delivery, add a durable Cloudflare Queue with retries / dead
   letters. Current `waitUntil()` is best effort and can be rate-limited.

### Investigation queries (set a narrow UTC time range in Axiom)

**5-minute suspicious sequences** (network-level, not individual identity):

```apl
['vynalth-security-logs']
| where ['event'] == "HONEYPOT_TRIGGER" and isnotnull(['network_actor_id'])
| summarize hits=count(), unique_requests=dcount(['request_id']), unique_paths=dcount(['path']) by ['network_actor_id'], bin(['_time'],5m)
| where unique_requests >= 5 and unique_paths >= 3
| top 20 by hits
```

**Inspect sequence** after obtaining the network actor hash:

```apl
['vynalth-security-logs']
| where ['event'] == "HONEYPOT_TRIGGER" and ['network_actor_id'] == "PASTE_EXACT_ACTOR_HASH"
| project ['_time'], ['host'], ['path'], ['http_method'], ['status_code'], ['request_id']
| sort by ['_time'] asc
| take 100
```

**Data quality**:

```apl
['vynalth-security-logs']
| where ['event'] == "HONEYPOT_TRIGGER" and ['event_version'] == "php-honeypot-v2"
| summarize events=count(), unique_requests=dcount(['request_id']) by ['host'], ['ip_attestation_status']
| top 20 by events
```

**Never automatically block** based only on a PHP URL hit or a network hash.
Require multiple paths and rates, verified benign-bot exclusions, and review.
An exact IP or network range should only be considered after separate WAF and
Cloudflare origin-provenance evidence, and manual approval.

## Telegram wording and benign redirects

- `www.vynalthai.com/robots.txt -> 301 vynalthai.com/robots.txt`
  is an expected canonical redirect, still `HTTP_REQUEST/INFO`.
- `Ip Verified: true` reflects **edge-provided header metadata only**,
  not cryptographic validation of the origin or a human identity.
- For the Cloudflare special cross-zone Worker IP, mark visitor attribution
  **unknown** and `Ip Verified: false`.
- A `Twitterbot/1.0` user-agent is a claim and must not be
  automatically treated as a verified crawler.
- Unrelated missing social preview image paths should be diagnosed against
  the real asset storage/build, never treated as proof of malicious scanning.
