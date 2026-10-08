# Vynalth Shield: verified school egress WAF — staged zone deployment

## Scope
Maintain public, anonymous access for ordinary Vynalth AI users. Deny only independently
verified and unexpired POWIIS school egress IPs; do NOT deny ASN 4788, TM, school-like
browser signatures, VPN customers, broad netblocks, or clients with unknown affiliation.

The same Cloudflare account-level IP List can be referenced by zone-level WAF rules.
Account-level WAF custom rulesets typically require Cloudflare Enterprise, so this script
handles each of the five configured zones separately.

## Inputs / prerequisites
- Cloudflare account API token with least-privilege **Account Filter Lists Read**
  and **Zone WAF Edit** for the specified zones. Never commit it.
- \`CLOUDFLARE_ACCOUNT_ID\`, \`CLOUDFLARE_API_TOKEN\`
- Zone IDs verified in Cloudflare dashboard. Copy \`security/zone-ids.example.json\`
  to a private local JSON config and replace each placeholder. Set
  \`VYNALTH_CF_ZONE_MAP_FILE\` to its path. Do not commit that config.
- A DEDICATED account-wide IP list named \`powiis_verified_egress\` with kind=ip.
- Items populated by a separate owner-approved, auditable, short-TTL synchronization
  process, with a comment exactly \`POWIIS|exp=<ISO date>|ref=<approval ID>\`.
  Do not enable based on a months-old campus IP, an RDAP ownership guess, or ASN.
- The IP-list sync tool currently lives in \`vyncuslim/vv\` PR #5:
  \`scripts/powiis-waf-sync.mjs\`. It must be tested/merged separately.
  If no active approved school IP exists, this WAF installer refuses to enable.

## Dry-run — no network or credentials
\`\`\`bash
node security/setup-verified-school-waf.mjs
\`\`\`

## Explicit deployment, ONLY after reviewing the zone map and live IP list
\`\`\`bash
export CLOUDFLARE_ACCOUNT_ID=...
export CLOUDFLARE_API_TOKEN=...
export VYNALTH_CF_ZONE_MAP_FILE=/private/path/verified-zone-ids.json
export VYNALTH_WAF_CONFIRM=ENABLE_VERIFIED_SCHOOL_BLOCK
node security/setup-verified-school-waf.mjs --apply
\`\`\`

On apply, verifies list contents and TTL, verifies zone ID ↔ domain, reads each existing
WAF phase entrypoint, inserts only the specifically tagged exact-match rule, and aborts
rather than silently changing an unexpected existing rule. Staging is not atomic across
zones: if one zone fails, review each successful zone before retrying.

Rule:
\`\`\`text
ip.src in $powiis_verified_egress
\`\`\`
Action: \`block\`. Use Cloudflare WAF Custom HTML response where supported if branded
403 is wanted. The Worker 403 HTML does **not** render if WAF blocks first.
Normal Cloudflare Block responses are acceptable while the custom response is unavailable.

## Acceptance and rollback
1. Confirm the affected DNS entries are orange-cloud proxied by Cloudflare.
2. From a reverified campus egress IP, request each custom domain and API endpoint;
   expect 403 before any app content is delivered. Repeat for verified IPv6 if available.
3. From an unrelated Telekom Malaysia customer, verify public home, AI, Search and API.
4. Confirm Vercel generated *.vercel.app URLs have deployment authentication; check
   any shareable/bypass URLs and remove unnecessary exceptions.
5. Test backend rewrites and direct origins. Cloudflare WAF cannot protect a request
   which never visits Cloudflare; direct Supabase endpoints need their own authorization.
6. Keep admin rollback access on a trusted, independent, non-blocked route. To roll back,
   disable/remove this named WAF rule per zone (not unrelated rules) or revoke the
   verified entries using the separate IP List sync tool.
7. Monitor expiry. Cloudflare WAF lists do **not** auto-expire entries. Reconcile the
   approved registry frequently and remove expired entries promptly to limit TM IP reuse.
8. The five zones are those in wrangler.toml. If there are other Cloudflare accounts or
   additional zones outside this manifest, repeat the review; this is not automatic.

## What it does not do
This cannot identify all school members when they use a personal network, VPN or
unrelated anonymous account. Identity blocking requires a verified server-side school
organization claim or an explicitly confirmed restricted account. Do not infer identity
from a client header or user-editable Supabase user_metadata.
