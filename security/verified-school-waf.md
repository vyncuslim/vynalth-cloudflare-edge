# Vynalth Shield: verified school egress WAF — staged zone deployment

## Scope
Maintain public, anonymous access for ordinary Vynalth AI users. Deny only independently
verified and unexpired POWIIS school egress IPs; do NOT deny ASN 4788, TM, school-like
browser signatures, VPN customers, broad netblocks, or clients with unknown affiliation.

The same Cloudflare account-level IP List can be referenced by zone-level WAF rules.
Account-level WAF custom rulesets typically require Cloudflare Enterprise, so this script
handles each of the five configured zones separately.

## Inputs / prerequisites
- Cloudflare API token scoped to the intended account and zones, with **Account Filter Lists Read**, **Zone Read**, and **Zone WAF Read/Edit** as required by the list, zone verification and WAF rules endpoints. Never commit it.
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


## Owner-managed IP changes, 403 and automatic expiry
- The Vynalth Shield owner admin panel is added in frontend PR #37 and backend PR #51.
  It can add exact, evidenced, 1–12 hour IP entries via Cloudflare's Lists API and revoke
  only items tagged with its \`POWIIS|exp=...|ref=...\` ownership comment.
- Deploy five zone WAF rules with \`security/setup-verified-school-waf.mjs --apply\`
  only after all zone IDs and fresh approved list items are independently confirmed.
- On Cloudflare Pro or higher, set \`VYNALTH_WAF_CUSTOM_403=true\` to embed the static
  \`security/school-access-403.html\` multilingual Vynalth Shield HTML in a WAF Block
  custom response (max 2 KB). On Free, use the normal Cloudflare block page and still
  return HTTP 403. This installer will not mutate a pre-existing rule whose HTML differs.
- Cloudflare Lists **do not natively expire** items based on comment text. Hourly removal
  is therefore a distinct critical control in
  \`.github/workflows/school-egress-expiry.yml\` and
  \`security/reconcile-school-expiry.mjs\`. This workflow is NOT active while only on
  a draft PR. After merging to the default branch, configure the GitHub Actions
  repository secrets \`CLOUDFLARE_ACCOUNT_ID\`, \`CLOUDFLARE_IP_LIST_ID\`,
  \`CLOUDFLARE_API_TOKEN\`, allow scheduled workflows, and verify initial runs.
- The expiry script only deletes exact, marked, expired IP items; no broad or unmanaged
  IP entries are modified. Cloudflare bulk operations are asynchronous and at most one
  list operation per account may be outstanding; error conditions must be reviewed,
  never interpreted as successful revocation without a confirmed readback.
- Until the hourly cleanup is actually running, make short-lived school approvals only
  under direct owner supervision and revoke manually as soon as verification expires.
- The admin API **does not prove** each zone's WAF rule is deployed; it explicitly
  returns \`zoneRuleStatus: not_verified_by_this_endpoint\`. Verify the zone rules and
  HTTP 403 behavior independently before claiming full protection.
