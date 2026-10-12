# SI apex GPS verification — rollout and rollback (2026-10-12)

## Confirmed source configuration gap

The previous Worker routes `*.vyncuslim.si/*` and `*.vynalthai.si/*` did **not** cover the apex websites. Vercel confirms both project domains are verified and the authoritative name servers are Cloudflare:

- `vyncuslim.si` → `dax.ns.cloudflare.com`, `magnolia.ns.cloudflare.com`
- `vynalthai.si` → `bill.ns.cloudflare.com`, `dara.ns.cloudflare.com`

The origin website was therefore accessible without invoking the GPS middleware even though the wildcard routes existed.

## Scope of this change

Add ONLY `vyncuslim.si/*` and `vynalthai.si/*` to existing `vynalth-cloudflare-edge`. Keep all original eight routes. Specifically **do not add `vyncuslim.com/*`** to this Worker; `vv` is the active owner and its GPS integration uses a separate Service Binding controlled by `GPS_EDGE_POLICY_ENABLED`.

Existing GPS region rules, cross-domain location hub and 403, private media, public build CSS/JS exemptions, canonical trusted account exemptions, and Telegram alerts are not changed.

## Operational checks before and after activation

1. In Cloudflare Dashboard, each SI DNS zone must be active and its apex DNS record must be **proxied** (orange cloud).
2. In each SI zone's **Workers Routes**, look for an existing exact `vyncuslim.si/*` or `vynalthai.si/*` owner. If any different Worker already owns an apex route, **stop deployment** and integrate GPS through a Service Binding to that Worker; do not displace it. Repo config and Vercel DNS data do not prove the live Cloudflare route ownership.
3. Confirm the GPS Worker has its production secret `GPS_GATE_SESSION_SECRET` and binding `CONSENT_KV`. Do not use frontend/Vercel secrets or publicly share signing keys. GitHub Actions `Deploy Worker` may skip even when builds succeed; check Cloudflare's **Active Deployment** and the actual Workers Routes.
4. Verify from the intended Malaysia test network:
   - `https://vyncuslim.si/__shield/gps/status`
   - `https://vynalthai.si/__shield/gps/status`
   Both must return JSON with `enabled:true`, `configurationAvailable:true`, `enforcing:true`, `regionalPolicy.enabled:true`, and `policyRevision:"gps-inner-boundary-403-v2"`.
5. Visit each root URL from a browser without prior GPS cookies. Expect a redirect to the centralized hub at `vynalthai.com` and the English GPS consent/verification flow; a valid outside verdict may return the browser to the original website. A campus-inside or school-side uncertain verdict must remain **403**, not mint a signed outside token.
6. Check `/assets/main-<hash>.js`, fingerprinted CSS, original Vercel pages, status/contact/trust, and login recovery. Requests for static build artifacts should never return GPS HTML; auth and private APIs must still be guarded where intended.

## Safe rollback

Restore the previous eight-route `wrangler.toml` configuration and redeploy the edge Worker **only after confirming route ownership**. Alternatively delete only the two newly added route assignments in the Cloudflare dashboard; do not delete the existing subdomain route patterns. Do not change `vv`, main `.com` domains, DNS, or Vercel aliases for this incident.
