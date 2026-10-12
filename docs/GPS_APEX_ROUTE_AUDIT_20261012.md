# Apex-domain GPS routing fix — 2026-10-12

## Root cause

The live/source `wrangler.toml` previously routed only `*.vyncuslim.com/*`, `*.vyncuslim.si/*`, and `*.vynalthai.si/*`. Cloudflare wildcard subdomain Worker routes do **not** cover the zone apex. Thus `vyncuslim.com`, `vyncuslim.si`, and `vynalthai.si` could load their Vercel-hosted websites without entering `vynalth-cloudflare-edge`'s GPS middleware. `vynalthai.com/*` already had explicit apex coverage.

## Requested change

Add **only** three explicit apex routes to the existing Worker:

- `vyncuslim.com/*` (zone `vyncuslim.com`)
- `vyncuslim.si/*` (zone `vyncuslim.si`)
- `vynalthai.si/*` (zone `vynalthai.si`)

This increases the route validator from 8 to 11 routes, without touching unrelated apexes `sleepsomno.com`, `powiismunc.com`, or `vitamindai.online`. It does not change DNS, origin, cookies, site UI, or SSO.

## Production ownership audit — required before merge/deploy

Older Worker configuration deliberately reserved other apex hostnames to avoid disturbing independent Cloudflare Workers. The GitHub connector can verify code routes but **cannot** list or inspect the current Cloudflare account's route ownership. Do not enable these three new apex routes blindly if any of them has a different live Worker or a more-specific route which would be displaced.

In Cloudflare Dashboard:
1. For each of the three zones, inspect Workers Routes for exact `<apex>/*` and competing patterns. Record existing route owners. Do not delete or replace any unrelated Worker without its own migration plan.
2. Verify the DNS zone is proxied (orange cloud) and traffic truly reaches Cloudflare. Vercel project/domain verification alone is insufficient.
3. If a competing Worker is active, move this GPS logic into that route's current Worker via a service binding or an approved chained design instead of replacing the route blindly.
4. If no conflict exists, merge and deploy the reviewed route additions, then inspect the **active** Cloudflare Worker version.
5. Verify each of these paths from a Malaysian-IP test: `https://vyncuslim.com/__shield/gps/status`, `https://vyncuslim.si/__shield/gps/status`, and `https://vynalthai.si/__shield/gps/status`. They should return JSON containing `enabled: true`, `enforcing: true`, `policyRevision: gps-inner-boundary-403-v2`, and `regionalPolicy.enabled: true` if the GPS secrets are deployed and the routes actually reach the Worker.
6. Check anonymous browser navigation. As designed, sibling sites redirect via `vynalthai.com` for a GPS recheck and then return to the original pathname; a legitimate `CAMPUS_RESTRICTED`/ `CAMPUS_BOUNDARY_UNCERTAIN` result must never mint a signed outside permission.
7. Verify certified `trust/contact/status` identity exemptions and public legal/auth/recovery routes still work; verify original page content and other Workers were not displaced.

### Expected limitations

- A GitHub CI success or a Cloudflare **Build** success does not alone prove deployed route ownership or active GPS enforcement.
- The Cloudflare request country and browser timezone conditions are not reliable universal VPN detection.
- The OSM candidate polygons are not official property boundaries.
- A previously approved GPS status cookie does not remove the per-document GPS recheck rule for Malaysian visits.
