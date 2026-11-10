# Vynalth Device ID — 10-domain rollout

## Scope and browser security

This feature issues separate, signed, first-party browser Device IDs for each
host served by the Vynalth Cloudflare edge Worker. It does NOT give one browser
a universal, secretly correlated identifier across unrelated root domains.

A host-scoped security cookie is HttpOnly, Secure, SameSite=Lax, Path=/ and
expires after 90 days. A valid signature is required on every verification;
the 30-day refresh retains the same UUID. HMAC keys are independently
derived for each hostname so one site's cookie cannot be replayed elsewhere.

There is no IP-based ID generation, geolocation tracking, fingerprinting,
cross-domain account association, third-party cookie or new centralized
data transmission. Client-provided Device IDs are never trusted as account
authentication or administrative authority.

## Domain coverage

| Domain | Canonical behavior | Identity implementation |
| --- | --- | --- |
| sleepsomno.com | Redirect to vynalthai.com | Main site's existing Device ID |
| vitamindai.online | Redirect to vynalthai.com | Main site's existing Device ID |
| vynalthai.com | App | Existing backend Device ID, unchanged |
| vynalthai.si | App | Host-scoped signed edge Device ID |
| vyncuslim.com | App | Host-scoped signed edge Device ID |
| vyncuslim.my | App | Host-scoped signed edge Device ID |
| vyncuslim.si | App | Host-scoped signed edge Device ID |
| vynlink.xyz | App | Host-scoped signed edge Device ID |
| vynli.xyz | Redirect to vynlink.xyz | Canonical VynLink Device ID |
| zokivo.xyz | App | Host-scoped signed edge Device ID |

Other web subdomains are eligible for independently signed, host-only
device identities if their requests actually traverse this Worker.

GET /__vynalth/device on an eligible host returns no-store JSON with the
current browser's own ID, signature verification state and hostname.
It does not expose another user's data, IP, GPS, token or cookie value.
A new signature sets the __Host-vyn_edge_device cookie. A second request
with this valid cookie reports signedAndVerified true.

The new endpoint cannot bypass WAF, school, GPS, application authentication
or the established Vynalth Device ID / 11-control backend.

## Required signing material

Feature switches:
- EDGE_DEVICE_ID_ENABLED=true
- EDGE_DEVICE_ALLOW_DERIVED_KEY=true

Preferred is a dedicated 32+ byte EDGE_DEVICE_ID_SIGNING_SECRET stored
only in Cloudflare Worker Secrets. Compatibility permits a *distinctly
derived host-scoped key* from the already configured
VISITOR_IP_SIGNING_SECRET; it does not reuse the original visitor-IP
HMAC key or signed message.

If no suitable secret is present, issuance is DISABLED. The status endpoint
returns HTTP 503 instead of issuing unverified IDs. No signing material
is committed to GitHub or wrangler.toml.

## Required production acceptance

Cloudflare Worker Routes are Dashboard-owned and intentionally absent
from wrangler.toml because redeclaring existing routes caused error 10020.
Having a root in managed-domains.js alone does NOT establish active routing.
Historical documentation names several wildcard patterns, but does not
prove apex routes or .my / .xyz are currently assigned.

1. Confirm vynalth-cloudflare-edge has the intended apex and wildcard routes
   under Workers & Pages > Settings > Domains & Routes. Do NOT delete or
   seize another Worker's routes; preserve Cloudflare-proxied DNS and mail.
2. Confirm Cloudflare Workers Builds successfully deployed main.
3. For each non-redirect domain, check GET https://HOST/__vynalth/device
   returns enabled:true and a new HttpOnly cookie. On a second request
   signedAndVerified should be true. Check x-vynalth-edge response header.
4. Confirm main vynalthai.com retains its pre-existing Device ID API
   and redirects never receive a duplicate cookie.
5. Verify DNS, origin forwarding, WAF, GPS, login, sensitive APIs,
   VynLink and ZoKivo account flows, plus privacy notices.
6. No claim of complete ten-domain production activation is justified
   until route, key, site and browser tests pass for every hostname.

The central Device Intelligence database is NOT automatically populated
by these separately signed edge IDs. Future account-linked federation
requires an authenticated and revocable opt-in; no anonymous cross-site
linking or IP-based attribution is permitted.
