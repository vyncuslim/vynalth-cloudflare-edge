# Per-document GPS revalidation — October 11, 2026

## Required website behavior

With `GPS_GATE_ENABLED=true` and `GPS_RECHECK_EVERY_DOCUMENT=true`, every normal top-level HTML navigation (including F5/refresh and reopening a page) calls the browser Geolocation API again before a guest can receive the protected document. Previously issued 15-minute OUTSIDE or 5-minute NEARBY cookies are still useful for assets and API calls but alone cannot authorize a new HTML document. Signed trust/contact/status exemptions and public auth/legal/status recovery paths remain unchanged.

- Uses `getCurrentPosition({enableHighAccuracy:true,timeout:15000,maximumAge:0})`; this requests a new platform location result but does not prove that hardware GPS measured the device (network positioning, spoofing and permission reuse remain possible).
- Site visitors who have already granted permission generally **will not get a second browser permission popup**. They still get a new geolocation read on every protected document load.
- INSIDE => 403 with no new cookie and existing first-party permission cookie cleared. DENIED/UNAVAILABLE => 403 challenge/retry. Clearly OUTSIDE => original 15-minute signed allow; uncertain near the OSM mapped boundary => 5-minute signed nearby allow.
- The successful browser verification returns a short-lived, host-and-path-bound navigation ticket; the client navigates once using the `__vynalth_gps_visit` URL query parameter. The Worker checks the ticket and its signed cookie and marks the random token as consumed in the existing `CONSENT_KV`, without writing location coordinates. Refreshing that same URL returns to GPS verification. No `location.reload()` loop.
- When crossing to another first-party root, the site redirects to `vynalthai.com/__shield/gps/recheck` regardless of prior cookies. The hub requires another GPS sample and issues a separate signed, one-use freshness cookie before the bridge can transfer a verdict. The original pathname is retained, while query parameters are deliberately NOT transferred, to avoid leaking query secrets between roots.
- Successful protected HTML responses set `Cache-Control: private, no-store` and `Referrer-Policy: no-referrer`.

## Operational requirements and limits

- Cloudflare deployment must have the real `GPS_GATE_SESSION_SECRET`, a working `CONSENT_KV` binding, valid candidate polygons and the specified Worker routing. Without the secret, `GPS_CONFIG_ERROR_ACTION=bypass` can disable GPS; without a working KV the new proof issuance fails with a clear 503 JSON error and does not issue a bypass token.
- Cloudflare Workers KV is eventually consistent and does **not** offer atomic consume-once guarantees across PoPs. Replays in a cross-region propagation window remain a limitation. For stronger guarantees, move consumed-token state to a Durable Object with atomic storage.
- KV will incur one write per consumed navigation ticket and another write for a consumed cross-domain freshness ticket. Monitor KV write quotas and cost.
- Some back/forward cache restorations, embedded WebViews and service workers can restore existing content without a new document request. This system enforces new GPS when a protected request reaches the Worker; absolute detection of every UI state change requires additional native/client instrumentation.
- The site is not guaranteed to identify a school member or detect GPS spoofing. OSM candidates are not official boundaries; the 30-metre additional tolerance remains a recommendation.
- Production GitHub Actions may report success while the Deploy Worker step is skipped because Cloudflare credentials are not configured; do not claim the live site is enforcing this until the Cloudflare production version, signed status and real-browser F5 behavior are verified.

## Manual acceptance checklist

1. Visit a protected `vynalthai.com` HTML page as a guest. The location check must appear on initial navigation.
2. Approve precise location outside restricted polygons. It should navigate once without looping.
3. Press F5 within 15 minutes. A new location request should run even though an OUTSIDE cookie remains.
4. Reject permission. The protected document must stay unavailable with retry instructions.
5. Simulate confirmed INSIDE in an isolated test, not by falsifying production GPS. Expect 403 and no newly issued authorization Cookie.
6. Repeat on routed sibling domain: redirect to hub `recheck`, perform fresh GPS, import and return to the original pathname once. A second refresh must return to `recheck`.
7. Test malicious/wrong-path/replayed tickets, KV downtime, and trust/contact/status exceptions.
