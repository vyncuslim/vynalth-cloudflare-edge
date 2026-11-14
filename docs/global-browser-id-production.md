# Global Browser ID — Production Release and Verification

## Implemented and reviewed

- Anonymous, no account or user gesture, no install. On a routed managed root's HTTPS HTML 200 response, the edge sets a signed random first-party `__Secure-vyn_browser` cookie with `Domain=<managed-root>`, `Path=/`, `Secure`, `HttpOnly`, `SameSite=Lax`, and a 90-day maximum lifetime.
- Endpoint: `GET https://<routed-host>/__vynalth/browser` returns `globalBrowserId`, `scope: "first-party-root"`, `rootDomain`, `hardwareVerified: false`, `crossBrowserLinked: false`, `securityAuthorization: false`.
- Same root, same browser profile: browser sends the existing signed cookie to eligible subdomains; identity remains the same as long as the cookie persists. No root-to-root cross-site syncing.
- Separate root domains (`vynalthai.com`, `vynlink.xyz`, `zokivo.xyz`) and separate browser profiles necessarily have different anonymous IDs. No physical-device claim. No IP/fingerprint-based linking.
- Existing `__Host-vyn_edge_device`, `__Host-vyn_device`, and account-linked `__Host-vyn_global_device` remain unchanged and authoritative for their existing policies. GBID is NEVER an authorization credential or a global device block key.
- No responses on Cloudflare WAF-denied requests, un-routed hostnames, or origin failures. Existing security gates remain in place.

## Release procedure (Cloudflare credentials required)

1. Verify the reviewed `main` commit contains `src/global-browser-id.js`, its tests, the `src/index.js` handlers, and `ROOT_BROWSER_ID_ENABLED = "true"` in `wrangler.toml`.
2. Verify Cloudflare Worker secrets: `EDGE_DEVICE_ID_SIGNING_SECRET` (preferred, minimum 32 bytes), OR the explicitly approved `VISITOR_IP_SIGNING_SECRET` with `EDGE_DEVICE_ALLOW_DERIVED_KEY=true`. Never expose secret values in CI logs.
3. Deploy the reviewed `vynalth-cloudflare-edge` Worker through your **existing Cloudflare deployment workflow** or authenticated `npx wrangler deploy`. Wrangler project deliberately has NO `routes` setting due to existing duplicate-route error 10020. Do not add or seize DNS/routes during deployment.
4. Check Dashboard > Worker > Domains & Routes and verify each intended public host resolves through THIS Worker. A code merge is not itself a live Worker deployment.
5. On a routed hostname, request `GET /__vynalth/browser`. Expect status 200, `x-vynalth-edge: cloudflare-worker`, `scope: first-party-root`, `rootDomain` matching that host, a UUID `globalBrowserId`, and `Set-Cookie: __Secure-vyn_browser=...; Domain=<root>; ...`. A 403/404/503, redirect or an absent Worker header is a **release failure**, not success.
6. Open the root and a subdomain in the same normal browser profile: IDs match. Revisit root: ID remains stable. Fresh browser profile/other browser: new ID. Other registrable root: different ID. Shared-campus-IP independent browsers: different IDs.
7. Verify cookies never replace login or device-policy credentials, HTML caching remains private where cookies are issued, APIs/assets remain unaffected, and WAF/GPS policy still blocks as before.
8. Verify privacy notices/policy explain pseudonymous anonymous visitor IDs, purpose, retention, and user/browser deletion controls appropriate to jurisdictions where the site operates.

## Read-only smoke checks

```bash
curl -si https://vynalthai.com/__vynalth/browser
curl -si https://search.vynalthai.com/__vynalth/browser
curl -si https://vynlink.xyz/__vynalth/browser
```

These requests **do not confirm subdomain continuity**, because independent curl calls omit or discard cookies. Test actual same-browser behavior, or deliberately use a scoped local cookie jar for the same root.

## Rollback

Set Cloudflare `ROOT_BROWSER_ID_ENABLED = "false"` and redeploy. Endpoint then returns 503 with `SIGNING_NOT_CONFIGURED`, and no GBID is minted on HTML responses. The already-set GBID cookie expires normally or can be explicitly cleared by a first-party `Set-Cookie` at the same domain scope.

## Non-negotiable limitations

An ordinary website cannot guarantee a permanent hardware identity, continuity after deleting browser data, or reliable zero-interaction identification across Chrome, Firefox, Safari or Edge. Never claim that GBID meets those requirements, never infer one physical device from a shared IP or user agent, and never bypass browser tracking protections.
