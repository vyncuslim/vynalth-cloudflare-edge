# Vynalth Global Device ID v2 — release gate

## Scope
A Global Device ID is an explicitly account-linked browser credential association,
NOT a hardware serial number, IMEI, cross-browser fingerprint, login credential,
or proof that two browser profiles belong to the same physical machine.
Different registered domains retain distinct host-only, signed credentials.
After a one-time host-authorized pairing, the effective Global ID is identical
on each linked site. New/unlinked contexts keep their own local ID.

## Current coverage
Managed roots: vynalthai.com (canonical backend ID), vynalthai.si,
vyncuslim.com, vyncuslim.my, vyncuslim.si, vynlink.xyz, zokivo.xyz,
powiismunc.com and hosted personal subdomains of sleepsomno.com.
Redirect-only: vitamindai.online and vynli.xyz inherit canonical target ID.
DNS and Worker route assignments MUST be verified for every real host. This
repository's domain list does not create routes.

## Central policy
- Protected: server-verified Global ID mapped via a live, unrevoked record
  in device_federation_links.
- Policy authority: browser_device_controls on the canonical Supabase project.
- Edge v2 enforces active block, revoke, temporary_block, restricted routes,
  AI tools disallow and export disallow before private media and dynamic pages.
- Future: browser-specific step-up grants and central custom rate limits need
  independent implementation. Do NOT claim all 11 original controls are
  cross-domain-ready yet.
- The same browser with cleared cookies may appear new. Account enforcement,
  session controls and abuse protection remain necessary for effective blocks.
- Legal pages, consent and device-link/recovery entrypoints remain accessible.
- No IP/UA/fingerprint-based anonymous cross-site identity matching.

## Deployment and test order
1. Main Supabase schema migration in the backend repository:
   docs/sql/vynalth-device-federation-all-managed-domains-v3.sql
   Applied Nov 13 2026 to central project. SQL verified permitted managed
   hosts and rejected external roots. No user links created or modified.
2. Validate backend PR 186 with Node device-identity tests and a real signed
   status proof; check service-role isolation and HMAC key parity.
3. Validate frontend PR 247 and the consent pairing screen.
4. Validate edge PR 82 with Node tests, Wrangler dry-run and no route edits.
   GitHub Actions run 43382498714 passed on SHA 7eb37e1.
5. Audit Cloudflare Dashboard for active apex/wildcard routes and proxied DNS
   on .com/.my/.si/.xyz and all distinct managed roots; avoid route code 10020.
6. Check shared VISITOR_IP_SIGNING_SECRET in Worker and Vercel using secure
   platform settings, never GitHub or chat. Do not trust an ID string alone.
7. Deploy BACKEND, then frontend, then Edge in coordinated production rollout.
   Keep GLOBAL_DEVICE_CONTROL_ENABLED false until backend status policy
   response and real cross-origin tests pass. The branch config prepares
   true for deployment; do not merge ahead of backend readiness.
8. Browser E2E: pair A and B with same canonical signed browser ID, assert
   equal global IDs, distinct host IDs; verify different device remains
   distinct, then block a consenting test device and assert 403 on dynamic
   HTML, API, private image and PDF across registered sites.
9. Verify revoked code, expired code, forged MAC, cross-host replay, unlink,
   cookie clearing, central outage (503 for active signed associations),
   WAF, GPS and public/legal page availability. Record results before GO.
10. Emergency rollback: disable new GLOBAL_DEVICE_CONTROL_ENABLED without
    disabling existing security, login, GPS or canonical account policy.

## Status
Schema has shipped. Code is on coordinated draft PRs, not production.
Backend and frontend Actions were unable to execute job steps, so CI is not
verified there. Edge Node suite passed (359/359 on earlier branch SHA), but
live route/browser tests and deploy coordination remain incomplete.
