# Unified Device ID — voluntary cross-domain linking

## Purpose

Modern browsers do not permit one first-party Cookie to be read on
vynalthai.com, vyncuslim.si and zokivo.xyz simultaneously.
This feature keeps separate site-signed host-only Device IDs and shows the
same Global Device ID ONLY when an authenticated Vynalth account user
explicitly links a website. It does not identify anonymous visitors across
domains or use IP addresses as linking evidence.

## Entry points

- Canonical: https://vynalthai.com/cn/security/device-link
- Each participating site: https://HOST/__vynalth/device/link
- Device status: https://HOST/__vynalth/device

Supported hosts: vynalthai.si, vyncuslim.com, vyncuslim.my,
vyncuslim.si, vynlink.xyz, zokivo.xyz and their exact www variants.
Redirect-only roots inherit the canonical destination's identity.

After linking, status JSON includes globalDeviceId, siteDeviceId,
accountLinked=true, and deviceId matching globalDeviceId. These are
presentation and account-association signals only; never use
globalDeviceId as an authentication token or WAF allowlist.

## Deployment requirements

1. Parent Supabase tables device_federation_codes, device_federation_links,
   and device_federation_audit (private, RLS enabled) and the
   service_role-only claim_device_federation_code RPC.
2. Backend and frontend code deployed to correct production projects.
3. VISITOR_IP_SIGNING_SECRET must match securely between this Worker and
   the canonical backend. The new HMAC protocol uses a separate derived
   key namespace, not the existing visitor-IP signature.
4. Only after successful end-to-end browser tests, set
   DEVICE_FEDERATION_ENABLED=true in the Cloudflare Worker environment
   AND the Vercel backend production environment, then redeploy.
   Feature is OFF by default. Do not paste keys into chat or commit them.
5. Verify Cloudflare route assignments for all target hosts, CORS,
   WAF/GPS controls, account authentication, pairing expiry/replay,
   unlink and upstream failure handling.

Security: no third-party cookies, cross-site fingerprint matching,
anonymous ID merging, shared account login or automatic 11-mode WAF
enforcement. Each host signs its own first-party credentials.
Worker /claim and /status bypass browser GPS checks only on a valid
short-lived HMAC proof tied to a specific registered host and action.
All other traffic keeps the normal security paths.
