/**
 * Enforce central policies for a previously consent-linked Global Device ID.
 * Different first-party sites retain distinct host-signed cookies. This
 * service never infers devices from IP, UA, fingerprinting or bare UUIDs.
 */
import { edgeDeviceScope, verifyEdgeDevice, readGlobalDeviceCookie } from './domain-device-id.js';
import { signedFederationAssertion } from './domain-device-federation.js';

const STATUS_URL = 'https://vynalthai.com/api/security/device/federation/status';
const EXEMPT = /^\/(?:__vynalth\/device(?:\/|$)|__vynalth\/consent(?:\/|$)|\.well-known\/|robots\.txt$|sitemap(?:-index)?\.xml$|favicon\.ico$|(?:en|cn|ms)\/(?:privacy|terms|contact|security\/device-link)(?:\/|$))/i;
const ASSET = /\.(?:css|js|mjs|png|jpg|jpeg|gif|webp|svg|ico|woff2?|ttf|otf|map|mp4|webm|pdf)(?:$|\/)/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function denial(status, code, retryAfterSeconds) {
  const headers = {
    'Cache-Control': 'no-store, private',
    'Content-Type': 'application/json; charset=utf-8',
    'Referrer-Policy': 'no-referrer',
    'X-Content-Type-Options': 'nosniff',
    'X-Robots-Tag': 'noindex, nofollow',
    'X-Vynalth-Global-Device-Policy': code,
  };
  if (retryAfterSeconds) headers['Retry-After'] = String(retryAfterSeconds);
  return new Response(JSON.stringify({ success: false, error: code, retryAfterSeconds: retryAfterSeconds || undefined }), { status, headers });
}

export function evaluateGlobalDevicePolicy(policy, pathname, nowMs = Date.now()) {
  if (!policy || typeof policy !== 'object') return null;
  const mode = String(policy.mode || '');
  if (mode === 'revoke') return denial(403, 'GLOBAL_DEVICE_REVOKED');
  if (mode === 'block') return denial(403, 'GLOBAL_DEVICE_BLOCKED');
  if (mode === 'temporary_block') {
    const until = Date.parse(String(policy.blocked_until || ''));
    if (!Number.isFinite(until)) return denial(503, 'INVALID_GLOBAL_POLICY');
    if (nowMs < until) return denial(403, 'GLOBAL_DEVICE_TEMPORARILY_BLOCKED', Math.max(1, Math.ceil((until - nowMs) / 1000)));
  }
  const path = String(pathname || '/').toLowerCase();
  if (policy.ai_tools_allowed === false && /^\/api\/(?:ai\/|cloud-browser|browser-run|sandbox)/.test(path)) {
    return denial(403, 'GLOBAL_DEVICE_AI_RESTRICTED');
  }
  if (policy.exports_allowed === false && /^\/api\/.*(?:\/export|\/download|\/backup|\/archive|[-_]export)(?:\/|$)/.test(path)) {
    return denial(403, 'GLOBAL_DEVICE_EXPORT_RESTRICTED');
  }
  if (mode === 'restricted' && /^\/api\/(?:admin|security|auth|account|ai|keys|tokens)(?:\/|$)/.test(path)) {
    return denial(403, 'GLOBAL_DEVICE_RESTRICTED');
  }
  // Challenge grants and custom rate counters remain canonical-site-only
  // until they receive independent, host-scoped step-up verification.
  return null;
}

export async function checkFederatedDeviceAccess(request, env, url) {
  if (env?.GLOBAL_DEVICE_CONTROL_ENABLED !== 'true' || !edgeDeviceScope(url.hostname)) return null;
  if (request.method === 'OPTIONS' || EXEMPT.test(url.pathname) || ASSET.test(url.pathname)) return null;
  const device = await verifyEdgeDevice(request, env);
  if (device.state !== 'valid' && device.state !== 'rotated') return null;
  const linked = await readGlobalDeviceCookie(request, env, device.deviceId);
  if (!linked || !UUID.test(linked.globalDeviceId)) return null;
  try {
    const proof = await signedFederationAssertion(env, url.hostname, device.deviceId, linked.globalDeviceId, 'status');
    if (!proof) return denial(503, 'GLOBAL_DEVICE_PROOF_UNAVAILABLE');
    const response = await fetch(STATUS_URL, {
      method: 'POST',
      redirect: 'error',
      credentials: 'omit',
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
      body: JSON.stringify({ host: url.hostname, localDeviceId: device.deviceId, globalDeviceId: linked.globalDeviceId, ...proof }),
    });
    if (!response.ok) return denial(503, 'GLOBAL_DEVICE_POLICY_UNAVAILABLE');
    const state = await response.json();
    if (state?.success !== true || typeof state?.active !== 'boolean') return denial(503, 'INVALID_GLOBAL_POLICY_RESPONSE');
    if (!state.active) return null; // revoked association: never trust a stale global cookie.
    if (state.policy === undefined) return denial(503, 'GLOBAL_DEVICE_POLICY_UNAVAILABLE');
    return evaluateGlobalDevicePolicy(state.policy, url.pathname);
  } catch {
    // A known, signed global credential cannot silently bypass an unverified
    // central policy check. No signed global cookie => existing local behavior.
    return denial(503, 'GLOBAL_DEVICE_POLICY_UNAVAILABLE');
  }
}
