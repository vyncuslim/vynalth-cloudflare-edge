/**
 * Permanent owner *entitlement* for campus access (not a permanent session).
 *
 * Uses the existing login backend's short-lived, HMAC-verified SSO identity.
 * A site operator explicitly pins ONE stable user subject in Cloudflare
 * configuration as SHA-256("vynalth-owner-subject-v1:" + sub).
 *
 * Never trust browser-supplied email, role, IP, GPS, query, or custom headers.
 * Never create an unexpiring cookie, grant application admin, or bypass WAF.
 */
import { signedSSO } from "./universal-consent.js";

const APEX = "vynalthai.com";
const DOMAIN_SEPARATOR = "vynalth-owner-subject-v1:";
const TEXT = new TextEncoder();

function parseHexDigest(value) {
  if (typeof value !== "string" || !/^[a-f0-9]{64}$/.test(value)) return null;
  return Uint8Array.from(value.match(/../g), hex => Number.parseInt(hex, 16));
}

export async function hasPermanentOwnerAccess(request, env, url) {
  if (url.hostname !== APEX ||
      env?.VYNALTH_PERMANENT_OWNER_ENABLED !== "true") return false;
  const expected = parseHexDigest(env?.VYNALTH_OWNER_SSO_SUBJECT_SHA256);
  if (!expected) return false;
  try {
    // Must be issued by the real app after an authenticated login.
    // signedSSO verifies HMAC, exact host, allowed exp and subject schema.
    const identity = await signedSSO(request, env, APEX);
    if (!identity) return false;
    const hash = new Uint8Array(await crypto.subtle.digest("SHA-256",
      TEXT.encode(DOMAIN_SEPARATOR + identity.sub)));
    let different = 0;
    for (let i = 0; i < hash.length; i++) different |= hash[i] ^ expected[i];
    return different === 0;
  } catch {
    return false; // Missing secrets, unavailable crypto or invalid SSO fail closed.
  }
}
