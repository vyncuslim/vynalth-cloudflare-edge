/**
 * Penang-only opt-in GPS trigger.
 *
 * Uses Cloudflare-provided request.cf geo metadata, NOT browser-provided
 * headers or client timezones. This is an approximate UX selector, not
 * physical-position proof or a security boundary: IP geolocation can be
 * wrong, masked by VPN, or missing.
 *
 * When region cannot be positively identified as Penang, leave the ordinary
 * website accessible (fail open for this optional location challenge).
 * Existing WAF, School IP, authentication and private-media controls remain.
 */
const PENANG_REGION_NAMES = new Set(["penang", "pulau pinang"]);
const PENANG_REGION_CODES = new Set(["07", "MY-07"]);

export function gpsPenangOnlyDecision(request, env, verifiedCountry = null) {
  if (env?.GPS_PENANG_ONLY_ENABLED !== "true") {
    return { enabled: false, requireGPS: true, reason: "legacy-policy" };
  }

  // For signed Service Binding calls, the signed country must override the
  // internal worker's request.cf.country; request.cf.region is not proof of
  // the end user's region across a Worker-to-Worker hop.
  const cf = request?.cf;
  const hasSignedCountry = verifiedCountry !== null;
  const country = hasSignedCountry ? verifiedCountry : cf?.country;
  if (country !== "MY") {
    return { enabled: true, requireGPS: false, reason: "outside-malaysia-or-unknown" };
  }
  const regionCode = hasSignedCountry ? "" : String(cf?.regionCode ?? "").trim().toUpperCase();
  const regionName = hasSignedCountry ? "" : String(cf?.region ?? "").trim().toLowerCase();
  if (PENANG_REGION_CODES.has(regionCode) || PENANG_REGION_NAMES.has(regionName)) {
    return { enabled: true, requireGPS: true, reason: "penang-ip-region" };
  }
  // In particular, MY with an unknown region must not trigger a geolocation
  // permission prompt on every request. It is an explicit availability tradeoff.
  return { enabled: true, requireGPS: false, reason: "outside-penang-or-unknown-region" };
}
