/**
 * Penang STATE (MY-07) selector for consent-based browser GPS checking.
 * All Penang cities, including Butterworth / Seberang Perai, are eligible.
 * Cloudflare IP-derived region is not proof of physical location; only
 * consented browser GPS is used for campus inside/outside classification.
 * Independent Cloudflare WAF, school IP policy and app authentication remain.
 */
const PENANG_REGION_NAMES = new Set(["penang", "pulau pinang"]);
const PENANG_REGION_CODES = new Set(["07", "MY-07"]);

export function gpsPenangOnlyDecision(
  request, env, verifiedCountry = null, verifiedRegionCode = null, verifiedRegion = null
) {
  // Keep the existing deployed environment variable name for compatibility.
  // The enabled policy now covers the entire state, not just Penang island.
  if (env?.GPS_PENANG_ONLY_ENABLED !== "true") {
    return {enabled:false,requireGPS:true,reason:"legacy-policy"};
  }
  const signed = verifiedCountry !== null;
  const cf = request?.cf;
  const country = signed ? verifiedCountry : cf?.country;
  if (country !== "MY") {
    return {enabled:true,requireGPS:false,reason:"outside-malaysia-or-unknown"};
  }
  // Signed inter-Worker metadata is authoritative for the original client.
  // Never substitute the receiving Worker's request.cf or browser headers.
  const regionCode = String(signed ? (verifiedRegionCode ?? "") : (cf?.regionCode ?? "")).trim().toUpperCase();
  const regionName = String(signed ? (verifiedRegion ?? "") : (cf?.region ?? "")).trim().toLowerCase();
  const codeMatches = PENANG_REGION_CODES.has(regionCode);
  const nameMatches = PENANG_REGION_NAMES.has(regionName);
  if (regionCode && regionName && codeMatches !== nameMatches) {
    return {enabled:true,requireGPS:false,reason:"conflicting-region-evidence"};
  }
  if (!codeMatches && !nameMatches) {
    return {enabled:true,requireGPS:false,reason:"outside-penang-or-unknown-region"};
  }
  return {enabled:true,requireGPS:true,
    reason:signed ? "penang-state-signed-evidence" : "penang-state-ip-evidence"};
}
