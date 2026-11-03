/**
 * Conservative, *optional* GPS prompt selector for Penang ISLAND only.
 *
 * Butterworth, Seberang Perai and the mainland are in Penang STATE (MY-07).
 * Region alone is NOT evidence of being on Penang island.
 *
 * Cloudflare IP-derived city/latitude/longitude are approximate and can be
 * wrong, especially behind VPNs, mobile operators and NAT. They are ONLY used
 * to decide whether to display an optional browser GPS prompt, never to prove
 * identity, make authorization decisions or claim precise user location.
 *
 * Conservative availability policy: ambiguous, missing or contradictory
 * Cloudflare city/coordinates must NOT force a GPS permission dialog.
 * Existing WAF, signup protection, School IP and private API rules remain.
 */
const PENANG_REGION_NAMES = new Set(["penang", "pulau pinang"]);
const PENANG_REGION_CODES = new Set(["07", "MY-07"]);

const ISLAND_CITY_NAMES = new Set([
  "george town","georgetown","bayan lepas","bayan baru","balik pulau",
  "air itam","ayer itam","batu ferringhi","batu feringghi",
  "tanjung bungah","tanjung tokong","gelugor","jelutong","pulau tikus",
  "teluk bahang","sungai nibong","batu maung","tanjung bunga"
]);
const MAINLAND_CITY_NAMES = new Set([
  "butterworth","seberang perai","seberang prai","perai","prai",
  "bukit mertajam","kepala batas","tasek gelugor","tasik gelugor",
  "nibong tebal","juru","simpang ampat","permatang pauh",
  "bagan ajam","bagan luar","mak mandin","sungai bakap","alma"
]);

// Only a conservative inner bounding rectangle is used for prompt selection.
// It is NOT a legal/administrative or security geofence. The second city check
// is intentionally required to reduce inaccurate IP-location prompts.
const ISLAND_BOUNDS = Object.freeze({
  minLat: 5.265, maxLat: 5.485,
  minLon: 100.17, maxLon: 100.355
});

function normalizeCity(value) {
  return typeof value === "string"
    ? value.normalize("NFKC").trim().toLowerCase().replace(/\s+/g, " ")
    : "";
}

function islandCandidate(cf) {
  // Only runtime request.cf is trusted as a Cloudflare observation. Never
  // consult CF-IPCountry, X-Region, X-City or client-supplied browser headers.
  const city = normalizeCity(cf?.city);
  if (MAINLAND_CITY_NAMES.has(city)) return {requireGPS:false,reason:"penang-mainland-city"};
  if (!ISLAND_CITY_NAMES.has(city)) return {requireGPS:false,reason:"penang-island-city-unconfirmed"};

  const lat = Number(cf?.latitude);
  const lon = Number(cf?.longitude);
  if (cf?.latitude == null || cf?.longitude == null ||
      !Number.isFinite(lat) || !Number.isFinite(lon)) {
    return {requireGPS:false,reason:"penang-island-coordinates-unavailable"};
  }

  if (lat < ISLAND_BOUNDS.minLat || lat > ISLAND_BOUNDS.maxLat ||
      lon < ISLAND_BOUNDS.minLon || lon > ISLAND_BOUNDS.maxLon) {
    return {requireGPS:false,reason:"penang-island-coordinates-outside"};
  }
  return {requireGPS:true,reason:"penang-island-ip-evidence"};
}

export function gpsPenangOnlyDecision(
  request, env, verifiedCountry = null, verifiedRegionCode = null, verifiedRegion = null
) {
  // Preserve explicitly scoped legacy policy on other domains. The island
  // selector is active only where the operator enabled Penang-only mode.
  if (env?.GPS_PENANG_ONLY_ENABLED !== "true") {
    return {enabled:false,requireGPS:true,reason:"legacy-policy"};
  }
  const cf = request?.cf;
  const hasSignedCountry = verifiedCountry !== null;
  const country = hasSignedCountry ? verifiedCountry : cf?.country;
  if (country !== "MY") {
    return {enabled:true,requireGPS:false,reason:"outside-malaysia-or-unknown"};
  }
  const regionCode = String(hasSignedCountry ? (verifiedRegionCode ?? "") : (cf?.regionCode ?? "")).trim().toUpperCase();
  const regionName = String(hasSignedCountry ? (verifiedRegion ?? "") : (cf?.region ?? "")).trim().toLowerCase();
  if (regionCode && regionName &&
      PENANG_REGION_CODES.has(regionCode) !== PENANG_REGION_NAMES.has(regionName)) {
    return {enabled:true,requireGPS:false,reason:"conflicting-region-evidence"};
  }
  if (!(PENANG_REGION_CODES.has(regionCode) || PENANG_REGION_NAMES.has(regionName))) {
    return {enabled:true,requireGPS:false,reason:"outside-penang-or-unknown-region"};
  }
  // A signed Worker-to-Worker policy request only attests country and state,
  // not the ORIGINAL visitor's city or IP coordinates. Do not treat the
  // downstream Worker's request.cf city as if it were the user.
  if (hasSignedCountry) {
    return {enabled:true,requireGPS:false,reason:"island-evidence-not-signed"};
  }
  const candidate = islandCandidate(cf);
  return {enabled:true,...candidate};
}
