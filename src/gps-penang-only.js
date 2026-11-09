/**
 * Penang STATE (MY-07) selector for consent-based browser GPS checking.
 * Butterworth's optional GPS exemption is selected by original Cloudflare
 * IP-derived city/locality, postcode or a narrowly bounded mainland IP point.
 * These are approximate signals, never proof of physical location.
 * Cloudflare IP-derived region is not proof of physical location; only
 * consented browser GPS is used for campus inside/outside classification.
 * Independent Cloudflare WAF, school IP policy and app authentication remain.
 */
const PENANG_REGION_NAMES = new Set(["penang", "pulau pinang"]);
const PENANG_REGION_CODES = new Set(["07", "MY-07"]);
const normalizeCity = value => typeof value === "string"
  ? value.normalize("NFKC").trim().toLowerCase().replace(/\s+/g," ") : "";
// Narrow Butterworth localities, not the whole Seberang Perai municipality.
// Exact city matches only: a user-provided request header is never accepted.
const BUTTERWORTH_LOCALITIES = new Set([
  "butterworth","bandar butterworth","bagan ajam","bagan jermal",
  "bagan dalam","bagan luar","raja uda","mak mandin",
  "teluk air tawar","sungai puyu","seberang perai utara"
]);
const BUTTERWORTH_POSTCODES = code =>
  /^\d{5}$/.test(code) && ((Number(code)>=12000&&Number(code)<=13099)||
                          (Number(code)>=13400&&Number(code)<=13499));
// Intentionally small mainland urban box; never use as a campus GPS verdict.
// IP coordinates are coarse and may refer to an ISP rather than a device.
const BUTTERWORTH_IP_BOX = Object.freeze({south:5.375,north:5.455,west:100.355,east:100.445});
const parseCoord = (x,min,max) => {
  if(typeof x!=="number" && (typeof x!=="string"||!x.trim()))return null;
  const n=Number(x);
  return Number.isFinite(n)&&n>=min&&n<=max?n:null;
};

export function gpsPenangOnlyDecision(
  request, env, verifiedCountry = null, verifiedRegionCode = null, verifiedRegion = null,
  verifiedCity = null
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
  // A Service Binding call carries only the signed original city in v3.
  // Never use the *receiving* Worker's IP postcode or coordinates for it.
  const city = normalizeCity(signed ? verifiedCity : cf?.city);
  if (BUTTERWORTH_LOCALITIES.has(city)) {
    return {enabled:true,requireGPS:false,reason:
      city==="butterworth"?"butterworth-ip-city-exempt":"butterworth-ip-locality-exempt"};
  }
  // In first-party requests, Cloudflare may classify the Butterworth network
  // by postcode or by a coarse mainland location instead of its city name.
  if(!signed) {
    const postcode=String(cf?.postalCode??"").trim();
    if(BUTTERWORTH_POSTCODES(postcode)) {
      return {enabled:true,requireGPS:false,reason:"butterworth-ip-postcode-exempt"};
    }
    const latitude=parseCoord(cf?.latitude,-90,90);
    const longitude=parseCoord(cf?.longitude,-180,180);
    if(latitude!==null&&longitude!==null&&
       latitude>=BUTTERWORTH_IP_BOX.south&&latitude<=BUTTERWORTH_IP_BOX.north&&
       longitude>=BUTTERWORTH_IP_BOX.west&&longitude<=BUTTERWORTH_IP_BOX.east) {
      return {enabled:true,requireGPS:false,reason:"butterworth-ip-mainland-box-exempt"};
    }
  }
  return {enabled:true,requireGPS:true,
    reason:signed ? "penang-state-signed-evidence" : "penang-state-ip-evidence"};
}
