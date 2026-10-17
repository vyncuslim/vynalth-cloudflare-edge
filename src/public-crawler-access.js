/**
 * Permit ONLY authentic Google crawlers to read ZoKivo public search resources
 * without an interactive GPS challenge. Human/anonymous access rules, school
 * policy, other hosts, and all private/game APIs are unchanged.
 *
 * Google explicitly recommends matching a crawler's source IP to its
 * published IP ranges; a claimed User-Agent or Google ASN alone is NOT proof.
 * https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
 */
const HOST = "zokivo.vynalthai.com";
const PUBLIC_FILES = new Set(["/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/manifest.webmanifest"]);
const GOOGLE_FEEDS = Object.freeze([
  "https://developers.google.com/static/crawling/ipranges/common-crawlers.json",
  "https://developers.google.com/static/crawling/ipranges/special-crawlers.json",
  "https://developers.google.com/static/crawling/ipranges/user-triggered-fetchers-google.json",
]);
// Deliberately exclude user-controlled Google Cloud / user-triggered fetchers.
const REFRESH_MS = 6 * 60 * 60 * 1000;
const RETRY_MS = 5 * 60 * 1000;
let cachedPrefixes = [];
let refreshAfter = 0;
let inFlight = null;

function parseAddress(text) {
  if (typeof text !== "string") return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
    const values = text.split(".").map(Number);
    if (values.some(v => v > 255)) return null;
    return values;
  }
  if (!/^[\da-f:]+$/i.test(text) || text.includes(":::")) return null;
  const chunks = text.split("::");
  if (chunks.length > 2) return null;
  const left = chunks[0] ? chunks[0].split(":") : [];
  const right = chunks.length === 2 && chunks[1] ? chunks[1].split(":") : [];
  const values = [...left, ...right];
  if (values.some(v => !/^[\da-f]{1,4}$/i.test(v))) return null;
  const omitted = 8 - values.length;
  if ((chunks.length === 1 && omitted !== 0) || (chunks.length === 2 && omitted < 1)) return null;
  const words = [...left, ...Array(omitted).fill("0"), ...right].map(v => parseInt(v, 16));
  return words.flatMap(v => [v >>> 8, v & 255]);
}

export function matchesCidr(ip, cidr) {
  if (typeof cidr !== "string" || !cidr.includes("/")) return false;
  const parts = cidr.split("/");
  if (parts.length !== 2 || !/^(0|[1-9]\d{0,2})$/.test(parts[1])) return false;
  const address = parseAddress(ip);
  const network = parseAddress(parts[0]);
  if (!address || !network || address.length !== network.length) return false;
  const bits = Number(parts[1]);
  if (bits > address.length * 8) return false;
  const whole = Math.floor(bits / 8), remainder = bits % 8;
  for (let i = 0; i < whole; i++) if (address[i] !== network[i]) return false;
  if (remainder) {
    const mask = (255 << (8 - remainder)) & 255;
    if ((address[whole] & mask) !== (network[whole] & mask)) return false;
  }
  return true;
}

async function refreshGooglePrefixes() {
  if (Date.now() < refreshAfter) return cachedPrefixes;
  if (!inFlight) {
    inFlight = (async () => {
      try {
        const collections = await Promise.all(GOOGLE_FEEDS.map(async url => {
          const response = await fetch(url, {
            headers: { Accept: "application/json" },
            signal: AbortSignal.timeout(3500),
          });
          if (!response.ok) throw Error("Google crawler IP feed unavailable");
          const length = Number(response.headers.get("Content-Length") || 0);
          if (length > 1_000_000) throw Error("Google crawler IP feed too large");
          const json = await response.json();
          if (!Array.isArray(json.prefixes) || json.prefixes.length < 1 ||
              json.prefixes.length > 10000) throw Error("Invalid Google IP feed");
          return json.prefixes.map(x => x.ipv4Prefix || x.ipv6Prefix).filter(Boolean);
        }));
        cachedPrefixes = collections.flat().filter(x => matchesCidr(x.split("/")[0], x));
        refreshAfter = Date.now() + REFRESH_MS;
      } catch {
        // Never allow unverified traffic on upstream verification failure.
        refreshAfter = Date.now() + RETRY_MS;
      }
      return cachedPrefixes;
    })().finally(() => { inFlight = null; });
  }
  return inFlight;
}

export async function isVerifiedGooglePublicCrawler(request, prefixLoader = refreshGooglePrefixes) {
  const url = new URL(request.url);
  if (url.hostname.toLowerCase() !== HOST) return false;
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  if (!PUBLIC_FILES.has(url.pathname) && !url.pathname.startsWith("/_next/static/")) return false;

  // UA check is only a cheap prefilter: real authentication is Google's IP range.
  if (!/\b(?:Googlebot(?:-[A-Za-z]+)?|Google-InspectionTool)\b/i.test(
    request.headers.get("User-Agent") || "")) return false;

  // Cloudflare sets CF-Connecting-IP at the edge; do not accept forwarded IPs,
  // ASN, timezone claims, arbitrary client headers, or signed-cookie lookalikes.
  const ip = request.headers.get("CF-Connecting-IP");
  if (!parseAddress(ip)) return false;

  try {
    const cidrs = await prefixLoader();
    return Array.isArray(cidrs) && cidrs.some(cidr => matchesCidr(ip, cidr));
  } catch {
    return false;
  }
}
