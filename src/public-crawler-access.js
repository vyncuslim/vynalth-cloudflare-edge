/**
 * Permit ONLY source-IP-verified Google crawlers to fetch public SEO resources
 * on explicitly listed hosts without an interactive GPS challenge. Ordinary
 * visitors still face the existing GPS gate; School IP policy, WAF and private
 * APIs continue to enforce their own independent access restrictions.
 *
 * Google explicitly recommends matching a crawler's source IP to its
 * published IP ranges; a claimed User-Agent or Google ASN alone is NOT proof.
 * https://developers.google.com/crawling/docs/crawlers-fetchers/verify-google-requests
 */
// Exact host allowlist. Vyncuslim Global is a separate, public-only static
// website on the si-domain Vercel project; no internal or API paths are open.
// Main-site SEO paths are public content only. This exact allowlist does not
// contain account, search results, checkout, private dashboards, GPS endpoints,
// admin panels or APIs. Google crawler status still requires published source
// IP range verification (not a claim in request headers).
const MAIN_SITE_PUBLIC_ROUTES = [
  '', 'about', 'product', 'features', 'how-it-works', 'plans', 'research',
  'science', 'founder', 'docs', 'developers', 'contact', 'faq', 'support',
  'media', 'blog', 'news', 'changelog', 'status', 'trust', 'security',
  'legal', 'security/bug-bounty', 'security/hall-of-fame',
  'security/docs', 'event-center', 'bot',
  'legal/privacy', 'legal/terms', 'legal/cookies',
  'legal/biometric-data-notice', 'legal/medical-disclaimer',
  'legal/data-handling', 'legal/sub-processors', 'legal/dpa',
  'legal/contact', 'legal/security', 'legal/acceptable-use',
  'legal/ai-disclaimer', 'legal/abuse-policy', 'legal/account-blocking',
  'legal/policy-framework', 'legal/vulnerability-disclosure',
  'legal/bug-bounty', 'legal/appeals-and-complaints',
  'legal/intellectual-property', 'legal/children-privacy',
  'legal/open-source', 'legal/transparency',
];
const MAIN_SITE_PUBLIC_FILES = new Set([
  '/', '/robots.txt', '/sitemap.xml', '/sitemap.xsl',
  '/favicon.ico', '/favicon.svg', '/manifest.json', '/og-image.svg',
  '/llms.txt', '/llms-full.txt', '/rss.xml',
]);
for (const lang of ['en', 'cn', 'ms']) {
  for (const route of MAIN_SITE_PUBLIC_ROUTES) {
    MAIN_SITE_PUBLIC_FILES.add('/' + lang + (route ? '/' + route : ''));
  }
  MAIN_SITE_PUBLIC_FILES.add('/' + lang + '/');
}
const PUBLIC_RESOURCES = new Map([
  ['vynalthai.com', {
    files: MAIN_SITE_PUBLIC_FILES,
    prefixes: ['/assets/'],
  }],
  ['www.vynalthai.com', {
    files: MAIN_SITE_PUBLIC_FILES,
    prefixes: ['/assets/'],
  }],
  ["zokivo.vynalthai.com", {
    files: new Set(["/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/manifest.webmanifest",
      "/icon.svg", "/zokivo-mark.svg", "/games", "/how-it-works", "/try",
      "/paper", "/paper/cards", "/library", "/study"]),
    prefixes: ["/_next/static/"],
  }],
  ["gobal.vyncuslim.si", {
    files: new Set(["/", "/robots.txt", "/sitemap.xml", "/favicon.ico", "/vynalth-logo.svg"]),
    prefixes: ["/assets/"],
  }],
]);
// Public, owner-controlled pages of the personal site. In particular, DO NOT
// exempt friends.*, /jingxin, private photos, admin, APIs or account data.
// Public CSS/JS assets are only the named static resources needed to render SEO.
const VYNCUS_PUBLIC_PATHS = new Set([
  "/", "/robots.txt", "/sitemap.xml", "/favicon.svg", "/favicon.ico",
  "/achievements", "/story", "/web-design",
  "/styles.css", "/script.js", "/fixes.css",
]);
for (const host of ["vyncuslim.com", "www.vyncuslim.com"]) {
  PUBLIC_RESOURCES.set(host, { files: VYNCUS_PUBLIC_PATHS, prefixes: [] });
}
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
        // Never reuse stale source-IP evidence if the Google IP feed refresh fails.
        cachedPrefixes = [];
        refreshAfter = Date.now() + RETRY_MS;
      }
      return cachedPrefixes;
    })().finally(() => { inFlight = null; });
  }
  return inFlight;
}

export async function isVerifiedGooglePublicCrawler(request, prefixLoader = refreshGooglePrefixes) {
  const url = new URL(request.url);
  const publicResources = PUBLIC_RESOURCES.get(url.hostname.toLowerCase());
  if (!publicResources) return false;
  if (request.method !== "GET" && request.method !== "HEAD") return false;
  if (!publicResources.files.has(url.pathname) &&
      !publicResources.prefixes.some(prefix => url.pathname.startsWith(prefix))) return false;

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
