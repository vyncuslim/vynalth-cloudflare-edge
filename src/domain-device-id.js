/**
 * Vynalth domain-scoped Device ID (edge v1).
 *
 * This is a first-party, per-host, cryptographically signed browser credential
 * for abuse controls. It is not a hardware ID, account authentication, proof
 * of residency, or a universal cross-site tracking identifier.
 *
 * No third-party cookies, IP-derived ID, browser fingerprint, DOM script,
 * cross-domain synchronization, or centralized event transmission.
 */
import { getRootDomain } from './managed-domains.js';

export const DEVICE_ROOT_DOMAINS = Object.freeze([
  'sleepsomno.com',
  'vitamindai.online',
  'vynalthai.com',
  'vynalthai.si',
  'vyncuslim.com',
  'vyncuslim.my',
  'vyncuslim.si',
  'vynlink.xyz',
  'vynli.xyz',
  'zokivo.xyz',
  'powiismunc.com',
]);
export const REDIRECT_ONLY_ROOTS = Object.freeze([
  'vitamindai.online', 'vynli.xyz',
]);
const DEVICE_COOKIE_NAME = '__Host-vyn_edge_device';
const DEVICE_ENDPOINT = '/__vynalth/device';
const DEVICE_TTL_SECONDS = 90 * 86400;
const REFRESH_SECONDS = 30 * 86400;
const CLOCK_SKEW_SECONDS = 300;
const VERSION = 'e1';
const textEncoder = new TextEncoder();
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const skipBots = /(?:googlebot|bingbot|duckduckbot|yandexbot|baiduspider|petalbot|facebookexternalhit|twitterbot)/i;

export function edgeDeviceScope(hostname) {
  if (typeof hostname !== 'string') return null;
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const root = getRootDomain(host);
  if (!root || !DEVICE_ROOT_DOMAINS.includes(root) || REDIRECT_ONLY_ROOTS.includes(root)) return null;
  // The historic .com root redirects, but an independently hosted personal
  // subdomain can legitimately retain a separate first-party browser cookie.
  if (root === 'sleepsomno.com' && (host === root || host === 'www.'+root)) return null;
  // The original central backend already issues __Host-vyn_device on this host.
  // Do not create a second unrelated Device ID on its canonical apex.
  if (host === 'vynalthai.com' || host === 'www.vynalthai.com') return null;
  return { host, root };
}

function signingMaterial(env) {
  if (env?.EDGE_DEVICE_ID_ENABLED !== 'true') return '';
  const dedicated = String(env?.EDGE_DEVICE_ID_SIGNING_SECRET || '');
  if (dedicated.length >= 32) return dedicated;
  // Deliberate compatibility choice: use an independent, one-way derived
  // signing key from the existing signed-visitor secret. This never reuses
  // the visitor-IP MAC key or MAC message, and can be replaced by a dedicated
  // secret without ever treating edge cookies as user login credentials.
  if (env?.EDGE_DEVICE_ALLOW_DERIVED_KEY === 'true') {
    const legacy = String(env?.VISITOR_IP_SIGNING_SECRET || '');
    if (legacy.length >= 32) return legacy;
  }
  return '';
}
export function edgeDeviceAvailable(env, host) {
  return Boolean(edgeDeviceScope(host) && signingMaterial(env));
}
function parseCookie(header, name = DEVICE_COOKIE_NAME) {
  for (const raw of String(header || '').split(';')) {
    const i = raw.indexOf('=');
    if (i < 1 || raw.slice(0, i).trim() !== name) continue;
    try { return decodeURIComponent(raw.slice(i + 1).trim()); }
    catch { return ''; }
  }
  return '';
}
function encodeBytes(bytes) {
  let str = '';
  for (const byte of bytes) str += String.fromCharCode(byte);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decodeBytes(base64) {
  if (typeof base64 !== 'string' || !/^[a-z0-9_-]+$/i.test(base64) || base64.length > 120) return null;
  try {
    const standard = base64.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(standard + '='.repeat((4 - standard.length % 4) % 4));
    const result = Uint8Array.from(raw, x => x.charCodeAt(0));
    return encodeBytes(result) === base64 ? result : null;
  } catch { return null; }
}
async function signingKey(material, host) {
  // Per-host subkeys: a cookie on .si cannot validate on .com or subdomains.
  const seed = await crypto.subtle.digest('SHA-256',
    textEncoder.encode('vynalth-domain-device:key-derivation:v1:' + material + ':' + host));
  return crypto.subtle.importKey('raw', seed,
    { name:'HMAC', hash:'SHA-256' }, false, ['sign', 'verify']);
}
async function mac(material, host, payload) {
  const key = await signingKey(material, host);
  return encodeBytes(new Uint8Array(await crypto.subtle.sign('HMAC', key, textEncoder.encode(payload))));
}
export async function verifyEdgeDevice(request, env, nowMs = Date.now()) {
  const scope = edgeDeviceScope(new URL(request.url).hostname);
  const material = signingMaterial(env);
  if (!scope || !material) return { state:'disabled', deviceId:null, token:null, shouldSetCookie:false };
  const raw = parseCookie(request.headers.get('cookie'));
  const parts = raw.split('.');
  if (raw.length < 512 && parts.length === 4 && parts[0] === VERSION
    && uuidPattern.test(parts[1]) && /^[0-9]{10}$/.test(parts[2])) {
    const issued = Number(parts[2]);
    const now = Math.floor(nowMs / 1000);
    if (issued > 0 && issued <= now + CLOCK_SKEW_SECONDS && now - issued <= DEVICE_TTL_SECONDS) {
      const signed = [VERSION,parts[1].toLowerCase(),parts[2]].join('.');
      // Verify the canonical MAC bytes using WebCrypto, rather than a
      // potentially timing-variable JavaScript string comparison.
      const actual = decodeBytes(parts[3]);
      const key = await signingKey(material, scope.host);
      if (actual && await crypto.subtle.verify(
        'HMAC', key, actual, textEncoder.encode(signed),
      )) {
        const refresh = now - issued >= REFRESH_SECONDS;
        const token = refresh ? await signEdgeDevice(parts[1].toLowerCase(), scope.host, material, now) : raw;
        return { state:refresh?'rotated':'valid',deviceId:parts[1].toLowerCase(),
          token,shouldSetCookie:refresh };
      }
    }
  }
  const id = crypto.randomUUID().toLowerCase();
  const token = await signEdgeDevice(id, scope.host, material, Math.floor(nowMs / 1000));
  return { state:'issued',deviceId:id,token,shouldSetCookie:true };
}
async function signEdgeDevice(id, host, material, nowSeconds) {
  const payload = [VERSION,id,nowSeconds].join('.');
  return payload + '.' + await mac(material,host,payload);
}
export function buildEdgeDeviceCookie(token) {
  return [
    DEVICE_COOKIE_NAME + '=' + encodeURIComponent(token),
    'Path=/', 'Max-Age=' + DEVICE_TTL_SECONDS,
    'HttpOnly','Secure','SameSite=Lax','Priority=High',
  ].join('; ');
}

const GLOBAL_COOKIE_NAME='__Host-vyn_global_device';
const GLOBAL_TOKEN_VERSION='g1';
const GLOBAL_LIFETIME_SECONDS=90*86400;
const GLOBAL_REFRESH_SECONDS=30*86400;

// The global cookie is a display/association proof only; never a security
// authorization token. The canonical server must also approve active linkage.
export async function createGlobalDeviceCookie(host,localId,globalId,env,nowMs=Date.now()) {
  const scope=edgeDeviceScope(host),material=signingMaterial(env);
  if(!scope||!material||!uuidPattern.test(localId)||!uuidPattern.test(globalId))return null;
  const ts=Math.floor(nowMs/1000);
  const payload=[GLOBAL_TOKEN_VERSION,globalId.toLowerCase(),localId.toLowerCase(),ts].join('.');
  const proof=await mac(material,scope.host,payload);
  return [
    GLOBAL_COOKIE_NAME+'='+encodeURIComponent(payload+'.'+proof),
    'Path=/','Max-Age='+GLOBAL_LIFETIME_SECONDS,
    'HttpOnly','Secure','SameSite=Lax','Priority=High',
  ].join('; ');
}
export async function readGlobalDeviceCookie(request,env,localDeviceId,nowMs=Date.now()) {
  const scope=edgeDeviceScope(new URL(request.url).hostname);
  const material=signingMaterial(env);
  if(!scope||!material||!uuidPattern.test(localDeviceId))return null;
  const token=parseCookie(request.headers.get('cookie'),GLOBAL_COOKIE_NAME);
  if(token.length>520)return null;
  const parts=token.split('.');
  if(parts.length!==5||parts[0]!==GLOBAL_TOKEN_VERSION
      ||!uuidPattern.test(parts[1])||parts[2]!==localDeviceId.toLowerCase()
      ||!/^\d{10}$/.test(parts[3]))return null;
  const ts=Number(parts[3]),now=Math.floor(nowMs/1000);
  if(ts>now+300||now-ts>GLOBAL_LIFETIME_SECONDS)return null;
  const proof=decodeBytes(parts[4]);
  if(!proof)return null;
  const key=await signingKey(material,scope.host);
  const valid=await crypto.subtle.verify('HMAC',key,proof,
    textEncoder.encode(parts.slice(0,4).join('.')));
  return valid?{
    globalDeviceId:parts[1].toLowerCase(),
    localDeviceId:parts[2].toLowerCase(),
    shouldRefresh:now-ts>=GLOBAL_REFRESH_SECONDS,
  }:null;
}

function secureResponseHeaders() {
  return {
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'private, no-store, max-age=0',
    'Referrer-Policy':'no-referrer',
    'X-Content-Type-Options':'nosniff',
    'X-Robots-Tag':'noindex, nofollow, noarchive',
    'Cross-Origin-Resource-Policy':'same-origin',
    'Access-Control-Allow-Credentials':'false',
  };
}
function withCookie(response, cookie) {
  const headers = new Headers(response.headers);
  headers.append('Set-Cookie', cookie); // never replace application sessions
  headers.set('Cache-Control', 'private, no-store, max-age=0');
  return new Response(response.body, {
    status:response.status, statusText:response.statusText, headers,
  });
}
export async function handleEdgeDeviceEndpoint(request, env, url) {
  if (url.pathname !== DEVICE_ENDPOINT) return null;
  const scope = edgeDeviceScope(url.hostname);
  if (!scope) return null; // main site continues to use its existing Device ID
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}), {
      status:405,headers:{...secureResponseHeaders(),Allow:'GET, HEAD'},
    });
  }
  if (request.headers.get('Sec-Fetch-Site') === 'cross-site') {
    return new Response(JSON.stringify({error:'SAME_ORIGIN_REQUIRED'}), {
      status:403,headers:secureResponseHeaders(),
    });
  }
  const state = await verifyEdgeDevice(request, env);
  if (state.state === 'disabled') {
    return new Response(JSON.stringify({enabled:false,reason:'SIGNING_NOT_CONFIGURED'}),{
      status:503,headers:secureResponseHeaders(),
    });
  }
  // The caller must both hold a valid local signed ID and retain an
  // explicit account link in the canonical database. A stale or revoked
  // global cookie is never accepted merely because its MAC is valid.
  let activeGlobal=null;
  let refreshedGlobalCookie=null;
  if ((state.state==='valid'||state.state==='rotated') && request.method==='GET') {
    const candidate=await readGlobalDeviceCookie(request,env,state.deviceId);
    if (candidate) {
      // Loaded dynamically to avoid a circular dependency. Verification is
      // server-to-server with a short-lived signed Worker assertion.
      const { verifyActiveFederation }=await import('./domain-device-federation.js');
      if(await verifyActiveFederation(env,scope.host,state.deviceId,candidate.globalDeviceId)) {
        activeGlobal=candidate.globalDeviceId;
        if(candidate.shouldRefresh)refreshedGlobalCookie=await createGlobalDeviceCookie(
          scope.host,state.deviceId,activeGlobal,env);
      }
    }
  }
  const body = request.method === 'HEAD' ? null : JSON.stringify({
    enabled:true,
    scope:activeGlobal?'account-linked-global':'host-only',
    globalControlEnforcementActive:env?.GLOBAL_DEVICE_CONTROL_ENABLED==='true',
    host:scope.host,
    rootDomain:scope.root,
    deviceId:activeGlobal||state.deviceId,
    siteDeviceId:state.deviceId,
    globalDeviceId:activeGlobal,
    signedAndVerified:state.state==='valid'||state.state==='rotated',
    credentialState:state.state,
    lifetimeDays:90,
    accountLinked:Boolean(activeGlobal),
    warning:'A browser credential is not a hardware ID or account identity.',
  });
  let response = new Response(body,{status:200,headers:secureResponseHeaders()});
  if (state.shouldSetCookie && request.method==='GET')
    response=withCookie(response,buildEdgeDeviceCookie(state.token));
  if (refreshedGlobalCookie) response=withCookie(response,refreshedGlobalCookie);
  return response;
}
export async function addEdgeDeviceToDocumentResponse(request,response,env,url) {
  if (request.method !== 'GET' || response.status !== 200 || url.protocol !== 'https:') return response;
  const scope = edgeDeviceScope(url.hostname);
  if (!scope || !signingMaterial(env)) return response;
  if (url.pathname.startsWith('/__vynalth/') || url.pathname.startsWith('/.well-known/')) return response;
  if (skipBots.test(request.headers.get('User-Agent') || '')) return response;
  const destination = request.headers.get('Sec-Fetch-Dest');
  if (destination && destination !== 'document') return response;
  if (!(request.headers.get('Accept') || '').includes('text/html')) return response;
  if (!(response.headers.get('Content-Type') || '').toLowerCase().includes('text/html')) return response;
  const state = await verifyEdgeDevice(request,env);
  return state.shouldSetCookie ? withCookie(response,buildEdgeDeviceCookie(state.token)) : response;
}
