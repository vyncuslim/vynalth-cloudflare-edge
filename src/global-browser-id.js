/**
 * Global Browser ID (GBID) — anonymous first-party, registrable-domain scope.
 *
 * Never treat this as a physical-device identity, login assertion, security
 * authorization, or a cross-browser/cross-root ID. Browsers isolate separate
 * profiles and different registrable domains. No redirect/bounce tracking,
 * fingerprinting, IP linking, third-party cookies or cross-site synchronization.
 */
import { getRootDomain } from './managed-domains.js';

const COOKIE = '__Secure-vyn_browser';
const PATH = '/__vynalth/browser';
const VERSION = 'b1';
const LIFETIME = 90 * 86400;
const REFRESH = 30 * 86400;
const SKEW = 300;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const BOTS = /(?:googlebot|bingbot|duckduckbot|yandexbot|baiduspider|petalbot|facebookexternalhit|twitterbot)/i;
const excluded = new Set(['vitamindai.online','vynli.xyz']);
const encoder = new TextEncoder();

function scope(hostname) {
  if (typeof hostname !== 'string') return null;
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const root = getRootDomain(host);
  if (!root || excluded.has(root)) return null;
  if (root === 'sleepsomno.com' && (host === root || host === 'www.' + root)) return null;
  return { host, root };
}
function material(env) {
  if (env?.ROOT_BROWSER_ID_ENABLED !== 'true' || env?.EDGE_DEVICE_ID_ENABLED !== 'true') return '';
  const dedicated = String(env?.EDGE_DEVICE_ID_SIGNING_SECRET || '');
  if (dedicated.length >= 32) return dedicated;
  if (env?.EDGE_DEVICE_ALLOW_DERIVED_KEY === 'true') {
    const legacy = String(env?.VISITOR_IP_SIGNING_SECRET || '');
    if (legacy.length >= 32) return legacy;
  }
  return '';
}
function b64(bytes) {
  let s = '';
  for (const c of bytes) s += String.fromCharCode(c);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value)) return null;
  try {
    const s = atob(value.replace(/-/g,'+').replace(/_/g,'/') + '=');
    const bytes = Uint8Array.from(s,c=>c.charCodeAt(0));
    return bytes.length === 32 && b64(bytes) === value ? bytes : null;
  } catch { return null; }
}
async function key(secret, root) {
  const digest = await crypto.subtle.digest('SHA-256',
    encoder.encode('vynalth-browser-root-signing:v1:' + secret + ':' + root));
  return crypto.subtle.importKey('raw', digest,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
function cookieValue(request) {
  const matches = String(request.headers.get('Cookie') || '').split(';').map(x=>x.trim())
    .filter(x=>x.startsWith(COOKIE + '='));
  // Duplicate cookie names can be injected from less trusted subdomains.
  // Never pick an arbitrary identity when there is ambiguity.
  if (matches.length !== 1) return '';
  try { return decodeURIComponent(matches[0].slice(COOKIE.length + 1)); }
  catch { return ''; }
}
async function sign(id, root, secret, issued) {
  const payload = [VERSION, id.toLowerCase(), issued].join('.');
  const mac = await crypto.subtle.sign('HMAC',await key(secret,root),encoder.encode(payload));
  return payload + '.' + b64(new Uint8Array(mac));
}
export async function getRootBrowserIdentity(request,env,nowMs=Date.now()) {
  const site=scope(new URL(request.url).hostname),secret=material(env);
  if (!site || !secret) return {state:'disabled',id:null,token:null,shouldSetCookie:false,root:site?.root||null};
  const raw=cookieValue(request),parts=raw.split('.');
  const now=Math.floor(nowMs/1000);
  if (raw.length < 512 && parts.length===4 && parts[0]===VERSION
      && UUID.test(parts[1]) && /^\d{10}$/.test(parts[2])) {
    const issued=Number(parts[2]),signature=decode(parts[3]);
    if (issued>0 && issued<=now+SKEW && now-issued<=LIFETIME && signature) {
      const payload=parts.slice(0,3).join('.');
      const verified=await crypto.subtle.verify('HMAC',await key(secret,site.root),
        signature,encoder.encode(payload));
      if (verified) {
        const refresh=now-issued>=REFRESH;
        return {state:refresh?'rotated':'valid',id:parts[1].toLowerCase(),
          token:refresh?await sign(parts[1],site.root,secret,now):raw,
          shouldSetCookie:refresh,root:site.root};
      }
    }
  }
  const id=crypto.randomUUID().toLowerCase();
  return {state:'issued',id,token:await sign(id,site.root,secret,now),
    shouldSetCookie:true,root:site.root};
}

export function buildRootBrowserCookie(token,root) {
  // __Secure- (not __Host-) is required because Domain legitimately spans
  // first-party subdomains. HMAC makes an overwritten token non-authoritative.
  return [COOKIE + '=' + encodeURIComponent(token), 'Domain=' + root,
    'Path=/','Max-Age=' + LIFETIME,'Secure','HttpOnly','SameSite=Lax','Priority=High'].join('; ');
}
function appendCookie(response,cookie) {
  const headers=new Headers(response.headers);
  headers.append('Set-Cookie',cookie);
  headers.set('Cache-Control','private, no-store, max-age=0');
  return new Response(response.body,{status:response.status,
    statusText:response.statusText,headers});
}
export async function handleRootBrowserEndpoint(request,env,url) {
  if (url.pathname!==PATH) return null;
  if (!scope(url.hostname)) return null;
  const headers={
    'Content-Type':'application/json; charset=utf-8',
    'Cache-Control':'private, no-store, max-age=0',
    'Referrer-Policy':'no-referrer',
    'X-Content-Type-Options':'nosniff',
    'X-Robots-Tag':'noindex, nofollow, noarchive',
    'Cross-Origin-Resource-Policy':'same-origin',
  };
  if (request.method!=='GET' && request.method!=='HEAD')
    return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}),
      {status:405,headers:{...headers,Allow:'GET, HEAD'}});
  if (request.headers.get('Sec-Fetch-Site')==='cross-site')
    return new Response(JSON.stringify({error:'SAME_ORIGIN_REQUIRED'}),{status:403,headers});
  const state=await getRootBrowserIdentity(request,env);
  if (state.state==='disabled')
    return new Response(JSON.stringify({enabled:false,reason:'SIGNING_NOT_CONFIGURED'}),
      {status:503,headers});
  // A central, explicit opt-in record can identify this browser across
  // separately owned first-party roots. It never affects auth or device bans.
  // KV is eventually consistent; after approval, the link may take time
  // to become visible and a read failure leaves the local ID unchanged.
  let linkedGlobal=null;
  if(request.method==='GET' && (state.state==='valid'||state.state==='rotated')){
    const {readConsentedBrowserLink}=await import('./anonymous-browser-bridge.js');
    linkedGlobal=await readConsentedBrowserLink(env,state.root,state.id,request);
  }
  const body=request.method==='HEAD'?null:JSON.stringify({
    enabled:true,
    scope:linkedGlobal?'consented-cross-root':'first-party-root',
    rootDomain:state.root,
    globalBrowserId:linkedGlobal||state.id,
    siteBrowserId:state.id,
    crossRootLinked:Boolean(linkedGlobal),
    // Only explicit, first-party human approval can enable a cross-root link.
    bridgeAvailable:env?.ANON_BROWSER_BRIDGE_ENABLED==='true'
      && Boolean(env?.CONSENT_KV)
      && (state.root==='vynlink.xyz'||state.root==='zokivo.xyz'),
    connectPath:state.root==='vynlink.xyz'||state.root==='zokivo.xyz'
      ?'/__vynalth/browser/bridge':null,
    unlinkPath:state.root==='vynlink.xyz'||state.root==='zokivo.xyz'
      ?'/__vynalth/browser/bridge/unlink':null,
    browserCredentialSigned:true,
    credentialState:state.state,
    lifetimeDays:90,
    accountLinked:false,
    hardwareVerified:false,
    crossBrowserLinked:false,
    securityAuthorization:false,
    warning:'Not a hardware ID or authorization. Separate browsers are not linked. Other roots require explicit approval.',
  });
  let response=new Response(body,{status:200,headers});
  if (request.method==='GET' && state.shouldSetCookie)
    response=appendCookie(response,buildRootBrowserCookie(state.token,state.root));
  return response;
}

export async function addRootBrowserToDocumentResponse(request,response,env,url) {
  if (request.method!=='GET' || response.status!==200 || url.protocol!=='https:') return response;
  if (!scope(url.hostname) || !material(env)) return response;
  if (url.pathname.startsWith('/__vynalth/') || url.pathname.startsWith('/.well-known/')) return response;
  if (BOTS.test(request.headers.get('User-Agent')||'')) return response;
  const dest=request.headers.get('Sec-Fetch-Dest');
  if (dest && dest!=='document') return response;
  if (!(request.headers.get('Accept')||'').includes('text/html')) return response;
  if (!(response.headers.get('Content-Type')||'').toLowerCase().includes('text/html')) return response;
  const state=await getRootBrowserIdentity(request,env);
  return state.shouldSetCookie
    ? appendCookie(response,buildRootBrowserCookie(state.token,state.root))
    : response;
}
