import { verifyEdgeDevice } from './domain-device-id.js';
import { VynalthWafState } from './vwaf-state.js';
import { matchPhpHoneypot } from './php-honeypots.js';
import { isPhpInfoHoneypotPath } from './phpinfo-honeypot.js';

const encoder = new TextEncoder();
const MINUTE = 60000;
const BLOCK_MS = 72 * 3600000;
const WINDOW_MS = 10 * MINUTE;
const SAFE_PATH = /^\/(?:\.well-known\/|__vynalth\/|__shield\/|__observability\/|__ops\/|auth(?:\/|$)|status(?:\/|$)|recover(?:\/|$)|block-ip(?:\/|$)|contact(?:\/|$)|api\/(?:health|status|security\/recovery)(?:\/|$)|(?:en|cn|ms)\/(?:privacy|terms|contact)(?:\/|$)|(?:assets|static|_next|_assets)\/)/i;
const SEARCH_HOST = 'search.vynalthai.com';
const APEX = 'vynalthai.com';

export function classifySiteRequest(request) {
  const u = new URL(request.url);
  const path = u.pathname.toLowerCase().replace(/\/+$/, '') || '/';
  const method = request.method.toUpperCase();
  if (SAFE_PATH.test(path) || method === 'OPTIONS') return null;
  if (method === 'GET' && u.hostname === SEARCH_HOST && path === '/api/images') return 'IMAGE';
  if (method === 'GET' && u.hostname === SEARCH_HOST && path === '/api/search') return 'SEARCH';
  if (method === 'POST' && u.hostname === APEX && path === '/api/ai/image') return 'IMAGE';
  if (['POST', 'GET'].includes(method) && u.hostname === APEX && path === '/api/web-search') return 'SEARCH';
  if (method === 'POST' && u.hostname === APEX && ['/api/signup','/api/auth/signup'].includes(path)) return 'SIGNUP';
  // This does not cover direct Supabase Auth signups; those require an origin-side fix.
  if (['GET','HEAD'].includes(method) && !path.startsWith('/api/') &&
      path !== '/api' && !/\.[a-z0-9]{1,8}$/i.test(path) &&
      (request.headers.get('accept') || '').includes('text/html') &&
      ['','document'].includes(request.headers.get('sec-fetch-dest') || '') &&
      request.cf?.botManagement?.verifiedBot !== true) return 'DOC';
  return null;
}

export function classifyPrivateDecoy(request) {
  if (!['GET','HEAD','POST'].includes(request.method)) return null;
  const path = new URL(request.url).pathname.toLowerCase();
  if (/^\/wp-admin\/install\.php\/?$/.test(path)) return '/wp-admin/install.php';
  if (isPhpInfoHoneypotPath(path)) return '/api/phpinfo.php';
  // Only existing allowlisted static decoys; never ordinary 403/429 or a generic API route.
  const decoy = matchPhpHoneypot(path);
  return decoy?.path || null;
}

export function advanceDeviceRisk(prior, probe, now) {
  const state = prior && typeof prior === 'object' ? prior : {};
  if (Number.isFinite(state.blockUntil) && state.blockUntil > now)
    return { blockUntil: state.blockUntil, probes: [] };
  const probes = Array.isArray(state.probes)
    ? state.probes.filter(p => typeof p.id === 'string' && typeof p.category === 'string' &&
        Number.isFinite(p.at) && p.at <= now && p.at > now - WINDOW_MS).slice(-20) : [];
  if (probe && !probes.some(p => p.id === probe.id)) {
    probes.push({ id: probe.id, category: probe.category, at: now });
  }
  if (probes.length >= 5 && new Set(probes.map(p => p.category)).size >= 3)
    return { blockUntil: now + BLOCK_MS, probes: [] };
  return { blockUntil: 0, probes: probes.slice(-20) };
}

export class SecurityDeviceRisk {
  constructor(state, env) { this.state = state; this.vwaf = new VynalthWafState(state,env); }
  async fetch(request) {
    // Internal, disjoint VWAF objects share this deployed class to avoid a migration.
    // Legacy device-risk objects use hex HMAC names and the device-risk.internal URL.
    const url = new URL(request.url);
    if (url.origin === 'https://vwaf.internal' && url.pathname === '/' && !url.search) {
      if (await this.state.storage.get('risk')) return new Response(null,{status:409});
      return this.vwaf.fetch(request);
    }
    // Never allow the legacy protocol to modify a VWAF object.
    if (await this.state.storage.get('actor') || await this.state.storage.get('ledger'))
      return new Response(null,{status:409});
    if (request.method !== 'POST') return new Response(null, { status: 405 });
    let body;
    try { body = await request.json(); } catch { return new Response(null, { status: 400 }); }
    const now = Date.now();
    if (body?.op === 'status') {
      const existing = await this.state.storage.get('risk');
      return Response.json({ blockedUntil: existing?.blockUntil > now ? existing.blockUntil : 0 });
    }
    if (body?.op !== 'probe' || !/^[a-z0-9-]{20,80}$/i.test(body.id || '') ||
        typeof body.category !== 'string' || !body.category.startsWith('/') ||
        body.category.length > 160) return new Response(null, { status: 400 });
    const next = await this.state.storage.transaction(async txn => {
      const old = await txn.get('risk');
      const updated = advanceDeviceRisk(old, { id: body.id, category: body.category }, now);
      await txn.put('risk', updated);
      return updated;
    });
    // Clean up short observation state and expired restrictions. Alarm re-checks the deadline.
    await this.state.storage.setAlarm(next.blockUntil || now + WINDOW_MS);
    return Response.json({ blockedUntil: next.blockUntil });
  }
  async alarm() {
    // Only the new disjoint object names can have actor or ledger keys.
    if (await this.state.storage.get('actor') || await this.state.storage.get('ledger'))
      return this.vwaf.alarm();
    const now = Date.now();
    const state = await this.state.storage.get('risk');
    if (state?.blockUntil > now) return this.state.storage.setAlarm(state.blockUntil);
    const latest = Math.max(0, ...(state?.probes || []).map(x => x.at || 0));
    if (latest + WINDOW_MS > now) return this.state.storage.setAlarm(latest + WINDOW_MS);
    await this.state.storage.delete('risk');
  }
}

async function keyedDigest(env, host, kind, value) {
  const material = env?.EDGE_DEVICE_ID_SIGNING_SECRET || env?.VISITOR_IP_SIGNING_SECRET;
  if (typeof material !== 'string' || material.length < 32) return null;
  const key = await crypto.subtle.importKey('raw', encoder.encode(material), { name:'HMAC', hash:'SHA-256' }, false, ['sign']);
  const out = new Uint8Array(await crypto.subtle.sign('HMAC', key,
    encoder.encode('vynalth:site-abuse:v1:' + host + ':' + kind + ':' + value)));
  return Array.from(out, n => n.toString(16).padStart(2,'0')).join('');
}

function denial(status, error, retryAfter) {
  return Response.json({ success:false, error, retryAfterSeconds:retryAfter,
    appeal:'vyncuslim@vynalthai.com' }, {status, headers:{
    'Cache-Control':'private, no-store', 'Retry-After':String(retryAfter),
    'X-Content-Type-Options':'nosniff', 'X-Vynalth-Site-Abuse':error,
  }});
}

export async function enforceSiteAbuse(request, env, requestId, now = Date.now()) {
  const mode = env?.SECURITY_SITE_ABUSE_MODE;
  if (mode !== 'enforce' && mode !== 'observe') return null;
  const u = new URL(request.url);
  const hosts = new Set(String(env?.SECURITY_SITE_ABUSE_HOSTS || '').split(',').map(x=>x.trim().toLowerCase()).filter(Boolean));
  if (!hosts.has(u.hostname)) return null;
  const category = classifySiteRequest(request);
  const probe = classifyPrivateDecoy(request);
  if (!category && !probe) return null;
  try {
    let deviceKey = null;
    // Never mint an identity just because a request arrived. Only an already
    // signed, host-bound cookie participates. Ignore issued/forged tokens.
    if (/(?:^|;\s*)__Host-vyn_edge_device=/.test(request.headers.get('cookie') || '')) {
      const verified = await verifyEdgeDevice(request, env);
      if (['valid','rotated'].includes(verified.state)) {
        deviceKey = await keyedDigest(env, u.hostname, 'device', verified.deviceId);
      }
    }
    if (deviceKey && env.SECURITY_DEVICE_RISK?.idFromName) {
      const stub = env.SECURITY_DEVICE_RISK.get(env.SECURITY_DEVICE_RISK.idFromName(deviceKey));
      const result = await stub.fetch('https://device-risk.internal/', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify(probe ? {op:'probe',id:requestId,category:probe} : {op:'status'}),
      });
      if (!result.ok) throw new Error('device policy unavailable');
      const state = await result.json();
      if (Number.isFinite(state.blockedUntil) && state.blockedUntil > now) {
        console.info('[site-abuse] device restriction', { host:u.hostname, mode, category:probe ? 'decoy' : category });
        if (mode === 'enforce') return denial(403,'SIGNED_DEVICE_TEMPORARILY_RESTRICTED',Math.ceil((state.blockedUntil-now)/1000));
      }
    }
    if (!category) return null;
    const binding = env['SECURITY_' + category + '_RATE'];
    if (!binding?.limit) return null;
    const ip = request.headers.get('CF-Connecting-IP') || '';
    // No forwarded headers, client-supplied ID, browser fingerprint or raw IP in counters.
    // Cloudflare's shared cross-zone Worker address is not a visitor identity.
    const edgeIp = request.cf && /^[0-9a-f:.]{3,45}$/i.test(ip) && ip !== '2a06:98c0:3600::103' ? ip : null;
    const ipKey = edgeIp ? await keyedDigest(env,u.hostname,'ip',edgeIp) : null;
    for (const key of [deviceKey,ipKey].filter(Boolean)) {
      const result = await binding.limit({key});
      if (result?.success === false) {
        console.info('[site-abuse] rate limit', {host:u.hostname, mode, category});
        if (mode === 'enforce') return denial(429,'SITE_RATE_LIMITED',60);
      }
    }
  } catch {
    // This is a supplemental availability control, not an authentication gate.
    // Existing WAF, existing global device policy and origin authorization remain.
    console.warn('[site-abuse] supplemental control unavailable');
  }
  return null;
}
