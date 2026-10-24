// Opt-in, low-interaction edge honeypots and privacy-conscious security telemetry.
// These traps never serve real files, credentials, database endpoints, or a login session.
const DECOYS = new Map([
  ['/__vynalth-hp/admin/login', 'admin-login'],
  ['/__vynalth-hp/phpinfo.php', 'php-config'],
  ['/__vynalth-hp/.env', 'environment-file'],
  ['/__vynalth-hp/.git/config', 'git-config'],
  ['/__vynalth-hp/db-admin', 'database-console'],
  ['/__vynalth-hp/api/internal', 'internal-api'],
  ['/__vynalth-hp/backup.zip', 'backup-archive'],
  ['/__vynalth-hp/form-submit', 'form-bot'],
  ['/__vynalth-hp/token-check', 'invalid-honeytoken'],
  ['/__vynalth-hp/hidden-link', 'hidden-link'],
]);
const PASSIVE_PROBES = new Map([
  ['/.env', 'environment-file'],
  ['/api/.env', 'environment-file'],
  ['/phpinfo.php', 'php-config'],
  ['/api/phpinfo.php', 'php-config'],
  ['/.git/config', 'git-config'],
  ['/wp-admin/', 'admin-login'],
  ['/xmlrpc.php', 'legacy-rpc'],
  ['/backup.zip', 'backup-archive'],
]);
const ROOT_INGEST = 'https://us-east-1.aws.edge.axiom.co';
function enabled(env) {
  return env?.SECURITY_TELEMETRY_ENABLED === 'true' &&
    typeof env?.AXIOM_SECURITY_INGEST_TOKEN === 'string' &&
    env.AXIOM_SECURITY_INGEST_TOKEN.length >= 20;
}
function ingestOrigin(env) {
  const url = new URL(env?.AXIOM_SECURITY_INGEST_BASE_URL || ROOT_INGEST);
  if (url.protocol !== 'https:' || url.username || url.password ||
      url.pathname !== '/' || url.search || url.hash ||
      !['us-east-1.aws.edge.axiom.co', 'eu-central-1.aws.edge.axiom.co'].includes(url.hostname))
    throw new Error('invalid Axiom ingest endpoint');
  return url.origin;
}
function limitedPath(path) {
  return String(path || '').split('/').map(s =>
    s.includes('@') || /^[0-9]{4,}$/.test(s) || /^[0-9a-f-]{20,}$/i.test(s)
      ? ':id' : s.slice(0, 60)).join('/').slice(0, 180);
}
function ipSource(request) {
  return request.headers.get('CF-Connecting-IP') ? 'cloudflare_edge' : 'unavailable';
}
async function anonymousActor(request, env) {
  const key = env?.SECURITY_TELEMETRY_HASH_KEY;
  const ip = request.headers.get('CF-Connecting-IP');
  if (typeof key !== 'string' || key.length < 32 || !ip || ip.length > 45) return undefined;
  const cryptoKey = await crypto.subtle.importKey('raw', new TextEncoder().encode(key),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const day = new Date().toISOString().slice(0, 10);
  const signature = await crypto.subtle.sign('HMAC', cryptoKey,
    new TextEncoder().encode(day + '|' + ip));
  return Array.from(new Uint8Array(signature).slice(0, 12), n => n.toString(16).padStart(2, '0')).join('');
}
async function eventBase(request, env, requestId, event, logType) {
  const url = new URL(request.url);
  const cf = request.cf || {};
  const actor = await anonymousActor(request, env);
  return {
    timestamp: new Date().toISOString(),
    service: 'vynalth-edge',
    source: 'cloudflare-worker',
    host: url.hostname.toLowerCase(),
    environment: 'production',
    event,
    log_type: logType,
    request_id: requestId,
    method: request.method,
    http_method: request.method,
    path: limitedPath(url.pathname),
    ip_source: ipSource(request),
    ...(actor ? { actor_id: actor } : {}),
    ...(typeof cf.country === 'string' && /^[A-Z]{2}$/.test(cf.country) ? { country: cf.country } : {}),
    ...(Number.isSafeInteger(cf.asn) ? { asn: cf.asn } : {}),
  };
}
async function ingest(env, dataset, event) {
  try {
    const url = ingestOrigin(env) + '/v1/ingest/' + dataset;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + env.AXIOM_SECURITY_INGEST_TOKEN,
      },
      body: JSON.stringify([event]),
      signal: AbortSignal.timeout(7000),
    });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    const result = await response.json();
    if (typeof result.failed === 'number' && result.failed !== 0)
      throw new Error('Axiom partial ingestion');
  } catch (error) {
    // Avoid sensitive payloads and raw error details in logs.
    console.warn('security_telemetry_ingest_failed', {
      dataset, reason: String(error).replace(/Bearer\s+\S+/gi, '[redacted]').slice(0, 100),
    });
  }
}
function enqueue(ctx, task) {
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(task);
}
export function honeypotType(path) {
  return DECOYS.get(path) || null;
}
export async function inspectHoneypotRequest(request, env, ctx, requestId) {
  if (env?.SECURITY_HONEYPOT_ENABLED !== 'true' || !enabled(env)) return null;
  const url = new URL(request.url);
  const trap = DECOYS.get(url.pathname);
  const passive = PASSIVE_PROBES.get(url.pathname);
  if (!trap && !passive) return null;
  const response = trap ? new Response('Not Found', {
    status: 404, headers: { 'Cache-Control': 'no-store', 'X-Robots-Tag': 'noindex, nofollow' },
  }) : null;
  const event = await eventBase(request, env, requestId,
    trap ? 'HONEYPOT_TRIGGER' : 'SENSITIVE_ROUTE_PROBE',
    trap ? 'honeypot' : 'security');
  event.trap = trap || passive;
  event.trap_mode = trap ? 'active-decoy' : 'passive-observation';
  // Only active decoy responses are controlled here. Existing app routes
  // (including /api/.env) continue to their original handlers untouched.
  if (response) event.status_code = response.status;
  enqueue(ctx, ingest(env, 'vynalth-security-logs', event));
  return response;
}
export function captureAccessTelemetry(request, response, env, ctx, requestId, startTime) {
  if (env?.SECURITY_ACCESS_MONITOR_ENABLED !== 'true' || !enabled(env)) return;
  const configured = Number(env?.SECURITY_ACCESS_SAMPLE_RATE ?? '0.02');
  const rate = Number.isFinite(configured) ? Math.max(0, Math.min(1, configured)) : 0.02;
  const probability = response.status >= 500 ? 1 : rate;
  if (Math.random() >= probability) return;
  enqueue(ctx, (async () => {
    const event = await eventBase(request, env, requestId, 'ACCESS_REQUEST', 'access');
    event.status_code = response.status;
    event.response_time_ms = Math.max(0, Date.now() - startTime);
    event.sample_probability = probability;
    const cache = response.headers.get('CF-Cache-Status');
    if (cache && /^[A-Z]{2,20}$/.test(cache)) event.cache_status = cache;
    await ingest(env, 'vynalth-access-logs', event);
  })());
}
