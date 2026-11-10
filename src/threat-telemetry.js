import { getRootDomain } from './managed-domains.js';
import { isPhpInfoHoneypotPath } from './phpinfo-honeypot.js';
import { matchPhpHoneypot } from './php-honeypots.js';

// Opt-in collection of narrow security-probe observations reaching this Worker.
// This is NOT a Cloudflare WAF log stream or evidence of a confirmed intrusion.
const INGEST_URL = 'https://vynalthai.com/api/security/ingest';
const ACCEPTED_METHODS = new Set(['GET','HEAD','POST']);
const DECOY_METHODS = new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS']);
// Never forward attacker-controlled path segments. Preserve only broad
// security-probe *categories*, with no personal data or arbitrary text.
const PATH_PROBES = [
  [/^\/(?:\.env(?:\.|\/|$))/, '/.env'],
  [/^\/(?:\.git(?:\/|$))/, '/.git/*'],
  [/^\/(?:\.svn(?:\/|$))/, '/.svn/*'],
  [/^\/api\/\.env(?:\.|\/|$)/, '/api/.env'],
  [/^\/api\/config\.json$/, '/api/config.json'],
  [/^\/api\/secrets?(?:\/|$)/, '/api/secrets/*'],
  [/^\/wp-admin(?:\/|$)/, '/wp-admin/*'],
  [/^\/wp-login\.php$/, '/wp-login.php'],
  [/^\/xmlrpc\.php$/, '/xmlrpc.php'],
  [/^\/server-status(?:\/|$)/, '/server-status/*'],
  [/^\/actuator\/env(?:\/|$)/, '/actuator/env'],
  [/^\/cgi-bin\//, '/cgi-bin/*'],
  // Unified edge observes explicit decoy-route probes across managed hosts.
  // The routes are telemetry-only here; no administrative pages are exposed.
  [/^\/_system\/(?:console|api|environment|database|storage|deployments|debug|identity|health|backups)\/?$/, '/_system/honeypot']
];

export function isObservedSecurityProbe(request) {
  if (!request) return false;
  const url = new URL(request.url);
  if (isPhpInfoHoneypotPath(url.pathname) ||
      matchPhpHoneypot(url.pathname)) return DECOY_METHODS.has(request.method);
  if (!ACCEPTED_METHODS.has(request.method)) return false;
  if (url.pathname === '/api/security/ingest') return false;
  return PATH_PROBES.some(([pattern]) => pattern.test(url.pathname));
}

export function scheduleThreatTelemetry(request, env, ctx, requestId, status = null) {
  if (env?.THREAT_INTEL_COLLECT_ENABLED !== 'true') return false;
  if (typeof env.THREAT_INTEL_INGEST_TOKEN !== 'string' ||
      env.THREAT_INTEL_INGEST_TOKEN.length < 32 ||
      !ctx || typeof ctx.waitUntil !== 'function' ||
      !isObservedSecurityProbe(request)) return false;
  const url = new URL(request.url);
  if (!getRootDomain(url.hostname)) return false;

  // Never send an IP, cookies, query strings, body, UA, GPS or visitor identity.
  const matchedPhp = matchPhpHoneypot(url.pathname);
  const isPhpDecoy = isPhpInfoHoneypotPath(url.pathname) || Boolean(matchedPhp);
  const probeTemplate = isPhpInfoHoneypotPath(url.pathname) ? '/api/phpinfo.php' :
    matchedPhp ? matchedPhp.path :
    PATH_PROBES.find(([pattern]) => pattern.test(url.pathname))?.[1];
  if (!probeTemplate) return false;
  const event = {
    source: isPhpDecoy ? 'honeypot' : 'cloudflare_worker',
    host: url.hostname,
    timestamp: new Date().toISOString(),
    path: probeTemplate,
    method: request.method,
    classification: 'suspicious_probe',
    action: 'log',
    ...(Number.isInteger(status) && status >= 100 && status <= 599 ? { status } : {}),
    eventId: request.headers.get('CF-Ray') || requestId,
  };
  const token = env.THREAT_INTEL_INGEST_TOKEN;
  const operation = (async () => {
    try {
      const response = await fetch(INGEST_URL, {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + token,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(event),
        redirect: 'manual',
        signal: AbortSignal.timeout(3500),
      });
      if (response.status !== 202) {
        // Never log authorization, body or response data.
        console.warn('[shield-threat-telemetry] delivery refused; status', response.status);
      }
    } catch {
      console.warn('[shield-threat-telemetry] delivery unavailable');
    }
  })();
  ctx.waitUntil(operation);
  return true;
}
