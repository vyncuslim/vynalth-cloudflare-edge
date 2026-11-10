import { getRootDomain } from './managed-domains.js'
import { isObservedSecurityProbe } from './threat-telemetry.js'

// These two hard-coded destinations are the publisher hosts, never attacker input.
const AXIOM_ACCESS_ENDPOINT = 'https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-access-logs'
const POSTHOG_HOSTS = new Set(['us.i.posthog.com', 'eu.i.posthog.com'])
const ALLOWED_METHODS = new Set(['GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'])

export function routeFamily(pathname) {
  if (typeof pathname !== 'string') return '/other/*'
  if (pathname === '/') return '/'
  if (pathname === '/robots.txt' || pathname === '/sitemap.xml') return pathname
  if (pathname.startsWith('/api/')) return '/api/*'
  if (pathname.startsWith('/_next/')) return '/_next/*'
  if (pathname.startsWith('/auth/')) return '/auth/*'
  if (pathname.startsWith('/__shield/')) return '/__shield/*'
  if (pathname.startsWith('/_system/')) return '/_system/*'
  if (pathname.startsWith('/media/')) return '/media/*'
  if (pathname.startsWith('/c/')) return '/c/*'
  return '/page/*'
}

export function buildAccessObservation({ request, url, response, requestId, responseTimeMs, now = Date.now() }) {
  if (!request || !response || !url) return null
  const root = getRootDomain(url.hostname)
  if (!root || !ALLOWED_METHODS.has(request.method) ||
      !Number.isInteger(response.status) || response.status < 100 || response.status > 599) return null
  const id = typeof requestId === 'string' && /^[0-9a-f-]{36}$/i.test(requestId)
    ? requestId : null
  if (!id) return null
  return {
    _time: new Date(now).toISOString(),
    event_id: id,
    event: 'HTTP_REQUEST',
    log_type: 'access',
    source: 'cloudflare_worker',
    service: 'vynalth-cloudflare-edge',
    environment: 'production',
    host: url.hostname.toLowerCase(),
    root_domain: root,
    path: routeFamily(url.pathname),
    http_method: request.method,
    status_code: response.status,
    response_time_ms: Number.isFinite(responseTimeMs) ? Math.max(0, Math.round(responseTimeMs)) : null,
    security_probe: isObservedSecurityProbe(request),
    request_id: id,
    pii_policy: 'allowlist-v1',
    observation: 'worker_response',
  }
}

function otlpValue(value) {
  if (typeof value === 'boolean') return { boolValue: value }
  if (typeof value === 'number') return { intValue: String(value) }
  return { stringValue: String(value) }
}
export function toPostHogOtlp(event) {
  const severityNumber = event.status_code >= 500 ? 17 : event.status_code >= 400 ? 13 : 9
  const severityText = event.status_code >= 500 ? 'ERROR' : event.status_code >= 400 ? 'WARN' : 'INFO'
  const attributes = Object.entries(event)
    .filter(([key,value]) => value !== null && key !== '_time')
    .map(([key,value]) => ({ key, value: otlpValue(value) }))
  const resourceAttributes = [
    { key:'service.name', value: otlpValue(event.service) },
    { key:'deployment.environment', value: otlpValue(event.environment) },
  ]
  const milliseconds = Date.parse(event._time)
  return { resourceLogs: [{
    resource: { attributes: resourceAttributes },
    scopeLogs: [{
      scope: { name:'vynalth-edge-dual-logs' },
      logRecords: [{
        timeUnixNano: String(milliseconds) + '000000',
        severityNumber, severityText,
        body: { stringValue:'HTTP_REQUEST' },
        attributes
      }],
    }],
  }] }
}

export function validatedPostHogEndpoint(value) {
  try {
    const url = new URL(value)
    if (url.protocol !== 'https:' || url.username || url.password || url.port ||
        !POSTHOG_HOSTS.has(url.hostname) || url.pathname !== '/i/v1/logs' ||
        url.search || url.hash) return null
    return url.href
  } catch { return null }
}

export async function dispatchEdgeAccessLogs(args, fetchImpl = fetch) {
  const { env, request, url, response, requestId, responseTimeMs } = args || {}
  if (env?.EDGE_DUAL_LOGS_ENABLED !== 'true') return { state:'disabled' }
  const event = buildAccessObservation({ request, url, response, requestId, responseTimeMs })
  if (!event) return { state:'invalid_event' }

  const jobs = []
  if (typeof env.AXIOM_ACCESS_INGEST_TOKEN === 'string' && env.AXIOM_ACCESS_INGEST_TOKEN.length >= 32) {
    jobs.push((async () => {
      try {
        const result = await fetchImpl(AXIOM_ACCESS_ENDPOINT, {
          method:'POST',
          headers:{ Authorization:'Bearer ' + env.AXIOM_ACCESS_INGEST_TOKEN,
            'Content-Type':'application/json' },
          body:JSON.stringify([event]), redirect:'manual',
          signal:AbortSignal.timeout(4000)
        })
        if (!result.ok) return { destination:'axiom', state:'rejected', status:result.status }
        const ack = await result.json().catch(() => null)
        return { destination:'axiom',
          state:ack?.ingested === 1 && (!ack.failed || ack.failed === 0)
            ? 'ingested' : 'unconfirmed' }
      } catch { return { destination:'axiom', state:'failed' } }
    })())
  } else jobs.push(Promise.resolve({ destination:'axiom', state:'not_configured' }))

  const postHogEndpoint = validatedPostHogEndpoint(env.POSTHOG_LOGS_ENDPOINT)
  if (typeof env.POSTHOG_PROJECT_TOKEN === 'string' &&
      env.POSTHOG_PROJECT_TOKEN.startsWith('phc_') && postHogEndpoint) {
    jobs.push((async () => {
      try {
        const result = await fetchImpl(postHogEndpoint, {
          method:'POST',
          headers:{ Authorization:'Bearer ' + env.POSTHOG_PROJECT_TOKEN,
            'Content-Type':'application/json' },
          body:JSON.stringify(toPostHogOtlp(event)), redirect:'manual',
          signal:AbortSignal.timeout(4000)
        })
        return { destination:'posthog', state:result.ok ? 'accepted' : 'rejected',
          ...(!result.ok ? { status:result.status } : {}) }
      } catch { return { destination:'posthog', state:'failed' } }
    })())
  } else jobs.push(Promise.resolve({ destination:'posthog', state:'not_configured' }))

  // A successful HTTP response confirms acceptance, not eventual indexing.
  const results = await Promise.all(jobs)
  for (const item of results) {
    if (item.state !== 'ingested' && item.state !== 'accepted') {
      console.warn('[EDGE DUAL LOGS]', item.destination, item.state,
        typeof item.status === 'number' ? item.status : '')
    }
  }
  return { state:'processed', results }
}

export function scheduleEdgeAccessLogs(args) {
  if (args?.env?.EDGE_DUAL_LOGS_ENABLED !== 'true' ||
      !args.ctx || typeof args.ctx.waitUntil !== 'function') return false
  args.ctx.waitUntil(dispatchEdgeAccessLogs(args))
  return true
}
