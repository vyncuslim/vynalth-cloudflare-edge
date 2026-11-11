import { toPostHogOtlp, routeFamily } from './dual-access-logs.js'
import { getRootDomain } from './managed-domains.js'
const AXIOM_ACCESS_ENDPOINT = 'https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-access-logs'
const REGION_ENDPOINTS = new Set([
  'https://us.i.posthog.com/i/v1/logs',
  'https://eu.i.posthog.com/i/v1/logs',
])
const SOURCES = new Set(['build','edge','lambda','static','external','firewall','redirect'])
const LEVELS = new Set(['info','warning','error','fatal'])
const MAX_BYTES = 2 * 1024 * 1024
const MAX_EVENTS = 1000
const BATCH_SIZE = 100

function textResponse(status, code) {
  return new Response(JSON.stringify({ error:code }),{
    status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}
  })
}

async function readLimited(request) {
  const advertised = Number(request.headers.get('content-length'))
  if (Number.isFinite(advertised) && advertised > MAX_BYTES) return null
  const reader=request.body?.getReader()
  if (!reader) return null
  const chunks=[]
  let size=0
  while (true) {
    const {value,done}=await reader.read()
    if (done) break
    size += value.byteLength
    if (size > MAX_BYTES) { await reader.cancel(); return null }
    chunks.push(value)
  }
  const bytes=new Uint8Array(size)
  let offset=0
  for (const c of chunks) {bytes.set(c,offset);offset+=c.length}
  return bytes
}

export async function verifyVercelDrainSignature(bytes, signed, secret) {
  if (!(bytes instanceof Uint8Array) || typeof signed !== 'string' ||
      !/^[0-9a-f]{40}$/i.test(signed) || typeof secret !== 'string' ||
      secret.length < 32) return false
  const key=await crypto.subtle.importKey('raw',new TextEncoder().encode(secret),
    { name:'HMAC',hash:'SHA-1' },false,['sign'])
  const computed=new Uint8Array(await crypto.subtle.sign('HMAC',key,bytes))
  const supplied=Uint8Array.from(signed.match(/.{2}/g),x=>parseInt(x,16))
  let diff=0
  for(let i=0;i<computed.length;i++) diff |= computed[i]^supplied[i]
  return diff===0
}

function safeText(value,re,max=120) {
  return typeof value==='string' && value.length>0 && value.length<=max &&
    re.test(value) ? value : null
}

export function sanitizeVercelDrainRecord(raw) {
  if (!raw || typeof raw!=='object' || Array.isArray(raw)) return null
  const id=safeText(raw.id,/^[a-z0-9_-]+$/i,128)
  const projectId=safeText(raw.projectId,/^[a-z0-9_-]+$/i,100)
  const source=SOURCES.has(raw.source)?raw.source:null
  if(!id || !projectId || !source) return null
  const project = safeText(raw.projectName,/^[a-z0-9_-]+$/i,80) || 'project'
  const status = Number.isInteger(raw.statusCode) && raw.statusCode>=100 &&
    raw.statusCode<=599 ? raw.statusCode : null
  const level=LEVELS.has(raw.level)?raw.level:'info'
  const time=Number.isInteger(raw.timestamp) && raw.timestamp>0 &&
    raw.timestamp<Date.now()+86400000 ? raw.timestamp : Date.now()
  const rawPath=typeof raw.path==='string' ? raw.path :
    typeof raw.proxy?.path==='string' ? raw.proxy.path : null
  const route=routeFamily(rawPath?rawPath.split('?')[0]:null)
  const name='vercel-'+project.toLowerCase()
  const observedHost=safeText(raw.host,/^[a-z0-9.-]+$/i,253)
  const managedRoot=observedHost ? getRootDomain(observedHost.toLowerCase()) : null
  // Do not forward message, proxy.clientIp, JA3/JA4, userAgent, referral,
  // raw path, query parameters, environment secrets or application payload.
  return {
    _time: new Date(time).toISOString(),
    event_id:'vercel:'+id,
    event:'VERCEL_LOG',
    source:'vercel_log_drain',
    service:name,
    environment: raw.environment==='production'?'production':'preview',
    host:managedRoot ? observedHost.toLowerCase() : '',
    root_domain:managedRoot || '',
    path:route,
    http_method:typeof raw.proxy?.method==='string' &&
      /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(raw.proxy.method)
        ? raw.proxy.method:'UNKNOWN',
    status_code:status,
    response_time_ms:null,
    security_probe:false,
    request_id:safeText(raw.requestId,/^[a-z0-9_-]+$/i,128)||'unavailable',
    pii_policy:'allowlist-v1',
    observation:source,
    log_level:level,
    project_id:projectId,
  }
}

export async function dispatchVercelDrainEvents(events,env,fetchImpl=fetch) {
  const axiomToken=env?.AXIOM_ACCESS_INGEST_TOKEN
  const posthogToken=env?.POSTHOG_PROJECT_TOKEN
  const posthogEndpoint=env?.POSTHOG_LOGS_ENDPOINT
  if(typeof axiomToken!=='string'||axiomToken.length<32||
    typeof posthogToken!=='string'||!posthogToken.startsWith('phc_')||
    !REGION_ENDPOINTS.has(posthogEndpoint)) return {state:'not_configured'}
  const results=[]
  for(let i=0;i<events.length;i+=BATCH_SIZE){
    const batch=events.slice(i,i+BATCH_SIZE)
    const otlp={resourceLogs:batch.map(e=>toPostHogOtlp(e).resourceLogs[0])}
    const [a,p]=await Promise.allSettled([
      fetchImpl(AXIOM_ACCESS_ENDPOINT,{
        method:'POST',headers:{Authorization:'Bearer '+axiomToken,'Content-Type':'application/json'},
        body:JSON.stringify(batch),redirect:'manual',signal:AbortSignal.timeout(6500),
      }),
      fetchImpl(posthogEndpoint,{
        method:'POST',headers:{Authorization:'Bearer '+posthogToken,'Content-Type':'application/json'},
        body:JSON.stringify(otlp),redirect:'manual',signal:AbortSignal.timeout(6500),
      })
    ])
    const axiomOk=a.status==='fulfilled' && a.value.ok &&
      (await a.value.json().catch(()=>null))?.ingested === batch.length
    const posthogOk=p.status==='fulfilled'&&p.value.ok
    results.push({count:batch.length,axiom:axiomOk,posthog:posthogOk})
    if(!axiomOk || !posthogOk) return {state:'retry',results}
  }
  return {state:'accepted',results}
}

export async function handleVercelDrain(request,env,fetchImpl=fetch) {
  if (env?.VERCEL_LOG_DRAIN_ENABLED!=='true')
    return textResponse(404,'not_found')
  if (request.method!=='POST') return textResponse(405,'method_not_allowed')
  if (typeof env?.VERCEL_LOG_DRAIN_SIGNING_SECRET!=='string' ||
      env.VERCEL_LOG_DRAIN_SIGNING_SECRET.length<32)
    return textResponse(503,'not_configured')
  const bytes=await readLimited(request)
  if (!bytes) return textResponse(413,'payload_too_large')
  if(!await verifyVercelDrainSignature(bytes,request.headers.get('x-vercel-signature'),
      env.VERCEL_LOG_DRAIN_SIGNING_SECRET))
    return textResponse(403,'invalid_signature')
  let parsed
  try { parsed=JSON.parse(new TextDecoder().decode(bytes)) }
  catch { return textResponse(400,'invalid_json') }
  if(!Array.isArray(parsed)||parsed.length<1||parsed.length>MAX_EVENTS)
    return textResponse(400,'unsupported_batch')
  const events=parsed.map(sanitizeVercelDrainRecord)
  if(events.some(x=>!x)) return textResponse(422,'invalid_record')
  const outcome=await dispatchVercelDrainEvents(events,env,fetchImpl)
  if(outcome.state!=='accepted') return textResponse(503,'delivery_pending_retry')
  return new Response(JSON.stringify({ok:true,received:events.length}),{
    status:200,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}
  })
}
