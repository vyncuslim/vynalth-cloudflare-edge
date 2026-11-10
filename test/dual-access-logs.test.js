import { test } from 'node:test'
import assert from 'node:assert/strict'
import { MANAGED_ROOT_DOMAINS } from '../src/managed-domains.js'
import { routeFamily, buildAccessObservation, toPostHogOtlp,
  validatedPostHogEndpoint, dispatchEdgeAccessLogs, scheduleEdgeAccessLogs } from '../src/dual-access-logs.js'

const base = {
  EDGE_DUAL_LOGS_ENABLED: 'true',
  AXIOM_ACCESS_INGEST_TOKEN: 'test-' + 'a'.repeat(36),
  POSTHOG_PROJECT_TOKEN: 'phc_' + 'b'.repeat(36),
  POSTHOG_LOGS_ENDPOINT: 'https://us.i.posthog.com/i/v1/logs',
}

function fixture(url = 'https://vynalthai.com/api/private/123?q=topsecret') {
  return {
    request: new Request(url, { method:'GET', headers: {
      'Authorization':'Bearer topsecret',
      'Cookie':'session=topsecret',
      'CF-Connecting-IP':'192.0.2.44',
      'User-Agent':'example-secret-agent',
    }}),
    url: new URL(url), response: new Response('', { status: 403 }),
    requestId:'9a78b90a-92de-48ad-816f-d652d16d65d5', responseTimeMs:23,
  }
}

test('sitewide hostname inventory is covered without leaking URL query or request headers', () => {
  for (const root of MANAGED_ROOT_DOMAINS) {
    const args = fixture('https://' + root + '/api/users/123?token=private')
    const event = buildAccessObservation(args)
    assert.equal(event.root_domain, root)
    assert.equal(event.host, root)
    assert.equal(event.path, '/api/*')
    assert.equal(event.status_code, 403)
    for (const raw of ['private','192.0.2.44','topsecret','example-secret-agent','/users/123']) {
      assert.ok(!JSON.stringify(event).includes(raw), raw)
    }
  }
  assert.equal(buildAccessObservation(fixture('https://unmanaged.invalid/secret')), null)
})

test('route family is deliberately low cardinality', () => {
  assert.equal(routeFamily('/api/account/super-secret'), '/api/*')
  assert.equal(routeFamily('/auth/callback/google'), '/auth/*')
  assert.equal(routeFamily('/__shield/gps/challenge'), '/__shield/*')
  assert.equal(routeFamily('/'), '/')
})

test('PostHog OTLP payload matches allowlisted Axiom event ID and service', () => {
  const event = buildAccessObservation(fixture())
  const payload = toPostHogOtlp(event)
  const raw = JSON.stringify(payload)
  assert.match(raw, /9a78b90a-92de-48ad-816f-d652d16d65d5/)
  assert.match(raw, /service.name/)
  assert.match(raw, /vynalth-cloudflare-edge/)
  assert.match(raw, /HTTP_REQUEST/)
  assert.doesNotMatch(raw, /topsecret|192\.0\.2\.44|private\/123|Bearer/)
  assert.equal(payload.resourceLogs[0].scopeLogs[0].logRecords[0].severityNumber, 13)
})

test('refuse PostHog endpoint injection and unknown regions', () => {
  assert.equal(validatedPostHogEndpoint('https://us.i.posthog.com/i/v1/logs'), 'https://us.i.posthog.com/i/v1/logs')
  for (const input of ['http://us.i.posthog.com/i/v1/logs',
    'https://us.i.posthog.com.attacker.invalid/i/v1/logs',
    'https://us.i.posthog.com/i/v1/logs?token=x',
    'https://attacker.invalid/i/v1/logs', 'file:///tmp/logs']) {
    assert.equal(validatedPostHogEndpoint(input), null, input)
  }
})

test('dispatch attempts both destinations with the same ID and isolated failures', async () => {
  const calls = []
  const result = await dispatchEdgeAccessLogs({ ...fixture(), env:base },
    async (url, init) => {
      calls.push({url,body:JSON.parse(init.body)})
      if (url.includes('axiom.co')) return new Response(JSON.stringify({ ingested:1,failed:0 }),{status:200})
      return new Response('upstream unavailable',{status:503})
    })
  assert.equal(calls.length, 2)
  assert.equal(result.state, 'processed')
  assert.deepEqual(result.results.map(x=>x.state),['ingested','rejected'])
  assert.equal(calls[0].body[0].event_id,
    calls[1].body.resourceLogs[0].scopeLogs[0].logRecords[0].attributes.find(x=>x.key==='event_id').value.stringValue)
})

test('off by default and waitUntil enrollment is non-blocking', async () => {
  const off=await dispatchEdgeAccessLogs({ ...fixture(), env:{} },()=>{throw Error('must not call')})
  assert.equal(off.state,'disabled')
  const queued=[]
  assert.equal(scheduleEdgeAccessLogs({ ...fixture(),env:{EDGE_DUAL_LOGS_ENABLED:'true'},
    ctx:{waitUntil(p){queued.push(p)}}}),true)
  assert.equal(queued.length,1)
  const outcome=await queued[0]
  assert.deepEqual(outcome.results.map(x=>x.state),['not_configured','not_configured'])
})
