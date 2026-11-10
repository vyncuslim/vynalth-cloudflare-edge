import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHmac } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { verifyVercelDrainSignature, sanitizeVercelDrainRecord,
  handleVercelDrain } from '../src/vercel-log-drain.js'

const secret='secret-'+'a'.repeat(40)
const env={
  VERCEL_LOG_DRAIN_ENABLED:'true',
  VERCEL_LOG_DRAIN_SIGNING_SECRET:secret,
  AXIOM_ACCESS_INGEST_TOKEN:'test-'+'a'.repeat(36),
  POSTHOG_PROJECT_TOKEN:'phc_'+'b'.repeat(36),
  POSTHOG_LOGS_ENDPOINT:'https://us.i.posthog.com/i/v1/logs'
}
const original={
  id:'1573817250283254651097202070',
  deploymentId:'dpl_testing',
  projectId:'prj_test12345',
  projectName:'vynchapp',
  source:'lambda',
  timestamp:Date.now(),
  level:'error',
  message:'private body and password=top-secret',
  statusCode:500,
  path:'/api/private/account/123?secret=top-secret',
  requestId:'b351c4d8-ec32-4e0c-a3e5-0a91c47223ab',
  proxy:{
    method:'POST',clientIp:'192.0.2.44',path:'/api/users/123?token=top-secret',
    userAgent:['private-UA'],referer:'https://private.example'
  }
}
function makeRequest(body, signature) {
  return new Request('https://vynalthai.com/__observability/vercel-drain',{
    method:'POST',
    headers:{'Content-Type':'application/json','x-vercel-signature':signature},
    body
  })
}
function sign(body) {
  return createHmac('sha1',secret).update(body).digest('hex')
}

test('HMAC verification accepts authentic bytes and rejects modified bytes',async()=>{
  const body=JSON.stringify([original])
  const bytes=new TextEncoder().encode(body)
  assert.equal(await verifyVercelDrainSignature(bytes,sign(body),secret),true)
  assert.equal(await verifyVercelDrainSignature(bytes,sign(body+'x'),secret),false)
  assert.equal(await verifyVercelDrainSignature(bytes,'bad',secret),false)
})

test('source sanitization strips raw IP, user-agent, messages and query paths',()=>{
  const clean=sanitizeVercelDrainRecord(original)
  assert.equal(clean.service,'vercel-vynchapp')
  assert.equal(clean.status_code,500)
  assert.equal(clean.path,'/api/*')
  assert.equal(clean.event_id,'vercel:'+original.id)
  for(const s of ['192.0.2.44','top-secret','private-UA','private body',
    '/api/private/account/123','https://private.example']) {
      assert.equal(JSON.stringify(clean).includes(s),false,s)
  }
})

test('signed drain forwards only sanitized data to both Axiom and PostHog',async()=>{
  const body=JSON.stringify([original])
  const sent=[]
  const res=await handleVercelDrain(makeRequest(body,sign(body)),env,
    async (url,opts)=>{
      sent.push({url,body:JSON.parse(opts.body)})
      if(url.includes('axiom.co')) return new Response(JSON.stringify({ingested:1,failed:0}),{status:200})
      return new Response('{}',{status:200})
    })
  assert.equal(res.status,200)
  assert.equal(sent.length,2)
  for(const s of ['192.0.2.44','top-secret','private-UA','private body']) {
    assert.ok(!JSON.stringify(sent).includes(s),s)
  }
  assert.ok(JSON.stringify(sent[0]).includes('vercel:'+original.id))
  assert.ok(JSON.stringify(sent[1]).includes('vercel:'+original.id))
})

test('disabled drain, missing credentials and forged signature fail closed',async()=>{
  const body=JSON.stringify([original])
  let count=0
  const mock=async()=>{count++;return new Response(null,{status:204})}
  assert.equal((await handleVercelDrain(makeRequest(body,sign(body)),{},mock)).status,404)
  assert.equal((await handleVercelDrain(makeRequest(body,sign(body)),
    {VERCEL_LOG_DRAIN_ENABLED:'true'},mock)).status,503)
  assert.equal((await handleVercelDrain(makeRequest(body,sign(body+'x')),env,mock)).status,403)
  assert.equal(count,0)
})

test('failed mirror returns a retriable status, not false success',async()=>{
  const body=JSON.stringify([original])
  const res=await handleVercelDrain(makeRequest(body,sign(body)),env,async(url)=>{
    if(url.includes('axiom.co')) return new Response(JSON.stringify({ingested:1}),{status:200})
    return new Response('failed',{status:503})
  })
  assert.equal(res.status,503)
})

test('drain route never recursively logs itself through observedResponse',()=>{
  const edge=readFileSync(new URL('../src/index.js',import.meta.url),'utf8')
  const start=edge.indexOf('incomingUrl.pathname === "/__observability/vercel-drain"')
  assert.ok(start>0)
  assert.ok(edge.slice(start,start+120).includes('handleVercelDrain(request, env)'))
})
