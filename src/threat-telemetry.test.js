import test from 'node:test';
import assert from 'node:assert/strict';
import {isObservedSecurityProbe, scheduleThreatTelemetry} from './threat-telemetry.js';

const KEY='secret-'.padEnd(64,'b');
const env={THREAT_INTEL_COLLECT_ENABLED:'true',THREAT_INTEL_INGEST_TOKEN:KEY};
const req=(url='https://vynalthai.com/api/config.json?token=SENSITIVE',method='GET')=>
  new Request(url,{method,headers:{'CF-Ray':'abcdef1234567890-KUL'}});

test('only narrow security probes trigger, not regular pages',()=>{
  for(const path of ['/.env','/api/.env','/api/config.json','/.git/config','/wp-login.php','/cgi-bin/x'])
    assert.equal(isObservedSecurityProbe(req('https://vynalthai.com'+path)),true,path);
  for(const path of ['/','/api/security/ingest','/api/ai/chat','/auth/login','/.well-known/security.txt'])
    assert.equal(isObservedSecurityProbe(req('https://vynalthai.com'+path)),false,path);
});
test('explicit flag, long secret and waitUntil are mandatory',()=>{
  const ctx={waitUntil(){throw Error('unexpected background task')}};
  assert.equal(scheduleThreatTelemetry(req(),{},ctx,'a'),false);
  assert.equal(scheduleThreatTelemetry(req(),{THREAT_INTEL_COLLECT_ENABLED:'true'},ctx,'a'),false);
  assert.equal(scheduleThreatTelemetry(req(),env,{},'a'),false);
  assert.equal(scheduleThreatTelemetry(req('https://evil.example/.env'),env,ctx,'a'),false);
  assert.equal(scheduleThreatTelemetry(req('https://vynalthai.com.attacker.invalid/.env'),env,ctx,'a'),false);
});
test('sender strips visitor metadata and only targets first-party ingest',async()=>{
  const saved=globalThis.fetch;const sent=[];const tasks=[];
  globalThis.fetch=async(url,options)=>{sent.push({url,options});return new Response(null,{status:202})};
  try{
    const req0=new Request('https://search.vynalthai.com/api/config.json?token=SECRET',{
      headers:{'CF-Ray':'abcdef1234567890-KUL',Cookie:'session=SECRET',
        'CF-Connecting-IP':'203.0.113.14','User-Agent':'test-private-device'}});
    assert.equal(scheduleThreatTelemetry(req0,env,{waitUntil(p){tasks.push(p)}},'test-request'),true);
    await Promise.all(tasks);
    assert.equal(sent.length,1);
    assert.equal(sent[0].url,'https://vynalthai.com/api/security/ingest');
    assert.equal(sent[0].options.redirect,'manual');
    const body=JSON.parse(sent[0].options.body);
    assert.equal(body.source,'cloudflare_worker');
    assert.equal(body.classification,'suspicious_probe');
    assert.equal(body.path,'/api/config.json');
    assert.equal(body.eventId,'abcdef1234567890-KUL');
    for(const secret of ['SECRET','203.0.113.14','test-private-device'])
      assert.equal(JSON.stringify(body).includes(secret),false);
  }finally{globalThis.fetch=saved}
});
test('arbitrary path segments never enter telemetry payload',async()=>{
  const original=globalThis.fetch, task=[];
  let payload;
  globalThis.fetch=async(_url, opts)=>{payload=JSON.parse(opts.body);return new Response(null,{status:202})};
  try{
    const request=new Request('https://vynalthai.com/.git/config/very-private-visitor-identifier?key=SECRET');
    assert.equal(scheduleThreatTelemetry(request,env,{waitUntil(p){task.push(p)}},'id-1'),true);
    await Promise.all(task);
    assert.equal(payload.path,'/.git/*');
    assert.ok(!JSON.stringify(payload).includes('very-private-visitor-identifier'));
  }finally{globalThis.fetch=original}
});
test('transport failures do not impact request handling',async()=>{
  const fetch0=globalThis.fetch,warn=console.warn;
  globalThis.fetch=async()=>{throw Error('network unavailable')};console.warn=()=>{};
  try{const tasks=[];assert.equal(scheduleThreatTelemetry(req(),env,{waitUntil(p){tasks.push(p)}},'x'),true);
  await Promise.all(tasks)}finally{globalThis.fetch=fetch0;console.warn=warn}
});

test('all eleven managed domains and their subdomains forward only bounded probe metadata', async () => {
  const roots=['vynalthai.com','vynalthai.si','vyncuslim.com','vyncuslim.si',
    'vyncuslim.my','sleepsomno.com','vitamindai.online','powiismunc.com',
    'vynli.xyz','vynlink.xyz','zokivo.xyz'];
  const original=globalThis.fetch;
  const calls=[];const pending=[];
  globalThis.fetch=async(_url, options)=>{
    calls.push(JSON.parse(options.body));
    return new Response(null,{status:202});
  };
  try{
    for(const root of roots)for(const host of [root,'www.'+root]){
      assert.equal(scheduleThreatTelemetry(req('https://'+host+'/.git/config?key=secret'),
        env,{waitUntil(task){pending.push(task)}},'test-id'),true,host);
    }
    await Promise.all(pending);
    assert.equal(calls.length,roots.length*2);
    for(const event of calls){
      assert.equal(event.path,'/.git/*');
      assert.equal(event.source,'cloudflare_worker');
      assert.ok(!JSON.stringify(event).includes('secret'));
    }
    for(const host of ['vyncuslim.my.attacker.tld','notzokivo.xyz','evil.vynlink.xyz.attacker.test']){
      assert.equal(scheduleThreatTelemetry(req('https://'+host+'/.env'),
        env,{waitUntil(){throw Error('unexpected forward')}},'bad'),false,host);
    }
  }finally{globalThis.fetch=original}
});
