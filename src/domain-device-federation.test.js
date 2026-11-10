import test from 'node:test';
import assert from 'node:assert/strict';
import { handleDomainDeviceFederation, signedFederationAssertion, verifyFederationServiceRelay } from './domain-device-federation.js';
import { handleEdgeDeviceEndpoint } from './domain-device-id.js';

const host='vyncuslim.si';
const globalDeviceId='90253425-a951-4cb7-af0d-379ac8c92f0b';
const shared='test-federation-shared-secret-longer-than-32-characters-value';
const env={
  EDGE_DEVICE_ID_ENABLED:'true',
  EDGE_DEVICE_ALLOW_DERIVED_KEY:'true',
  VISITOR_IP_SIGNING_SECRET:shared,
  DEVICE_FEDERATION_ENABLED:'true',
};
const code='F'.repeat(43);
const uri='https://'+host+'/__vynalth/device/link';

function cookieValue(setCookie,name) {
  return (String(setCookie||'').match(new RegExp(name+'=([^;]+)'))||[])[1]||'';
}
test('explicit consent page is gated and issues only the host-local device cookie',async()=>{
  const req=new Request(uri);
  const disabled=await handleDomainDeviceFederation(req,{},new URL(uri));
  assert.equal(disabled.status,503);
  assert.equal(disabled.headers.get('set-cookie'),null);
  const page=await handleDomainDeviceFederation(req,env,new URL(uri));
  assert.equal(page.status,200);
  assert.match(await page.text(),/统一|Unified Device ID/);
  assert.match(page.headers.get('set-cookie')||'',/__Host-vyn_edge_device=/);
  assert.doesNotMatch(page.headers.get('set-cookie')||'',/__Host-vyn_global_device=/);
});
test('unknown host, missing origin, cross-site request and forged code are rejected',async()=>{
  const external=new Request('https://example.com/__vynalth/device/link');
  assert.equal(await handleDomainDeviceFederation(external,env,new URL(external.url)),null);
  const first=await handleDomainDeviceFederation(new Request(uri),env,new URL(uri));
  const local=cookieValue(first.headers.get('set-cookie'),'__Host-vyn_edge_device');
  const invalid=new Request(uri,{method:'POST',
    headers:{cookie:'__Host-vyn_edge_device='+local,
      'content-type':'application/x-www-form-urlencoded','sec-fetch-site':'cross-site',
      origin:'https://evil.example'},
    body:'code='+code,
  });
  const rejected=await handleDomainDeviceFederation(invalid,env,new URL(uri));
  assert.equal(rejected.status,403);
  const wrong=new Request(uri,{method:'POST',
    headers:{cookie:'__Host-vyn_edge_device='+local,
      'content-type':'application/x-www-form-urlencoded','sec-fetch-site':'same-origin',
      origin:'https://'+host},
    body:'code=1234',
  });
  const bad=await handleDomainDeviceFederation(wrong,env,new URL(uri));
  assert.equal(bad.status,400);
});
test('a valid site-signed browser can claim a one-time consent code and retain a host-only global cookie',async()=>{
  const initial=await handleDomainDeviceFederation(new Request(uri),env,new URL(uri));
  const local=cookieValue(initial.headers.get('set-cookie'),'__Host-vyn_edge_device');
  const original=globalThis.fetch;
  const calls=[];
  globalThis.fetch=async (url,params)=>{
    calls.push({url,params});
    if(String(url).endsWith('/claim'))return Response.json({success:true,globalDeviceId});
    if(String(url).endsWith('/status'))return Response.json({success:true,active:true});
    throw Error('Unexpected central route');
  };
  try{
    const post=new Request(uri,{method:'POST',
      headers:{
        cookie:'__Host-vyn_edge_device='+local,
        'content-type':'application/x-www-form-urlencoded',
        'origin':'https://'+host,
        'sec-fetch-site':'same-origin',
      },body:'code='+code});
    const link=await handleDomainDeviceFederation(post,env,new URL(uri));
    assert.equal(link.status,200);
    const cookies=link.headers.get('set-cookie')||'';
    const globalCookie=cookieValue(cookies,'__Host-vyn_global_device');
    assert.ok(globalCookie);
    assert.match(cookies,/HttpOnly/);
    assert.doesNotMatch(cookies,/;\s*Domain=/i);
    assert.equal(calls.length,1);
    assert.equal(calls[0].params.redirect,'error');
    const body=JSON.parse(calls[0].params.body);
    assert.equal(body.host,host);
    assert.equal(body.code,code);
    assert.match(body.proof,/^[A-Za-z0-9_-]{43}$/);
    assert.equal(calls[0].url,'https://vynalthai.com/api/security/device/federation/claim');

    const statusReq=new Request('https://'+host+'/__vynalth/device',{
      headers:{cookie:'__Host-vyn_edge_device='+local+'; __Host-vyn_global_device='+globalCookie}});
    const status=await handleEdgeDeviceEndpoint(statusReq,env,new URL(statusReq.url));
    const json=await status.json();
    assert.equal(json.accountLinked,true);
    assert.equal(json.deviceId,globalDeviceId);
    assert.equal(json.globalDeviceId,globalDeviceId);
    assert.notEqual(json.siteDeviceId,globalDeviceId);
    assert.equal(calls.length,2);
    globalThis.fetch=async()=>Response.json({success:true,active:false});
    const revoked=await handleEdgeDeviceEndpoint(statusReq,env,new URL(statusReq.url));
    const reset=await revoked.json();
    assert.equal(reset.accountLinked,false);
    assert.equal(reset.globalDeviceId,null);
    assert.equal(reset.deviceId,reset.siteDeviceId);
  } finally{globalThis.fetch=original;}
});
test('signed proof is bound to action, host, local browser ID and consent code',async()=>{
  const localId='e6245f16-a262-45e0-9477-af1459f651ce';
  const a=await signedFederationAssertion(env,host,localId,code);
  const b=await signedFederationAssertion(env,host,localId,globalDeviceId,'status');
  assert.match(a.proof,/^[A-Za-z0-9_-]{43}$/);
  assert.match(b.proof,/^[A-Za-z0-9_-]{43}$/);
  assert.notEqual(a.proof,b.proof);
  assert.equal(await signedFederationAssertion({},host,localId,code),null);
});


test('only fresh signed canonical Worker service traffic can bypass GPS browser preflight',async()=>{
  const id='e6245f16-a262-45e0-9477-af1459f651ce';
  const a=await signedFederationAssertion(env,host,id,globalDeviceId,'status');
  const target='https://vynalthai.com/api/security/device/federation/status';
  const body={host,localDeviceId:id,globalDeviceId,...a};
  const valid=new Request(target,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify(body)});
  assert.equal(await verifyFederationServiceRelay(valid,env,new URL(target)),true);
  const forged=new Request(target,{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({...body,host:'zokivo.xyz'})});
  assert.equal(await verifyFederationServiceRelay(forged,env,new URL(target)),false);
  assert.equal(await verifyFederationServiceRelay(valid,{},new URL(target)),false);
  assert.equal(await verifyFederationServiceRelay(valid,env,new URL('https://vyncuslim.si/api/security/device/federation/status')),false);
});


test('federation auto-activates with a signed device and a valid trust root, with emergency-off override',async()=>{
  const activeEnv={...env};
  delete activeEnv.DEVICE_FEDERATION_ENABLED;
  const ready=await handleDomainDeviceFederation(new Request(uri),activeEnv,new URL(uri));
  assert.equal(ready.status,200);
  assert.match(await ready.text(),/Unified Device ID/);
  const stopped=await handleDomainDeviceFederation(
    new Request(uri),{...activeEnv,DEVICE_FEDERATION_ENABLED:'false'},new URL(uri));
  assert.equal(stopped.status,503);
  const missingKey=await handleDomainDeviceFederation(new Request(uri),{
    ...activeEnv,VISITOR_IP_SIGNING_SECRET:'',
  },new URL(uri));
  assert.equal(missingKey.status,503);
});
