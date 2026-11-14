import assert from 'node:assert/strict';
import { test } from 'node:test';
import { HOSTS, classifyResponse, probeHost } from './check-device-federation.mjs';

const host='vyncuslim.si';
const edgeHeaders={
  'x-vynalth-edge':'cloudflare-worker',
  'x-vynalth-edge-host':host,
};
const goodDevice={enabled:true,host,globalControlEnforcementActive:true};
const goodPage='<title>Unified Device ID</title><form action="/__vynalth/device/link">';

test('403/404 signal separate WAF and routing failures, not success',()=>{
  assert.equal(classifyResponse(new Response('',{status:403}),'device',host,{}).reason,'DENIED_BEFORE_OR_IN_WORKER');
  assert.equal(classifyResponse(new Response('',{status:404}),'device',host,{}).reason,'NO_DEVICE_ROUTE');
  assert.equal(classifyResponse(new Response('',{status:302}),'device',host,{}).reason,'REDIRECT_BEFORE_DEVICE_HANDLER');
});
test('200 alone is not a verified pairing route',()=>{
  const html=new Response('<!doctype html>',{status:200,headers:edgeHeaders});
  assert.equal(classifyResponse(html,'link',host,'<html>app shell</html>').reason,'NOT_A_PAIRING_PAGE');
  assert.equal(classifyResponse(new Response('',{status:200}),'device',host,goodDevice).reason,'NOT_PROVEN_EDGE_RESPONSE');
  assert.equal(classifyResponse(new Response('',{status:200,headers:edgeHeaders}),'device',host,{...goodDevice,globalControlEnforcementActive:false}).reason,'DEVICE_STATUS_INCOMPLETE');
});
test('one host requires verified status AND site-specific consent page',async()=>{
  const seen=[];
  const fetcher=async (url,options)=>{
    seen.push([url,options.method,options.redirect]);
    return url.endsWith('/link')
      ? new Response(goodPage,{status:200,headers:edgeHeaders})
      : Response.json(goodDevice,{headers:edgeHeaders});
  };
  const result=await probeHost(host,fetcher);
  assert.equal(result.ok,true);
  assert.equal(seen.length,2);
  assert.deepEqual(seen.map(x=>x[1]),['GET','GET']);
  assert.ok(seen.every(x=>x[2]==='manual'));
});
test('no arbitrary third-party host can be probed',async()=>{
  await assert.rejects(probeHost('evil.example',()=>{}),/HOST_NOT_ALLOWLISTED/);
  assert.ok(HOSTS.includes('vyncuslim.com')&&HOSTS.includes('vyncuslim.my'));
});
