import test from 'node:test';
import assert from 'node:assert/strict';
import edge from './index.js';
import {
  DEVICE_ROOT_DOMAINS, REDIRECT_ONLY_ROOTS, edgeDeviceScope,
  edgeDeviceAvailable, verifyEdgeDevice, buildEdgeDeviceCookie,
  handleEdgeDeviceEndpoint, addEdgeDeviceToDocumentResponse,
} from './domain-device-id.js';

const secret='test-only-vynalth-signed-visitor-secret-0123456789abcd';
const env = {
  EDGE_DEVICE_ID_ENABLED:'true',
  EDGE_DEVICE_ALLOW_DERIVED_KEY:'true',
  VISITOR_IP_SIGNING_SECRET:secret,
  GPS_GATE_ENABLED:'false',
};
function request(host='vynalthai.si',path='/__vynalth/device',cookie='',headers={}) {
  return new Request('https://'+host+path,{headers:{
    'accept':'text/html,application/xhtml+xml',
    'sec-fetch-dest':'document',
    ...(cookie?{'cookie':cookie}:{}),
    ...headers,
  }});
}
function extract(response){
  return (response.headers.get('Set-Cookie') || '')
    .match(/__Host-vyn_edge_device=([^;]+)/)?.[1] || '';
}

test('exactly 10 fleet roots are configured, three redirects do not issue a second ID',()=>{
  assert.equal(DEVICE_ROOT_DOMAINS.length,10);
  assert.deepEqual([...REDIRECT_ONLY_ROOTS].sort(),
    ['sleepsomno.com','vitamindai.online','vynli.xyz'].sort());
  for(const host of DEVICE_ROOT_DOMAINS){
    const s=edgeDeviceScope(host);
    if (REDIRECT_ONLY_ROOTS.includes(host)||host==='vynalthai.com') assert.equal(s,null,host);
    else assert.equal(s?.root,host);
  }
  assert.equal(edgeDeviceScope('www.vynalthai.com'),null);
  assert.equal(edgeDeviceScope('search.vynalthai.com')?.root,'vynalthai.com');
  assert.equal(edgeDeviceScope('vynalthai.com.attacker.tld'),null);
  assert.equal(edgeDeviceScope('powiismunc.com'),null);
});
test('missing configuration remains passive; no unsigned Device ID',async()=>{
  const req=request();
  assert.equal(edgeDeviceAvailable({EDGE_DEVICE_ID_ENABLED:'true'},'vynalthai.si'),false);
  const r=await handleEdgeDeviceEndpoint(req,{EDGE_DEVICE_ID_ENABLED:'true'},new URL(req.url));
  assert.equal(r?.status,503);
  assert.equal(r?.headers.get('set-cookie'),null);
});
test('new host gets a cryptographic HttpOnly host-only first-party cookie',async()=>{
  const req=request();
  const result=await handleEdgeDeviceEndpoint(req,env,new URL(req.url));
  assert.equal(result?.status,200);
  const body=await result.json();
  assert.equal(body.scope,'host-only');
  assert.equal(body.rootDomain,'vynalthai.si');
  assert.equal(body.accountLinked,false);
  assert.equal(body.signedAndVerified,false);
  assert.match(body.deviceId,/^[0-9a-f-]{36}$/);
  const header=result.headers.get('set-cookie');
  assert.match(header,/__Host-vyn_edge_device=/);
  assert.match(header,/HttpOnly/);
  assert.match(header,/Secure/);
  assert.match(header,/SameSite=Lax/);
  assert.doesNotMatch(header,/;\s*Domain=/i);
  assert.doesNotMatch(JSON.stringify(body),/test-only-vynalth/);
});
test('valid second visit retains the ID and reports verified signature',async()=>{
  const first=await handleEdgeDeviceEndpoint(request(),env,new URL(request().url));
  const token=extract(first);
  const secondReq=request('vynalthai.si','/__vynalth/device','__Host-vyn_edge_device='+token);
  const second=await handleEdgeDeviceEndpoint(secondReq,env,new URL(secondReq.url));
  const a=await first.clone().json(),b=await second.json();
  assert.equal(b.credentialState,'valid');
  assert.equal(b.signedAndVerified,true);
  assert.equal(a.deviceId,b.deviceId);
  assert.equal(second.headers.get('set-cookie'),null);
});
test('copying a cookie to another root or child host cannot authenticate',async()=>{
  const first=await handleEdgeDeviceEndpoint(request(),env,new URL(request().url));
  const firstId=(await first.clone().json()).deviceId, cookie=extract(first);
  for(const host of ['vyncuslim.com','zokivo.xyz','www.vynalthai.si']) {
    const copied=await verifyEdgeDevice(request(host,'/','__Host-vyn_edge_device='+cookie),env);
    assert.equal(copied.state,'issued');
    assert.notEqual(copied.deviceId,firstId);
  }
});
test('tampered signature, expired timestamp and future timestamp are invalid',async()=>{
  const now=Date.UTC(2026,10,10,7);
  const req=request();
  const first=await verifyEdgeDevice(req,env,now);
  assert.equal(first.state,'issued');
  const good=request('vynalthai.si','/','__Host-vyn_edge_device='+first.token);
  assert.equal((await verifyEdgeDevice(good,env,now+1000)).state,'valid');
  assert.equal((await verifyEdgeDevice(good,env,now+91*86400*1000)).state,'issued');
  assert.equal((await verifyEdgeDevice(good,env,now-3600*1000)).state,'issued');
  const raw=first.token;
  const altered=raw.slice(0,-1)+(raw.endsWith('A')?'B':'A');
  assert.equal((await verifyEdgeDevice(request('vynalthai.si','/','__Host-vyn_edge_device='+altered),env,now+1000)).state,'issued');
});
test('HTML GET adds one cookie without overwriting other Set-Cookie headers',async()=>{
  const origin=new Response('<html>OK</html>',{status:200,
    headers:{'content-type':'text/html','Set-Cookie':'original_user_session=abc; Path=/; Secure'}});
  const r=await addEdgeDeviceToDocumentResponse(
    request('vyncuslim.my','/'),origin,env,new URL('https://vyncuslim.my/'));
  const cookies=r.headers.get('set-cookie')||'';
  assert.match(cookies,/original_user_session=/);
  assert.match(cookies,/__Host-vyn_edge_device=/);
  assert.equal(r.status,200);
  assert.equal(await r.text(),'<html>OK</html>');
  assert.match(r.headers.get('cache-control'),/no-store/);
});
test('no cookie on redirects, static assets, non-HTML, bots, POSTs or main origin',async()=>{
  const checks=[
    [request('vynlink.xyz','/'),new Response(null,{status:301,headers:{location:'/home'}})],
    [request('vynlink.xyz','/a.svg','',{'sec-fetch-dest':'image'}),new Response('<html>no</html>',{headers:{'content-type':'text/html'}})],
    [request('vynlink.xyz','/'),new Response('json',{headers:{'content-type':'application/json'}})],
    [request('vynlink.xyz','/','',{'user-agent':'Googlebot'}),new Response('page',{headers:{'content-type':'text/html'}})],
    [request('vynalthai.com','/'),new Response('page',{headers:{'content-type':'text/html'}})],
    [request('vynli.xyz','/'),new Response('page',{headers:{'content-type':'text/html'}})],
  ];
  for(const [req,resp] of checks){
    const result=await addEdgeDeviceToDocumentResponse(req,resp,env,new URL(req.url));
    assert.equal(extract(result),'',req.url);
  }
});
test('endpoint rejects cross-site fetch and non-read mutations',async()=>{
  const cross=request('vynlink.xyz','/__vynalth/device','','' instanceof Object?{}:{'Sec-Fetch-Site':'cross-site'});
  const denial=await handleEdgeDeviceEndpoint(cross,env,new URL(cross.url));
  assert.equal(denial?.status,403);
  const post=new Request('https://vynlink.xyz/__vynalth/device',{method:'POST'});
  const method=await handleEdgeDeviceEndpoint(post,env,new URL(post.url));
  assert.equal(method?.status,405);
});
test('edge integration exposes endpoint and preserves upstream routes',async()=>{
  const old=globalThis.fetch;
  const seen=[];
  globalThis.fetch=async request=>{
    seen.push(new URL(request.url).hostname);
    return new Response('<html>edge</html>',{status:200,headers:{'content-type':'text/html'}});
  };
  try {
    for(const host of ['vynalthai.si','vyncuslim.com','vyncuslim.my','vyncuslim.si','vynlink.xyz','zokivo.xyz']) {
      const status=await edge.fetch(request(host,'/__vynalth/device'),env,{});
      assert.equal(status.status,200,host);
      assert.equal(JSON.parse(await status.text()).rootDomain,host);
      assert.ok(extract(status),host);
      const landing=await edge.fetch(request(host,'/'),env,{});
      assert.equal(landing.status,200);
      assert.ok(extract(landing),host);
      assert.equal(landing.headers.get('x-vynalth-zone'),host);
    }
    assert.equal(seen.length,6); // only the 6 HTML docs hit their original origins
  }finally{globalThis.fetch=old;}
});
