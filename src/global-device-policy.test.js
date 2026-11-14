import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateGlobalDevicePolicy, checkFederatedDeviceAccess } from './global-device-policy.js';
import { verifyEdgeDevice, buildEdgeDeviceCookie, createGlobalDeviceCookie } from './domain-device-id.js';

const host = 'zokivo.xyz';
const secret = 'test-global-policy-shared-secret-longer-than-32-bytes';
const env = { EDGE_DEVICE_ID_ENABLED: 'true', EDGE_DEVICE_ALLOW_DERIVED_KEY: 'true',
  DEVICE_FEDERATION_ENABLED: 'true', GLOBAL_DEVICE_CONTROL_ENABLED: 'true',
  VISITOR_IP_SIGNING_SECRET: secret };
const globalId = '90253425-a951-4cb7-af0d-379ac8c92f0b';
const url = 'https://' + host + '/private';

test('pure policy handles permanent, expiring, and route-specific restrictions', async () => {
  assert.equal(evaluateGlobalDevicePolicy({mode:'block'},'/').status,403);
  assert.equal(evaluateGlobalDevicePolicy({mode:'revoke'},'/').status,403);
  assert.equal(evaluateGlobalDevicePolicy({mode:'temporary_block',blocked_until:new Date(Date.now()+60000).toISOString()},'/').status,403);
  assert.equal(evaluateGlobalDevicePolicy({mode:'temporary_block',blocked_until:new Date(Date.now()-60000).toISOString()},'/'),null);
  assert.equal(evaluateGlobalDevicePolicy({mode:'restricted'},'/api/admin/').status,403);
  assert.equal(evaluateGlobalDevicePolicy({mode:'restricted'},'/'),null);
  assert.equal(evaluateGlobalDevicePolicy({mode:'allow',ai_tools_allowed:false},'/api/ai/chat').status,403);
  assert.equal(evaluateGlobalDevicePolicy({mode:'allow',exports_allowed:false},'/api/data/export').status,403);
});

test('unsigned or locally scoped credentials never claim a global device', async () => {
  assert.equal(await checkFederatedDeviceAccess(new Request(url),env,new URL(url)),null);
  assert.equal(await checkFederatedDeviceAccess(new Request(url),{},new URL(url)),null);
  const device=await verifyEdgeDevice(new Request(url),env);
  const local=buildEdgeDeviceCookie(device.token).split(';')[0];
  assert.equal(await checkFederatedDeviceAccess(new Request(url,{headers:{cookie:local}}),env,new URL(url)),null);
});

test('signed linked device observes central block and fails closed only for linked credentials', async () => {
  const first=await verifyEdgeDevice(new Request(url),env);
  const local=buildEdgeDeviceCookie(first.token).split(';')[0];
  const global=await createGlobalDeviceCookie(host,first.deviceId,globalId,env);
  const cookie=local+'; '+global.split(';')[0];
  const request=new Request(url,{headers:{cookie}});
  const original=globalThis.fetch;
  let calls=0;
  globalThis.fetch=async(_url,init)=>{
    calls++;
    const payload=JSON.parse(init.body);
    assert.equal(payload.globalDeviceId,globalId);
    assert.equal(payload.localDeviceId,first.deviceId);
    return Response.json({success:true,active:true,policy:{mode:'block'}});
  };
  try {
    const blocked=await checkFederatedDeviceAccess(request,env,new URL(url));
    assert.equal(blocked.status,403);
    assert.equal(JSON.parse(await blocked.text()).error,'GLOBAL_DEVICE_BLOCKED');
    assert.equal(calls,1);
    const privateAsset=new Request('https://'+host+'/private/report.pdf',{headers:{cookie}});
    assert.equal((await checkFederatedDeviceAccess(privateAsset,env,new URL(privateAsset.url))).status,403);
    const secretPhoto=new Request('https://'+host+'/media/private-photo.webp',{headers:{cookie}});
    assert.equal((await checkFederatedDeviceAccess(secretPhoto,env,new URL(secretPhoto.url))).status,403);
    const publicBuild=new Request('https://'+host+'/assets/app.js',{headers:{cookie}});
    assert.equal(await checkFederatedDeviceAccess(publicBuild,env,new URL(publicBuild.url)),null);
    globalThis.fetch=async()=>Response.json({success:true,active:false,policy:null});
    assert.equal(await checkFederatedDeviceAccess(request,env,new URL(url)),null);
    globalThis.fetch=async()=>new Response(null,{status:503});
    assert.equal((await checkFederatedDeviceAccess(request,env,new URL(url))).status,503);
  } finally { globalThis.fetch=original; }
});


test('shared campus NAT does not merge devices or spread a linked-device block', async () => {
  // TEST-NET address: do not check in an actual student's or campus's IP.
  const sharedNetwork = {
    'cf-connecting-ip': '192.0.2.82',
    'x-ipinfo-residential-proxy': 'true',
    'user-agent': 'CampusBrowser/1.0',
  };
  const a = await verifyEdgeDevice(new Request(url, { headers: sharedNetwork }), env);
  const b = await verifyEdgeDevice(new Request(url, { headers: sharedNetwork }), env);
  assert.notEqual(a.deviceId, b.deviceId, 'one public IP must not identify a browser');
  const aCookie = buildEdgeDeviceCookie(a.token).split(';')[0];
  const bCookie = buildEdgeDeviceCookie(b.token).split(';')[0];
  const linkedCookie = await createGlobalDeviceCookie(host, a.deviceId, globalId, env);
  const globalProof = linkedCookie.split(';')[0];
  const requestA = new Request(url, { headers: {
    ...sharedNetwork, cookie: aCookie + '; ' + globalProof,
  } });
  const requestB = new Request(url, { headers: {
    ...sharedNetwork, cookie: bCookie,
  } });
  const mismatchedProof = new Request(url, { headers: {
    ...sharedNetwork, cookie: bCookie + '; ' + globalProof,
  } });
  const original = globalThis.fetch;
  let lookups = 0;
  globalThis.fetch = async (_url, init) => {
    lookups++;
    const claim = JSON.parse(init.body);
    assert.equal(claim.localDeviceId, a.deviceId);
    assert.equal(claim.globalDeviceId, globalId);
    return Response.json({ success: true, active: true, policy: { mode: 'block' } });
  };
  try {
    const denied = await checkFederatedDeviceAccess(requestA, env, new URL(url));
    assert.equal(denied?.status, 403);
    assert.equal(await checkFederatedDeviceAccess(requestB, env, new URL(url)), null,
      'unrelated campus browsers must not inherit a global block');
    assert.equal(await checkFederatedDeviceAccess(mismatchedProof, env, new URL(url)), null,
      'a global association cookie is bound to its own host-local device');
    assert.equal(lookups, 1, 'do not query the blocked global ID for other browsers');
  } finally {
    globalThis.fetch = original;
  }
});

test('same host-signed browser survives Wi-Fi to mobile-network rotation', async () => {
  const issued = await verifyEdgeDevice(new Request(url, {
    headers: { 'cf-connecting-ip': '192.0.2.82' },
  }), env);
  const later = await verifyEdgeDevice(new Request(url, { headers: {
    'cf-connecting-ip': '198.51.100.19',
    'x-ipinfo-residential-proxy': 'false',
    cookie: buildEdgeDeviceCookie(issued.token).split(';')[0],
  } }), env);
  assert.equal(later.state, 'valid');
  assert.equal(later.deviceId, issued.deviceId,
    'an IP change cannot silently reset a valid local browser identity');
});
