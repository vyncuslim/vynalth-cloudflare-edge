import test from 'node:test';
import assert from 'node:assert/strict';
import { signedVisitorOriginRequest } from './signed-visitor-ip.js';

const now = Date.parse('2026-10-22T06:00:00Z');
const secret = 'unit_test_shared_secret_00000000000000000000000';

test('Cloudflare signs actual edge visitor and never preserves spoofed browser attestation', async () => {
  const req=new Request('https://vynalthai.com/api/ingest/telemetry',{
    headers:{
      'CF-Connecting-IP':'203.0.113.9',
      'x-vynalth-client-ip':'198.51.100.44',
      'x-vynalth-client-signature':'0000',
      'x-vynalth-client-ts':'11111',
      'x-vynalth-client-host':'attacker.example',
    },
  });
  const signed=await signedVisitorOriginRequest(req,{VISITOR_IP_SIGNING_SECRET:secret},now);
  assert.equal(signed.headers.get('x-vynalth-client-ip'),'203.0.113.9');
  assert.equal(signed.headers.get('x-vynalth-client-host'),'vynalthai.com');
  assert.equal(signed.headers.get('x-vynalth-client-ts'),String(now/1000));
  assert.match(signed.headers.get('x-vynalth-client-signature'),/^[0-9a-f]{64}$/);
  const unconfigured=await signedVisitorOriginRequest(req,{},now);
  assert.equal(unconfigured.headers.get('x-vynalth-client-ip'),null);
  assert.equal(unconfigured.headers.get('x-vynalth-client-ts'),null);
  assert.equal(unconfigured.headers.get('x-vynalth-client-signature'),null);
  assert.equal(unconfigured.headers.get('x-vynalth-client-host'),null);
});

test('No visitor IP yields no attacker-controlled signed claim',async()=>{
  const req=new Request('https://vynalthai.com/',{
    headers:{'x-vynalth-client-ip':'203.0.113.10'},
  });
  const result=await signedVisitorOriginRequest(req,{VISITOR_IP_SIGNING_SECRET:secret},now);
  assert.equal(result.headers.get('x-vynalth-client-ip'),null);
});


test('Signed Cloudflare country MY and state 07 are bound to the exact visitor IP',async()=>{
  const req=new Request('https://vynalthai.com/api/visitor-info',{headers:{
    'cf-connecting-ip':'203.0.113.9','x-vynalth-client-country':'US',
    'x-vynalth-client-region':'IL','x-vynalth-client-geo-signature':'f'.repeat(64),
  }});
  Object.defineProperty(req,'cf',{value:{country:'MY',regionCode:'07'}});
  const signed=await signedVisitorOriginRequest(req,{VISITOR_IP_SIGNING_SECRET:secret},now);
  assert.equal(signed.headers.get('x-vynalth-client-country'),'MY');
  assert.equal(signed.headers.get('x-vynalth-client-region'),'07');
  const {createHmac}=await import('node:crypto');
  const expected=createHmac('sha256',secret)
    .update(['geo-v1','203.0.113.9',String(now/1000),'vynalthai.com','MY','07'].join('|'))
    .digest('hex');
  assert.equal(signed.headers.get('x-vynalth-client-geo-signature'),expected);
});
test('No Cloudflare geolocation or signing secret never forwards an unsigned country',async()=>{
  const req=new Request('https://vynalthai.com/',{headers:{
    'cf-connecting-ip':'203.0.113.9','cf-ipcountry':'MY',
    'x-vynalth-client-country':'US',
    'x-vynalth-client-region':'CA',
    'x-vynalth-client-geo-signature':'f'.repeat(64),
  }});
  const unknownGeo=await signedVisitorOriginRequest(req,{VISITOR_IP_SIGNING_SECRET:secret},now);
  for(const h of ['country','region','geo-signature'])assert.equal(unknownGeo.headers.get('x-vynalth-client-'+h),null);
  Object.defineProperty(req,'cf',{value:{country:'MY',regionCode:'07'}});
  const noSecret=await signedVisitorOriginRequest(req,{},now);
  for(const h of ['country','region','geo-signature'])assert.equal(noSecret.headers.get('x-vynalth-client-'+h),null);
});
