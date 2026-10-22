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
