import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { runInNewContext } from 'node:vm';
import { handleDomainDeviceFederation } from './domain-device-federation.js';

const host = 'vynlink.xyz';
const path = '/__vynalth/device/link';
const uri = 'https://' + host + path;
const env = {
  DEVICE_FEDERATION_ENABLED:'true',
  EDGE_DEVICE_ID_ENABLED:'true',
  EDGE_DEVICE_ALLOW_DERIVED_KEY:'true',
  VISITOR_IP_SIGNING_SECRET:'test-only-shared-secret-longer-than-32-bytes',
};

async function inlineAutoScript() {
  const response=await handleDomainDeviceFederation(new Request(uri),env,new URL(uri));
  assert.equal(response.status,200);
  const html=await response.text();
  const source=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(source,'first-party automatic pairing script is present');
  return {source,headers:response.headers,html};
}

test('automatic pairing remains first-party, no-store and hash-locked by CSP',async()=>{
  const {source,headers,html}=await inlineAutoScript();
  const hash=createHash('sha256').update(source).digest('base64');
  assert.ok(headers.get('content-security-policy')?.includes("'sha256-"+hash+"'"));
  assert.match(headers.get('content-security-policy')||'',/form-action 'self'/);
  assert.match(headers.get('cache-control')||'',/no-store/);
  assert.match(headers.get('set-cookie')||'',/__Host-vyn_edge_device=/);
  assert.doesNotMatch(headers.get('set-cookie')||'',/__Host-vyn_global_device=/);
  assert.ok(html.includes('action="/__vynalth/device/link"'));
  assert.doesNotMatch(html,/http-equiv="refresh"/i);
});

test('valid one-time fragment auto-submits only to same-origin form and clears URL fragment',async()=>{
  const {source}=await inlineAutoScript();
  const code='Z'.repeat(43);
  const location={hash:'#vyn-auto-pair='+code,pathname:path,search:''};
  const input={value:''};
  const calls=[];
  const form={requestSubmit(){calls.push('post');}};
  const context={location,history:{replaceState(_a,_b,clean){
    calls.push(clean);location.hash='';
  }},document:{
    querySelector(s){assert.equal(s,'form[action="/__vynalth/device/link"]');return form;},
    getElementById(id){assert.equal(id,'code');return input;},
  }};
  runInNewContext(source,context,{timeout:200});
  assert.equal(input.value,code);
  assert.equal(location.hash,'');
  assert.deepEqual(calls,[path,'post']);
});

test('missing, malformed and attacker-injected fragments cannot auto-submit',async()=>{
  const {source}=await inlineAutoScript();
  for(const fragment of ['', '#foo=123','#vyn-auto-pair=short',
    '#vyn-auto-pair='+('a'.repeat(43))+'&return=https://evil.example']) {
    let submitted=0,historyEdits=0;
    runInNewContext(source,{
      location:{hash:fragment,pathname:path,search:''},
      history:{replaceState(){historyEdits++;}},
      document:{querySelector(){submitted++;return null;},getElementById(){return null;}},
    },{timeout:200});
    assert.equal(submitted,0,fragment);
    assert.equal(historyEdits,0,fragment);
  }
});
