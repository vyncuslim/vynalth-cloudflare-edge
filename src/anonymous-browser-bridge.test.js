import {test} from 'node:test';
import assert from 'node:assert/strict';
import {runInNewContext} from 'node:vm';
import {handleAnonymousBrowserBridge} from './anonymous-browser-bridge.js';
import {handleRootBrowserEndpoint} from './global-browser-id.js';

class MockKV {
  constructor(){this.values=new Map();this.calls=[];}
  async get(key,type){this.calls.push(['get',key]);const value=this.values.get(key);
    return value===undefined?null:type==='json'?JSON.parse(value):value;}
  async put(key,value,opts){this.calls.push(['put',key,opts]);this.values.set(key,value);}
  async delete(key){this.calls.push(['delete',key]);this.values.delete(key);}
}
const baseEnv={
  ROOT_BROWSER_ID_ENABLED:'true',
  ANON_BROWSER_BRIDGE_ENABLED:'true',
  EDGE_DEVICE_ID_ENABLED:'true',
  EDGE_DEVICE_ALLOW_DERIVED_KEY:'true',
  VISITOR_IP_SIGNING_SECRET:'test-shared-material-longer-than-thirty-two-bytes',
};
function mock(){return {...baseEnv,CONSENT_KV:new MockKV()};}
const bridge='/__vynalth/browser/bridge';
function url(host,path=bridge){return 'https://'+host+path;}
function req(host,path=bridge,opts={}){return new Request(url(host,path),opts);}
function cookies(response){
  return response.headers.getSetCookie?.()||
    (response.headers.get('set-cookie')?[response.headers.get('set-cookie')]:[]);
}
function named(response,name){
  const line=cookies(response).find(x=>x.startsWith(name+'='));
  assert.ok(line,'missing '+name);
  return line.split(';')[0];
}
function post(host,path,body,cookie,origin=host,site='same-origin'){
  return req(host,path,{method:'POST',headers:{
    Cookie:cookie,Origin:'https://'+origin,
    'Sec-Fetch-Site':site,'Content-Type':'application/x-www-form-urlencoded',
  },body:new URLSearchParams(body).toString()});
}
async function route(request,env){
  return handleAnonymousBrowserBridge(request,env,new URL(request.url));
}
async function status(host,cookie,env){
  const r=req(host,'/__vynalth/browser',{headers:{Cookie:cookie}});
  const result=await handleRootBrowserEndpoint(r,env,new URL(r.url));
  assert.equal(result.status,200);
  return result.json();
}
async function begin(host,env){
  const target=await route(req(host),env);
  assert.equal(target.status,303);
  const local=named(target,'__Secure-vyn_browser');
  const nonce=named(target,'__Host-vyn_browser_bridge_state');
  const centralUrl=target.headers.get('location');
  assert.ok(centralUrl.startsWith('https://vynalthai.com'+bridge+'?request='));
  return {local,nonce,centralUrl};
}
async function approve(centralUrl,env,priorCentralCookie=''){
  const u=new URL(centralUrl);
  const screen=await route(new Request(u,{headers:{Cookie:priorCentralCookie}}),env);
  assert.equal(screen.status,200);
  const html=await screen.text();
  assert.ok(html.includes('我同意关联这个浏览器'));
  const saved=priorCentralCookie||named(screen,'__Secure-vyn_browser');
  const request=html.match(/name="request" value="([^"]+)"/)?.[1];
  assert.ok(request);
  const grant=await route(post('vynalthai.com',bridge,{request,consent:'yes'},saved),env);
  assert.equal(grant.status,303);
  const target=new URL(grant.headers.get('Location'));
  assert.ok(target.hash.startsWith('#grant='));
  return {centralCookie:saved,grant:target.hash.slice('#grant='.length),
    targetHost:target.hostname,grantUrl:target.toString(),request};
}
async function complete(host,env,local,nonce,grant){
  return route(post(host,bridge+'/complete',{grant},local+'; '+nonce),env);
}

test('anonymous link to vynlink.xyz uses central explicit user consent and own cookies',async()=>{
  const env=mock();
  const start=await begin('vynlink.xyz',env);
  const independent=await status('vynlink.xyz',start.local,env);
  assert.equal(independent.scope,'first-party-root');
  assert.equal(independent.crossRootLinked,false);
  const confirmation=await approve(start.centralUrl,env);
  assert.equal(confirmation.targetHost,'vynlink.xyz');
  const completed=await complete('vynlink.xyz',env,start.local,start.nonce,confirmation.grant);
  assert.equal(completed.status,200);
  assert.ok((await completed.text()).includes('关联'));
  assert.ok(cookies(completed).some(x=>x.startsWith('__Host-vyn_browser_bridge_state=;')));
  const joined=await status('vynlink.xyz',start.local,env);
  const central=await status('vynalthai.com',confirmation.centralCookie,env);
  assert.equal(joined.globalBrowserId,central.globalBrowserId);
  assert.equal(joined.scope,'consented-cross-root');
  assert.equal(joined.crossRootLinked,true);
  assert.equal(joined.siteBrowserId,independent.globalBrowserId);
  assert.equal(joined.securityAuthorization,false);
  assert.equal(joined.hardwareVerified,false);
  assert.equal(joined.crossBrowserLinked,false);
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='put').length,1);
});

test('vynlink.xyz and zokivo.xyz can display same anonymous central ID after separate approvals',async()=>{
  const env=mock();
  const first=await begin('vynlink.xyz',env);
  const firstApproval=await approve(first.centralUrl,env);
  assert.equal((await complete('vynlink.xyz',env,first.local,first.nonce,firstApproval.grant)).status,200);
  const second=await begin('zokivo.xyz',env);
  const independent=await status('zokivo.xyz',second.local,env);
  assert.equal(independent.scope,'first-party-root');
  const secondApproval=await approve(second.centralUrl,env,firstApproval.centralCookie);
  assert.equal((await complete('zokivo.xyz',env,second.local,second.nonce,secondApproval.grant)).status,200);
  const a=await status('vynlink.xyz',first.local,env);
  const b=await status('zokivo.xyz',second.local,env);
  assert.equal(a.globalBrowserId,b.globalBrowserId);
  assert.notEqual(a.siteBrowserId,b.siteBrowserId);
  // A new, unconsented Firefox profile cannot be silently identified as Chrome.
  const other=await status('zokivo.xyz','',env);
  assert.notEqual(other.globalBrowserId,a.globalBrowserId);
});

test('signed grant cannot be redeemed in another browser or on another domain',async()=>{
  const env=mock(),start=await begin('vynlink.xyz',env);
  const grant=(await approve(start.centralUrl,env)).grant;
  const wrongBrowser=await complete('vynlink.xyz',env,
    named(await route(req('zokivo.xyz'),env),'__Secure-vyn_browser'),start.nonce,grant);
  assert.equal(wrongBrowser.status,428);
  const wrongHost=await complete('zokivo.xyz',env,start.local,start.nonce,grant);
  assert.equal(wrongHost.status,403);
  const tampered=grant.slice(0,-1)+(grant.endsWith('a')?'b':'a');
  const forged=await complete('vynlink.xyz',env,start.local,start.nonce,tampered);
  assert.equal(forged.status,403);
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='put').length,0);
});

test('central approval requires explicit opt-in, same-origin and signed request',async()=>{
  const env=mock(),start=await begin('vynlink.xyz',env);
  const central=new URL(start.centralUrl);
  const screen=await route(new Request(central),env);
  const local=named(screen,'__Secure-vyn_browser');
  const token=central.searchParams.get('request');
  const noConsent=await route(post('vynalthai.com',bridge,{request:token,consent:'no'},local),env);
  assert.equal(noConsent.status,403);
  const attack=await route(post('vynalthai.com',bridge,{request:token,consent:'yes'},local,'evil.example','cross-site'),env);
  assert.equal(attack.status,403);
  const forged=await route(new Request(url('vynalthai.com',bridge+'?request=abc')),env);
  assert.equal(forged.status,403);
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='put').length,0);
});

test('first-party callback script removes fragment before same-origin POST',async()=>{
  const env=mock(),start=await begin('vynlink.xyz',env);
  const grant=(await approve(start.centralUrl,env)).grant;
  const scriptResponse=await route(req('vynlink.xyz',bridge+'/script.js'),env);
  assert.equal(scriptResponse.status,200);
  const script=await scriptResponse.text();
  const calls=[],field={value:''};
  runInNewContext(script,{
    location:{hash:'#grant='+grant,pathname:bridge+'/complete',search:''},
    history:{replaceState(_a,_b,location){calls.push(['history',location]);}},
    document:{getElementById(id){assert.equal(id,'bridge-form');return {
      elements:{namedItem(name){assert.equal(name,'grant');return field;}},
      requestSubmit(){calls.push(['submit']);},
    };}},
  },{timeout:300});
  assert.equal(field.value,grant);
  assert.deepEqual(calls,[['history',bridge+'/complete'],['submit']]);
  assert.equal((await route(req('vynlink.xyz',bridge+'/complete'),env)).headers
    .get('Content-Security-Policy')?.includes("script-src 'self'"),true);
});

test('explicit unlink removes association without altering local browser ID or security cookies',async()=>{
  const env=mock(),start=await begin('vynlink.xyz',env);
  const grant=(await approve(start.centralUrl,env)).grant;
  await complete('vynlink.xyz',env,start.local,start.nonce,grant);
  const before=await status('vynlink.xyz',start.local,env);
  assert.equal(before.crossRootLinked,true);
  const screen=await route(req('vynlink.xyz',bridge+'/unlink'),env);
  assert.equal(screen.status,200);
  assert.ok((await screen.text()).includes('解除关联'));
  const after=await route(post('vynlink.xyz',bridge+'/unlink',{},start.local),env);
  assert.equal(after.status,200);
  const result=await status('vynlink.xyz',start.local,env);
  assert.equal(result.crossRootLinked,false);
  assert.equal(result.globalBrowserId,before.siteBrowserId);
  assert.equal(result.siteBrowserId,before.siteBrowserId);
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='delete').length,1);
});

test('feature flag off, absent KV or unsupported domains fail closed',async()=>{
  const env=mock();
  for(const disabled of [
    {...env,ANON_BROWSER_BRIDGE_ENABLED:'false'},
    {...env,CONSENT_KV:null},
  ]) {
    const reply=await route(req('vynlink.xyz'),disabled);
    assert.equal(reply.status,503);
    assert.equal(reply.headers.get('set-cookie'),null);
  }
  const out=await route(req('powiismunc.com'),env);
  assert.equal(out,null);
  const unrelated=await route(req('vynlink.xyz','/api/health'),env);
  assert.equal(unrelated,null);
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='put').length,0);
});

test('anonymous ordinary page identity never silently writes cross-root links',async()=>{
  const env=mock();
  const a=await status('vynlink.xyz','',env);
  const b=await status('zokivo.xyz','',env);
  assert.notEqual(a.globalBrowserId,b.globalBrowserId);
  assert.equal(a.scope,'first-party-root');
  assert.equal(b.scope,'first-party-root');
  assert.equal(env.CONSENT_KV.calls.filter(x=>x[0]==='put').length,0);
});
