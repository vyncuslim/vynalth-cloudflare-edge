import {test} from 'node:test';
import assert from 'node:assert/strict';
import {
  getRootBrowserIdentity, handleRootBrowserEndpoint,
  addRootBrowserToDocumentResponse,
} from './global-browser-id.js';

const env={
  ROOT_BROWSER_ID_ENABLED:'true',
  EDGE_DEVICE_ID_ENABLED:'true',
  EDGE_DEVICE_ALLOW_DERIVED_KEY:'true',
  VISITOR_IP_SIGNING_SECRET:'test-only-value-32-characters-or-longer',
};
const htmlHeaders={
  Accept:'text/html,application/xhtml+xml',
  'Sec-Fetch-Dest':'document',
  'User-Agent':'Mozilla/5.0 Chrome',
};
const url=(host,path='/')=>'https://'+host+path;
const make=(host,headers={},path='/')=>new Request(url(host,path),{headers});
const getCookie=(response)=>{
  const matches=response.headers.getSetCookie?.()||
    (response.headers.get('Set-Cookie')?[response.headers.get('Set-Cookie')]:[]);
  const line=matches.find(x=>x.startsWith('__Secure-vyn_browser='));
  assert.ok(line,'root-scoped signed browser cookie is present');
  return line.split(';')[0];
};

test('anon GET automatically issues a signed first-party cookie without login',async()=>{
  const endpoint=make('vynalthai.com',{},'/__vynalth/browser');
  const response=await handleRootBrowserEndpoint(endpoint,env,new URL(endpoint.url));
  assert.equal(response.status,200);
  const body=await response.json();
  assert.equal(body.enabled,true);
  assert.equal(body.scope,'first-party-root');
  assert.equal(body.rootDomain,'vynalthai.com');
  assert.equal(body.crossBrowserLinked,false);
  assert.equal(body.accountLinked,false);
  assert.equal(body.hardwareVerified,false);
  assert.equal(body.securityAuthorization,false);
  assert.match(body.globalBrowserId,/^[0-9a-f-]{36}$/);
  const cookies=response.headers.getSetCookie?.()||[response.headers.get('set-cookie')];
  assert.ok(cookies.some(c=>/Domain=vynalthai\.com;/.test(c)));
  assert.ok(cookies.some(c=>/HttpOnly; SameSite=Lax/.test(c)));
  assert.ok(cookies.some(c=>/Secure; HttpOnly/.test(c)));
  assert.equal(response.headers.get('Access-Control-Allow-Origin'),null);
  assert.match(response.headers.get('Cache-Control')||'',/no-store/);
});

test('same signed ID is reused by root and subdomains in one browser',async()=>{
  const first=make('vynalthai.com',{},'/__vynalth/browser');
  const original=await handleRootBrowserEndpoint(first,env,new URL(first.url));
  const cookie=getCookie(original);
  const id=(await original.json()).globalBrowserId;
  for(const host of ['search.vynalthai.com','vynova.vynalthai.com','utility.vynalthai.com']){
    const req=make(host,{Cookie:cookie},'/__vynalth/browser');
    const response=await handleRootBrowserEndpoint(req,env,new URL(req.url));
    assert.equal((await response.json()).globalBrowserId,id);
    assert.equal(response.headers.get('set-cookie'),null);
  }
});

test('two anonymous browsers sharing same school IP and user agent remain distinct',async()=>{
  const first=make('search.vynalthai.com',{
    'CF-Connecting-IP':'192.0.2.19','User-Agent':'identical',
  },'/__vynalth/browser');
  const second=make('search.vynalthai.com',{
    'CF-Connecting-IP':'192.0.2.19','User-Agent':'identical',
  },'/__vynalth/browser');
  const a=await handleRootBrowserEndpoint(first,env,new URL(first.url));
  const b=await handleRootBrowserEndpoint(second,env,new URL(second.url));
  assert.notEqual((await a.json()).globalBrowserId,(await b.json()).globalBrowserId);
});

test('same cookie does not transfer ID across unrelated top-level root domains',async()=>{
  const req=make('vynlink.xyz',{},'/__vynalth/browser');
  const first=await handleRootBrowserEndpoint(req,env,new URL(req.url));
  const cookie=getCookie(first),id=(await first.json()).globalBrowserId;
  const other=make('zokivo.xyz',{Cookie:cookie},'/__vynalth/browser');
  const second=await handleRootBrowserEndpoint(other,env,new URL(other.url));
  assert.notEqual((await second.json()).globalBrowserId,id);
  assert.match(second.headers.get('set-cookie')||'',/Domain=zokivo\.xyz/);
});

test('tampering with the signed cookie cannot assume victim browser identity',async()=>{
  const req=make('vynalthai.com',{},'/__vynalth/browser');
  const first=await handleRootBrowserEndpoint(req,env,new URL(req.url));
  const cookie=getCookie(first),id=(await first.json()).globalBrowserId;
  const spoofed=cookie.replace(/b1\.[^.]+/, 'b1.11111111-1111-4111-8111-111111111111');
  const bad=make('vynalthai.com',{Cookie:spoofed},'/__vynalth/browser');
  const second=await handleRootBrowserEndpoint(bad,env,new URL(bad.url));
  assert.notEqual((await second.json()).globalBrowserId,id);
  assert.notEqual((await getRootBrowserIdentity(bad,env)).state,'valid');
});

test('duplicated name is treated as ambiguous and reissued, never trusted',async()=>{
  const req=make('vynalthai.com',{},'/__vynalth/browser');
  const first=await handleRootBrowserEndpoint(req,env,new URL(req.url));
  const cookie=getCookie(first),id=(await first.json()).globalBrowserId;
  const duplicate=make('vynalthai.com',{Cookie:cookie+'; '+cookie},'/__vynalth/browser');
  const response=await handleRootBrowserEndpoint(duplicate,env,new URL(duplicate.url));
  assert.notEqual((await response.json()).globalBrowserId,id);
});

test('HTML gets root cookie while public assets and APIs stay unchanged',async()=>{
  const html=make('vynalthai.com',htmlHeaders);
  const response=await addRootBrowserToDocumentResponse(html,
    new Response('<html></html>',{status:200,headers:{'Content-Type':'text/html; charset=utf-8',
      'Set-Cookie':'__Host-app_session=abc; Path=/; Secure; HttpOnly'}}),
    env,new URL(html.url));
  const all=response.headers.getSetCookie?.()||[];
  assert.ok(all.some(c=>c.startsWith('__Secure-vyn_browser=')));
  assert.ok(all.some(c=>c.startsWith('__Host-app_session=')));
  for(const [path,headers,type] of [
    ['/api/health',{},'application/json'],
    ['/assets/main.js',{},'text/javascript'],
    ['/',{...htmlHeaders,'User-Agent':'Googlebot'},'text/html'],
  ]){
    const req=make('vynalthai.com',headers,path);
    const out=await addRootBrowserToDocumentResponse(req,
      new Response('ok',{status:200,headers:{'Content-Type':type}}),env,new URL(req.url));
    assert.equal(out.headers.get('set-cookie'),null,path);
  }
});

test('disabled flag, cross-site requests and unsafe methods cannot issue identity',async()=>{
  const req=make('vynalthai.com',{},'/__vynalth/browser');
  const disabled=await handleRootBrowserEndpoint(req,{...env,ROOT_BROWSER_ID_ENABLED:'false'},new URL(req.url));
  assert.equal(disabled.status,503);
  assert.equal(disabled.headers.get('Set-Cookie'),null);
  const cross=make('vynalthai.com',{'Sec-Fetch-Site':'cross-site'},'/__vynalth/browser');
  const forbidden=await handleRootBrowserEndpoint(cross,env,new URL(cross.url));
  assert.equal(forbidden.status,403);
  assert.equal(forbidden.headers.get('Set-Cookie'),null);
  const post=new Request(url('vynalthai.com','/__vynalth/browser'),{method:'POST'});
  const method=await handleRootBrowserEndpoint(post,env,new URL(post.url));
  assert.equal(method.status,405);
  assert.equal(method.headers.get('Set-Cookie'),null);
});
