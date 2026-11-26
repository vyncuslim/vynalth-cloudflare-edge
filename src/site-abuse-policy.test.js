import test from 'node:test';
import assert from 'node:assert/strict';
import { classifySiteRequest, classifyPrivateDecoy, advanceDeviceRisk, enforceSiteAbuse } from './site-abuse-policy.js';
const request=(host,path,method='GET',headers={})=>new Request('https://'+host+path,{method,headers});
test('actual Search paths, origin AI paths and method scope',()=>{
  assert.equal(classifySiteRequest(request('search.vynalthai.com','/api/search?q=x')),'SEARCH');
  assert.equal(classifySiteRequest(request('search.vynalthai.com','/api/images?q=x')),'IMAGE');
  assert.equal(classifySiteRequest(request('search.vynalthai.com','/api/images','POST')),null);
  assert.equal(classifySiteRequest(request('vynalthai.com','/api/ai/image','POST')),'IMAGE');
  assert.equal(classifySiteRequest(request('vynalthai.com','/api/auth/signup','POST')),'SIGNUP');
  assert.equal(classifySiteRequest(request('other.vynalthai.com','/api/search')),null);
});
test('ordinary document only, not assets, preflight or recovery',()=>{
  const headers={accept:'text/html'};
  assert.equal(classifySiteRequest(request('search.vynalthai.com','/','GET',headers)),'DOC');
  for (const path of ['/assets/app.js','/status','/recover','/.well-known/acme-challenge/a','/api/status','/auth/callback'])
    assert.equal(classifySiteRequest(request('search.vynalthai.com',path,'GET',headers)),null,path);
  assert.equal(classifySiteRequest(request('search.vynalthai.com','/','OPTIONS',headers)),null);
});
test('device restriction requires 5 distinct observations and 3 categories, expires without extension',()=>{
  const now=1_790_000_000_000;
  let s={};
  for(let i=0;i<4;i++) s=advanceDeviceRisk(s,{id:'ray-'+i,category:['/a','/b','/c'][i%3]},now+i);
  assert.equal(s.blockUntil,0);
  s=advanceDeviceRisk(s,{id:'ray-3',category:'/c'},now+4);
  assert.equal(s.blockUntil,0);
  s=advanceDeviceRisk(s,{id:'ray-4',category:'/a'},now+5);
  assert.equal(s.blockUntil,now+5+72*3600000);
  assert.equal(advanceDeviceRisk(s,{id:'ray-5',category:'/b'},now+100).blockUntil,s.blockUntil);
  assert.equal(advanceDeviceRisk(s,null,s.blockUntil).blockUntil,0);
});
test('single category or stale observations never impose device restriction',()=>{
  const now=1_790_000_000_000;
  let s={};
  for(let i=0;i<8;i++) s=advanceDeviceRisk(s,{id:'r'+i,category:'/a'},now+i);
  assert.equal(s.blockUntil,0);
  s=advanceDeviceRisk(s,{id:'r9',category:'/b'},now+11*60000);
  assert.equal(s.probes.length,1);
  assert.equal(classifyPrivateDecoy(request('search.vynalthai.com','/wp-admin/install.php')),'/wp-admin/install.php');
  assert.equal(classifyPrivateDecoy(request('search.vynalthai.com','/api/search')),null);
});
test('unknown or disabled host leaves existing behavior untouched',async()=>{
  assert.equal(await enforceSiteAbuse(request('search.vynalthai.com','/api/search'),{},'fake'),null);
  assert.equal(await enforceSiteAbuse(request('unlisted.vynalthai.com','/api/search'),{SECURITY_SITE_ABUSE_MODE:'enforce',SECURITY_SITE_ABUSE_HOSTS:'search.vynalthai.com'},'fake'),null);
});
test('independent host counters, no forwarding-header identity, observe versus enforce',async()=>{
  const calls=[];
  const env={SECURITY_SITE_ABUSE_MODE:'enforce',SECURITY_SITE_ABUSE_HOSTS:'search.vynalthai.com,vynalthai.com',
    EDGE_DEVICE_ID_SIGNING_SECRET:'synthetic-unit-test-secret-0123456789',
    SECURITY_DOC_RATE:{limit:async({key})=>{calls.push(key);return {success:false}}}};
  function doc(host,ip){const q=request(host,'/','GET',{accept:'text/html','CF-Connecting-IP':ip,'X-Forwarded-For':'203.0.113.10'});Object.defineProperty(q,'cf',{value:{}});return q;}
  const a=await enforceSiteAbuse(doc('search.vynalthai.com','198.51.100.1'),env,'test');
  const b=await enforceSiteAbuse(doc('vynalthai.com','198.51.100.1'),env,'test');
  assert.equal(a.status,429);assert.equal(b.status,429);assert.notEqual(calls[0],calls[1]);
  assert.ok(calls.every(x=>/^[0-9a-f]{64}$/.test(x)));
  env.SECURITY_SITE_ABUSE_MODE='observe';
  assert.equal(await enforceSiteAbuse(doc('search.vynalthai.com','198.51.100.1'),env,'test'),null);
  const before=calls.length;
  assert.equal(await enforceSiteAbuse(request('search.vynalthai.com','/','GET',{accept:'text/html','X-Forwarded-For':'203.0.113.10'}),env,'test'),null);
  assert.equal(calls.length,before);
});
