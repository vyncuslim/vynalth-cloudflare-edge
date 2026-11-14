#!/usr/bin/env node
// Read-only Cloudflare production smoke check; no login, no auth, no secrets,
// no stored cookies and no raw ID values written to logs.
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const endpoint='/__vynalth/browser';
export const hosts=Object.freeze([
  {host:'vynalthai.com',root:'vynalthai.com'},
  {host:'search.vynalthai.com',root:'vynalthai.com'},
  {host:'vynlink.xyz',root:'vynlink.xyz'},
  {host:'zokivo.xyz',root:'zokivo.xyz'},
  {host:'vyncuslim.com',root:'vyncuslim.com'},
  {host:'vyncuslim.my',root:'vyncuslim.my'},
]);

export async function checkHost(item,fetchImpl=fetch) {
  const target='https://'+item.host+endpoint;
  let response;
  try {
    response=await fetchImpl(target,{redirect:'manual',headers:{Accept:'application/json'},
      signal:AbortSignal.timeout(10000)});
  }catch(e){return {host:item.host,ok:false,reason:'NETWORK_ERROR',
    detail:String(e?.cause?.code||e?.name||'unknown')};}
  if(response.status!==200) return {host:item.host,ok:false,
    reason:response.status===403?'BLOCKED_BY_WAF_OR_POLICY':response.status===404?
      'ROUTE_OR_HANDLER_NOT_FOUND':response.status===503?'SIGNING_OR_WORKER_UNAVAILABLE':
      response.status>=300&&response.status<400?'REDIRECT_BEFORE_ENDPOINT':'UNEXPECTED_HTTP',
    status:response.status};
  if(response.headers.get('x-vynalth-edge')!=='cloudflare-worker'
    ||response.headers.get('x-vynalth-edge-host')!==item.host)
    return {host:item.host,ok:false,reason:'NOT_PROVEN_WORKER_RESPONSE',status:200};
  let data;
  try{data=await response.json();}catch{return {host:item.host,ok:false,reason:'INVALID_JSON',status:200};}
  if(data?.enabled!==true||data?.scope!=='first-party-root'
    ||data.rootDomain!==item.root||!UUID.test(String(data.globalBrowserId||''))
    ||data.hardwareVerified!==false||data.crossBrowserLinked!==false
    ||data.securityAuthorization!==false)
    return {host:item.host,ok:false,reason:'GBID_RESPONSE_INCOMPLETE',status:200};
  const cookie=response.headers.get('set-cookie')||'';
  if(!cookie.startsWith('__Secure-vyn_browser=')||!cookie.includes('Domain='+item.root)
    ||!cookie.includes('HttpOnly')||!cookie.includes('SameSite=Lax')
    ||!cookie.includes('Secure'))
    return {host:item.host,ok:false,reason:'SIGNED_COOKIE_MISSING_OR_BAD_SCOPE',status:200};
  return {host:item.host,ok:true,reason:'GBID_PRODUCTION_RESPONSE_VERIFIED',status:200};
}

export async function checkRootSubdomainReuse(fetchImpl=fetch) {
  const original='https://vynalthai.com'+endpoint;
  let a,b;
  try {
    a=await fetchImpl(original,{redirect:'manual',signal:AbortSignal.timeout(10000)});
    if(a.status!==200)return {ok:false,reason:'ROOT_UNAVAILABLE',status:a.status};
    const setCookie=a.headers.get('set-cookie')||'';
    const pair=setCookie.split(';')[0];
    if(!pair.startsWith('__Secure-vyn_browser='))return {ok:false,reason:'ROOT_COOKIE_MISSING'};
    const value=await a.json();
    b=await fetchImpl('https://search.vynalthai.com'+endpoint,{
      redirect:'manual',headers:{Cookie:pair},signal:AbortSignal.timeout(10000)});
    if(b.status!==200)return {ok:false,reason:'SUBDOMAIN_UNAVAILABLE',status:b.status};
    const child=await b.json();
    if(!UUID.test(String(value?.globalBrowserId||''))
      ||child?.globalBrowserId!==value.globalBrowserId)
      return {ok:false,reason:'ROOT_SUBDOMAIN_ID_MISMATCH'};
    return {ok:true,reason:'SAME_BROWSER_COOKIE_REUSE_VERIFIED'};
  }catch(e){return {ok:false,reason:'ROOT_SUBDOMAIN_NETWORK_ERROR',
    detail:String(e?.cause?.code||e?.name||'unknown')};}
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  const results=await Promise.all(hosts.map(x=>checkHost(x)));
  for(const result of results) console.log(JSON.stringify(result));
  const reuse=await checkRootSubdomainReuse();
  console.log(JSON.stringify({check:'first-party-subdomain-reuse',...reuse}));
  const passed=results.filter(x=>x.ok).length;
  console.log('LIVE_GLOBAL_BROWSER_ID: '+passed+'/'+results.length+
    ' hosts; same-root continuity='+String(reuse.ok));
  if(passed!==results.length||!reuse.ok)process.exitCode=1;
}
