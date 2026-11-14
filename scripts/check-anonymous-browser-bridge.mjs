#!/usr/bin/env node
/** Read-only, anonymous, no-cookie Cloudflare production route verifier. */
import {pathToFileURL} from 'node:url';
import {resolve} from 'node:path';

export const HOSTS=Object.freeze(['vynalthai.com','vynlink.xyz','zokivo.xyz']);
const PATH='/__vynalth/browser/bridge/health';
export async function checkBridgeHealth(host,fetchImpl=fetch){
  if(!HOSTS.includes(host))throw Error('HOST_NOT_ALLOWLISTED');
  let response;
  try{
    response=await fetchImpl('https://'+host+PATH,{
      redirect:'manual',method:'GET',headers:{Accept:'application/json'},
      signal:AbortSignal.timeout(12000),
    });
  }catch(error){return {host,ok:false,reason:'NETWORK_ERROR',
    detail:String(error?.cause?.code||error?.name||'unknown')};}
  if(response.status!==200)
    return {host,ok:false,reason:response.status===403?'WAF_OR_POLICY_BLOCK':
      response.status===404?'NO_WORKER_ROUTE':response.status===503?'BRIDGE_CONFIG_UNAVAILABLE':
      response.status>=300&&response.status<400?'REDIRECT_BEFORE_WORKER':'UNEXPECTED_STATUS',
      status:response.status};
  if(response.headers.get('x-vynalth-edge')!=='cloudflare-worker'||
     response.headers.get('x-vynalth-edge-host')!==host)
    return {host,ok:false,reason:'NOT_PROVEN_WORKER_RESPONSE'};
  let value;
  try{value=await response.json();}catch{return {host,ok:false,reason:'NON_JSON_RESPONSE'};}
  if(value?.service!=='vynalth-anonymous-browser-bridge'||
      value?.version!=='consent-v1'||value?.enabled!==true||value?.host!==host||
      value?.consentRequired!==true||value?.crossBrowserLinking!==false||
      value?.securityAuthorization!==false)
    return {host,ok:false,reason:'BRIDGE_HEALTH_INCOMPLETE'};
  return {host,ok:true,reason:'LIVE_BRIDGE_READY'};
}

if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){
  const results=await Promise.all(HOSTS.map(host=>checkBridgeHealth(host)));
  for(const row of results)console.log(JSON.stringify(row));
  console.log('LIVE_CONSENTED_BROWSER_BRIDGE: '+results.filter(r=>r.ok).length+'/'+results.length+' hosts ready');
  if(results.some(r=>!r.ok))process.exitCode=1;
}
