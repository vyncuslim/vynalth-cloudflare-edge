#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
/**
 * Read-only, unauthenticated, first-party routing preflight.
 * No pairing codes, login sessions, secrets, device identifiers or cookies are sent.
 * GET may receive Set-Cookie; this probe does not retain it.
 * NOT a substitute for consenting-browser end-to-end testing.
 */
export const HOSTS = Object.freeze([
  'vynalthai.si',
  'vyncuslim.com',
  'vyncuslim.my',
  'vyncuslim.si',
  'vynlink.xyz',
  'zokivo.xyz',
  'powiismunc.com',
  'search.vynalthai.com',
  'vynova.vynalthai.com',
]);

export function classifyResponse(response, kind, host, content) {
  if (response.status >= 300 && response.status < 400) {
    return { ok:false, reason:'REDIRECT_BEFORE_DEVICE_HANDLER', status:response.status };
  }
  if (response.status === 403) return { ok:false, reason:'DENIED_BEFORE_OR_IN_WORKER', status:403 };
  if (response.status === 404) return { ok:false, reason:'NO_DEVICE_ROUTE', status:404 };
  if (response.status === 503) return { ok:false, reason:'FEDERATION_OR_SIGNING_UNAVAILABLE', status:503 };
  if (response.status !== 200) return { ok:false, reason:'UNEXPECTED_HTTP_STATUS', status:response.status };
  if (response.headers.get('x-vynalth-edge') !== 'cloudflare-worker'
      || response.headers.get('x-vynalth-edge-host') !== host) {
    return { ok:false, reason:'NOT_PROVEN_EDGE_RESPONSE', status:200 };
  }
  if (kind === 'device') {
    if (!content || content.enabled !== true || content.host !== host
        || content.globalControlEnforcementActive !== true) {
      return { ok:false, reason:'DEVICE_STATUS_INCOMPLETE', status:200 };
    }
  } else if (kind === 'link') {
    if (typeof content !== 'string'
        || !content.includes('Unified Device ID')
        || !content.includes('action="/__vynalth/device/link"')) {
      return { ok:false, reason:'NOT_A_PAIRING_PAGE', status:200 };
    }
  }
  return { ok:true, reason:'READY_FOR_CONSENT_TEST', status:200 };
}

export async function probeHost(host, fetchImpl=fetch) {
  if (!HOSTS.includes(host)) throw Error('HOST_NOT_ALLOWLISTED');
  for (const [kind, path] of [
    ['device','/__vynalth/device'],
    ['link','/__vynalth/device/link'],
  ]) {
    let response;
    try {
      response=await fetchImpl('https://'+host+path,{
        method:'GET', redirect:'manual',
        headers:{Accept:kind==='device'?'application/json':'text/html'},
        signal:AbortSignal.timeout(12000),
      });
    } catch (error) {
      return {host, kind, ok:false, reason:'NETWORK_ERROR', detail:String(error?.cause?.code||error?.name||'unknown')};
    }
    let content;
    try {
      // Ignore error bodies; never dump WAF HTML, cookies or secrets.
      if (response.status===200) {
        if (kind==='device') content=await response.json();
        else content=await response.text();
      }
    } catch { content=null; }
    const verdict=classifyResponse(response,kind,host,content);
    if (!verdict.ok) return {host,kind,...verdict};
  }
  return {host, kind:'device+link', ok:true, reason:'READY_FOR_CONSENT_TEST', status:200};
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href===import.meta.url) {
  const requested=process.argv.slice(2);
  if (requested.some(h=>!HOSTS.includes(h))) {
    console.error('Only explicit managed hosts in HOSTS are allowed.');
    process.exitCode=2;
  } else {
    const targets=requested.length?requested:HOSTS;
    const results=[];
    for (const host of targets) {
      const result=await probeHost(host);
      results.push(result);
      console.log(JSON.stringify(result));
    }
    console.log('RESULT: '+results.filter(r=>r.ok).length+'/'+results.length+' preflight READY');
    if (results.some(r=>!r.ok)) process.exitCode=1;
  }
}
