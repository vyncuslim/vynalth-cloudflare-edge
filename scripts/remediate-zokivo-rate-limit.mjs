/**
 * Guarded Cloudflare zone-only rate limit remediation for ZoKivo.
 * Default is read-only. No write without reviewed rule SHA-256, exact Rule ID,
 * valid zone, and APPLY_ZOKIVO_WAF_CHANGE=I_APPROVE_ZONE_RATE_RULE_CHANGE.
 * Cannot remediate account-level or zone-wide rate limiting rules.
 */
import {fingerprint,proposeNatCounter,HOST} from './zokivo-waf-guard.mjs';
const zone=process.env.CLOUDFLARE_ZONE_ID || '';
const token=process.env.CLOUDFLARE_WAF_WRITE_TOKEN || '';
const ruleId=process.env.ZOKIVO_WAF_RULE_ID || '';
const expected=process.env.ZOKIVO_WAF_EXPECTED_SHA256 || '';
const apply=process.env.APPLY_ZOKIVO_WAF_CHANGE === 'I_APPROVE_ZONE_RATE_RULE_CHANGE';
if (!/^[a-f0-9]{32}$/i.test(zone) || !token || !/^[a-f0-9]{32}$/i.test(ruleId)) {
  console.error('CONFIG_REQUIRED: Set CLOUDFLARE_ZONE_ID, CLOUDFLARE_WAF_WRITE_TOKEN, ZOKIVO_WAF_RULE_ID. No change made.');
  process.exit(2);
}
const url='https://api.cloudflare.com/client/v4/zones/'+zone;
const headers={Authorization:'Bearer '+token,Accept:'application/json'};
async function api(path,method='GET',payload) {
  const c=new AbortController(), timeout=setTimeout(()=>c.abort(),12000);
  try {
    const r=await fetch(url+path,{method,
      headers:{...headers,...(payload?{'Content-Type':'application/json'}:{})},
      signal:c.signal,body:payload?JSON.stringify(payload):undefined});
    if(!r.ok)throw new Error('CLOUDFLARE_API_HTTP_'+r.status);
    const data=await r.json();
    if(!data.success)throw new Error('CLOUDFLARE_API_REJECTED');
    return data.result;
  } finally {clearTimeout(timeout)}
}
const zoneData=await api('');
if(zoneData?.name!=='vynalthai.com')throw new Error('WRONG_CLOUDFLARE_ZONE');
const root=await api('/rulesets/phases/http_ratelimit/entrypoint');
if(!root || root.phase!=='http_ratelimit'||!root.id)throw new Error('NO_ZONE_RATE_RULESET');
const target=(root.rules||[]).find(r=>r.id===ruleId);
const proposal=proposeNatCounter(target);
console.log('ZOKIVO_WAF_PROPOSAL='+JSON.stringify({...proposal.publicSummary,
  expectedSha256:proposal.before,rulesetIdSuffix:String(root.id).slice(-8),
  zoneName:zoneData.name,scope:'zone only',applyRequested:apply}));
if(!apply) {
  console.log('READ_ONLY: No live change made. Review SHA-256 and confirm in workflow.');
  process.exit(0);
}
if(!/^[a-f0-9]{64}$/i.test(expected)||expected!==proposal.before)
  throw new Error('FINGERPRINT_MISMATCH_OR_MISSING: Refusing stale or unapproved rule');
// Use PATCH on one exact rule; never PUT all rules / skip WAF / disable GPS.
const path='/rulesets/'+root.id+'/rules/'+ruleId;
await api(path+'?dry_run=true','PATCH',proposal.patch);
const rootFresh=await api('/rulesets/phases/http_ratelimit/entrypoint');
const current=(rootFresh.rules||[]).find(r=>r.id===ruleId);
if(!current||fingerprint(current)!==proposal.before)
  throw new Error('WAF_RULE_CHANGED_SINCE_REVIEW');
await api(path,'PATCH',proposal.patch);
const after=await api('/rulesets/phases/http_ratelimit/entrypoint');
const updated=(after.rules||[]).find(r=>r.id===ruleId);
if(!updated||!updated.ratelimit?.characteristics?.includes('cf.unique_visitor_id')||
  updated.ratelimit.characteristics.includes('ip.src')||
  updated.expression!==target.expression)
  throw new Error('POST_WRITE_VERIFICATION_FAILED: Recheck Cloudflare immediately');
console.log('ZOKIVO_WAF_UPDATED='+JSON.stringify({hostname:HOST,
  ruleIdSuffix:String(ruleId).slice(-8),success:true,
  characteristics:updated.ratelimit.characteristics,
  requestsPerPeriod:updated.ratelimit.requests_per_period,period:updated.ratelimit.period}));
