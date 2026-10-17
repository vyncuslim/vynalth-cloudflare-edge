/**
 * Read-only Cloudflare WAF audit for ZoKivo shared-IP classrooms.
 * NO security settings are mutated, NO token is printed.
 * Requires dedicated Zone:Read + Zone WAF:Read API token and zone ID.
 */
const zone=process.env.CLOUDFLARE_ZONE_ID;
const token=process.env.CLOUDFLARE_WAF_AUDIT_TOKEN;
if(!zone||!token){
  console.error("MISSING_WAF_AUDIT_CREDENTIALS: configure CLOUDFLARE_ZONE_ID and CLOUDFLARE_WAF_AUDIT_TOKEN GitHub Actions secrets.");
  process.exit(2);
}
if(!/^[a-f\d]{32}$/i.test(zone))throw Error("Invalid zone identifier format");
const api="https://api.cloudflare.com/client/v4/zones/"+zone;
async function get(path){
  const controller=new AbortController();
  const timeout=setTimeout(()=>controller.abort(),12000);
  try{
    const r=await fetch(api+path,{headers:{Authorization:"Bearer "+token,Accept:"application/json"},signal:controller.signal});
    if(r.status===404)return null;
    if(!r.ok)throw Error("Cloudflare HTTP "+r.status+" while reading "+path.replace(zone,"[zone]"));
    const body=await r.json();
    if(!body.success)throw Error("Cloudflare rejected WAF read");
    return body.result;
  }finally{clearTimeout(timeout)}
}
const host="zokivo.vynalthai.com";
function fingerprintRule(rule,level,phase){
 const expression=String(rule.expression||"");
 const relevant=expression.includes(host)||
  expression.includes("api/rooms")||
  expression.includes("api/")||
  !expression.includes("http.host"); // broad rules could match ZoKivo
 const ratelimit=rule.ratelimit||{};
 return {
  level,phase,idSuffix:String(rule.id||"").slice(-8),enabled:rule.enabled!==false,
  action:rule.action||null,
  maybeAffectsZoKivo:relevant,
  scope:expression.includes(host)?"exact-host":expression.includes("http.host")?"other-host-or-multi-host":"shared-zone",
  mentionsGameRooms:expression.includes("/api/rooms"),
  mentionsApi:expression.includes("/api/"),
  period:ratelimit.period??null,
  requestsPerPeriod:ratelimit.requests_per_period??null,
  mitigationTimeout:ratelimit.mitigation_timeout??null,
  characteristics:Array.isArray(ratelimit.characteristics)?ratelimit.characteristics.map(x=>
   x==="ip.src"?"source-IP":x==="cf.unique_visitor_id"?"IP-with-NAT-support":x.startsWith("http.request.cookies")?"cookie":x.startsWith("http.request.headers")?"header":x):null,
  hasCustomResponse:Boolean(rule.action_parameters?.response),
 };
}
const report={project:"ZoKivo",host,at:new Date().toISOString(),readOnly:true,
  note:"This audit enumerates zone-level rules and legacy rate limits. Account-level rules, internal Cloudflare protections, and Security Events are not covered.",
  rules:[],errors:[]};
for(const [phase,label] of [["http_ratelimit","rate-limit"],["http_request_firewall_custom","custom"]]){
 try{
  const entry=await get("/rulesets/phases/"+phase+"/entrypoint");
  if(!entry)continue;
  for(const rule of entry.rules||[]){
   report.rules.push(fingerprintRule(rule,"zone",label));
   if(rule.action==="execute"&&rule.action_parameters?.id){
    try{
     const child=await get("/rulesets/"+rule.action_parameters.id);
     for(const member of child?.rules||[])report.rules.push(fingerprintRule(member,"nested-zone",label));
    }catch{report.errors.push("Nested ruleset requires additional read permission");}
   }
  }
 }catch{report.errors.push("Unable to read "+label+" entrypoint (permission or request failure)");}
}
try{
 const legacy=await get("/rate_limits?per_page=100");
 for(const r of legacy||[]){
  const u=String(r.match?.request?.url||"");
  report.rules.push({level:"zone",phase:"legacy-rate-limit",idSuffix:String(r.id||"").slice(-8),
    enabled:!r.disabled,action:r.action?.mode||null,
    maybeAffectsZoKivo:!u.includes("http")||u.includes(host)||u.includes("vynalthai.com"),
    scope:u.includes(host)?"exact-host":"shared-zone-or-unknown",
    period:r.period??null,requestsPerPeriod:r.threshold??null,
    mitigationTimeout:r.action?.timeout??null,characteristics:["source-IP"]});
 }
}catch{report.errors.push("Legacy rate limits could not be read; inspect Cloudflare dashboard if used");}
const likely=report.rules.filter(x=>x.maybeAffectsZoKivo);
console.log("ZOKIVO_WAF_AUDIT="+JSON.stringify({at:report.at,readOnly:true,
  totalRules:report.rules.length,possibleMatches:likely,
  errors:report.errors,
  next:"Open Cloudflare Security Events, filter hostname and HTTP 429 at 2026-10-17 11:55-11:58 UTC. Match actual Rule ID before changing any threshold."}));
if(!report.rules.length)process.exitCode=1;
