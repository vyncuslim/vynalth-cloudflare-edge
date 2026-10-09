// Vynalth Shield volunteer school-egress observation.
// This NEVER blocks an address. Reports are unverified until an owner approves.
const TTL_SECONDS = 72 * 60 * 60;
const MAX_REPORTS_PER_IP_PER_DAY = 4;
const NO_CACHE = {"cache-control":"no-store, max-age=0","x-content-type-options":"nosniff"};
const json = (obj,status=200) => new Response(JSON.stringify(obj),{status,headers:{
  ...NO_CACHE,"content-type":"application/json; charset=utf-8","referrer-policy":"no-referrer"
}});
function isPublicIpv4(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return false;
  const a = ip.split(".").map(Number);
  if (a.some(v=>v<0||v>255)) return false;
  const [x,y,z] = a;
  return !(x===0||x===10||x===127||x>=224||x===169&&y===254||
    x===172&&y>=16&&y<=31||x===192&&y===168||x===100&&y>=64&&y<=127||
    x===192&&y===0&&z===2||x===198&&y===51&&z===100||x===203&&y===0&&z===113);
}
function isPublicIpv6(ip) {
  // Narrow acceptance: globally routable and excludes well-known documentation ranges.
  return /^[0-9a-f:]+$/i.test(ip) && ip.includes(":") &&
    /^[23][0-9a-f]{3}:/i.test(ip) &&
    !/^2001:0?db8:/i.test(ip) && ip.length<=39;
}
function validIp(ip){return typeof ip==="string"&&
  (isPublicIpv4(ip)||isPublicIpv6(ip));}
async function tokenEqual(left,right) {
  const encode=new TextEncoder();
  const [a,b]=await Promise.all([crypto.subtle.digest("SHA-256",encode.encode(left)),
     crypto.subtle.digest("SHA-256",encode.encode(right))]);
  const aa=new Uint8Array(a),bb=new Uint8Array(b);
  let diff=0; for(let i=0;i<aa.length;i++)diff|=aa[i]^bb[i];
  return diff===0;
}
function reportHtml() {
  // No profile collection, no images, no third-party analytics or cookies.
  return String.raw`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="referrer" content="no-referrer">
<title>School Network Report · Vynalth Shield</title>
<style>
:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#071322;color:#edf4fc}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px}
main{width:min(100%,540px);padding:30px;background:linear-gradient(135deg,#102440,#101927);border:1px solid #30516a;border-radius:25px;box-shadow:0 22px 65px #0004}
.brand{font-size:13px;color:#80cdfb;letter-spacing:.08em;font-weight:800}h1{font-size:29px;line-height:1.18;margin:20px 0 16px}
p{color:#bfcee0;line-height:1.65}.lang{font-size:13px;margin:9px 0}
.notice{margin:20px 0;padding:15px;background:#071322;border:1px solid #40516d;border-radius:12px}
label{display:flex;gap:10px;align-items:flex-start;font-size:14px;line-height:1.5;color:#e9f4fd}
input{width:19px;height:19px;flex:none;accent-color:#67c8ff}
button{margin-top:15px;padding:14px;width:100%;border-radius:12px;background:#31a8ed;border:0;color:#06172a;font-weight:800;font-size:15px;cursor:pointer}
button:disabled{opacity:.45;cursor:not-allowed}#msg{margin-top:15px;font-size:14px;white-space:pre-wrap}
small{font-size:12px;color:#93a8c1;line-height:1.6;display:block;margin-top:20px}
</style></head><body><main><div class="brand">🛡 VYNALTH SHIELD / VOLUNTEER REPORT</div>
<h1>Help verify today's school network exit</h1>
<p class="lang" lang="zh-CN">协助确认校园网络当前使用的公网出口 IP。</p>
<p class="lang" lang="ms">Bantu mengesahkan IP keluar rangkaian sekolah hari ini.</p>
<div class="notice"><strong>Before continuing</strong>
<p>Only help if you are voluntarily connected to the school Wi-Fi and school rules permit this check.
You must not use a confiscated or unauthorized device.</p>
<p>Your connection's public IP address and reporting time will be recorded for up to 72 hours.
No name, account, password, device identifier or Wi-Fi SSID will be collected.
A report is only a candidate; it will not automatically block anyone.</p></div>
<form id="report"><label><input id="consent" type="checkbox" required>
<span>I am currently on an authorized school Wi-Fi connection and voluntarily agree to the IP/time report.</span></label>
<button id="submit" disabled type="submit">Report the current public IP</button></form>
<div id="msg" role="status" aria-live="polite"></div>
<small>Not connected to school Wi-Fi? Don't submit. Network report ≠ confirmed identity. Never share a password or change school device/security settings.</small>
</main><script>
const c=document.getElementById('consent'),btn=document.getElementById('submit'),msg=document.getElementById('msg');
c.addEventListener('change',()=>btn.disabled=!c.checked);
document.getElementById('report').addEventListener('submit',async event=>{
event.preventDefault();btn.disabled=true;msg.textContent='Submitting secure network observation...';
try{
const r=await fetch(location.pathname,{method:'POST',credentials:'omit',headers:{'Content-Type':'application/json'},body:JSON.stringify({consent:true,schoolWifiConfirmed:true})});
const data=await r.json();
msg.textContent=r.ok?'Submitted as UNVERIFIED candidate. Thank you. No one was blocked.':
  'Unable to submit: '+(data.error||'service unavailable');
}catch{msg.textContent='Network unavailable. Please try again later.'}
finally{btn.disabled=!c.checked}
});
</script></body></html>`;
}
function headersForHtml(){
  return {...NO_CACHE,"content-type":"text/html; charset=utf-8","referrer-policy":"no-referrer",
    "content-security-policy":"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    "x-frame-options":"DENY"};
}
async function report(request,env) {
  if (!env.SCHOOL_EGRESS_REPORTS) return json({error:"REPORT_SERVICE_NOT_CONFIGURED"},503);
  const origin=request.headers.get("origin");
  if (origin!==new URL(request.url).origin) return json({error:"ORIGIN_REQUIRED"},403);
  if (!(request.headers.get("content-type")||"").startsWith("application/json")) return json({error:"CONTENT_TYPE_REQUIRED"},415);
  const length=Number(request.headers.get("content-length")||0);
  if(length>256)return json({error:"PAYLOAD_TOO_LARGE"},413);
  let body;
  try{body=await request.text();if(body.length>256)return json({error:"PAYLOAD_TOO_LARGE"},413);body=JSON.parse(body);}
  catch{return json({error:"INVALID_BODY"},400);}
  if(body?.consent!==true||body?.schoolWifiConfirmed!==true)return json({error:"CONSENT_REQUIRED"},400);
  const ip=request.headers.get("CF-Connecting-IP")||"";
  if(!validIp(ip))return json({error:"PUBLIC_IP_UNAVAILABLE"},422);
  const now=new Date(),day=now.toISOString().slice(0,10);
  // Keyed by actual Cloudflare edge-observed IP, not a client-submitted value.
  const key="report:"+day+":"+ip.toLowerCase();
  let old=null;
  try{old=JSON.parse(await env.SCHOOL_EGRESS_REPORTS.get(key)||"null");}catch{}
  if((old?.count||0)>=MAX_REPORTS_PER_IP_PER_DAY)
    return json({success:true,alreadyReported:true,classification:"unverified",noAutomaticBlock:true});
  const entry={ip,day,firstSeen:old?.firstSeen||now.toISOString(),
    lastSeen:now.toISOString(),count:(old?.count||0)+1,
    selfDeclaredSchoolWifi:true,verified:false,source:"cloudflare-edge"};
  await env.SCHOOL_EGRESS_REPORTS.put(key,JSON.stringify(entry),{expirationTtl:TTL_SECONDS});
  return json({success:true,classification:"unverified",noAutomaticBlock:true});
}
async function candidates(request,env) {
  const secret=String(env.SCHOOL_EGRESS_REVIEW_TOKEN||"");
  const auth=request.headers.get("authorization")||"";
  if(secret.length<32||!auth.startsWith("Bearer ")||
    !(await tokenEqual(auth.slice(7),secret)))return json({error:"FORBIDDEN"},403);
  if(!env.SCHOOL_EGRESS_REPORTS)return json({error:"REPORT_SERVICE_NOT_CONFIGURED"},503);
  const rows=[];
  let cursor=undefined;
  const seen=new Set();
  do{
    const batch=await env.SCHOOL_EGRESS_REPORTS.list({prefix:"report:",limit:100,cursor});
    for(const item of batch.keys){
      if(rows.length>=300)break;
      const value=await env.SCHOOL_EGRESS_REPORTS.get(item.name);
      if(value){try{
        const row=JSON.parse(value);
        if(validIp(row.ip))rows.push({ip:row.ip,day:row.day,firstSeen:row.firstSeen,
          lastSeen:row.lastSeen,count:row.count,verified:false});
      }catch{}}
    }
    cursor=batch.list_complete?undefined:batch.cursor;
    if(cursor&&(seen.has(cursor)||rows.length>=300))break;
    if(cursor)seen.add(cursor);
  }while(cursor);
  return json({success:true,source:"volunteer-unverified",total:rows.length,reports:rows});
}
export async function handleSchoolVolunteer(request,env,path) {
  if(path==="/school-ip-report") {
    if(request.method==="GET")return new Response(reportHtml(),{status:200,headers:headersForHtml()});
    if(request.method==="POST")return report(request,env);
    return json({error:"METHOD_NOT_ALLOWED"},405);
  }
  if(path==="/_shield/school-egress/candidates") {
    if(request.method==="GET")return candidates(request,env);
    return json({error:"METHOD_NOT_ALLOWED"},405);
  }
  return null;
}
export const schoolVolunteerTest={validIp};
