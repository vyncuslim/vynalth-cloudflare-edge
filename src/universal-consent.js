/*
 * Vynalth Universal Consent Management (Cloudflare Workers KV)
 * Dedicated API routes only; no Supabase, fingerprinting or third-party cookies.
 * Requires an authenticated, host-bound, signed SSO assertion from the EXISTING
 * identity backend; this Worker never manufactures identity assertions.
 */
export const CONSENT_DOMAINS=Object.freeze(["vynalthai.com","vyncuslim.com","vynalthai.si","vyncuslim.si"]);
export const TRUSTED_STATUSES=new Set(["trust","contact","status"]);
export const CONSENT_VERSION="2026-10-v1";
export const SHARED_NOTICE_VERSION="vynalth-four-domains-v1";
const API="/__vynalth/consent";
const SID_COOKIE="__Secure-vynalth-consent";
const CSRF_COOKIE="__Secure-vynalth-consent-csrf";
const SSO_COOKIE="__Secure-vynalth-sso";
const HUB_ROOT="vynalthai.com";
const LINK_COOKIE="__Secure-vynalth-consent-link";
const LINK_SECONDS=300;
const CODE_SECONDS=60;
const BOUND_SSO_SECONDS=600;
const COOKIE_SECONDS=60*60*24*90;
const AUDIT_SECONDS=60*60*24*365;
const te=new TextEncoder();
const RESP={
 "Cache-Control":"private, no-store, max-age=0",
 "Content-Type":"application/json; charset=utf-8",
 "Referrer-Policy":"no-referrer",
 "X-Content-Type-Options":"nosniff",
 "X-Frame-Options":"DENY",
 "X-Robots-Tag":"noindex,nofollow"
};
function output(status,data,headers){return new Response(JSON.stringify(data),{status,headers:{...RESP,...headers}});}
function base64(bytes){let x="";for(const b of bytes)x+=String.fromCharCode(b);return btoa(x).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"");}
function decode(value){
 if(typeof value!=="string"||!/^[A-Za-z0-9_-]{2,800}$/.test(value))return null;
 try{
  const normalized=value.replaceAll("-","+").replaceAll("_","/");
  return Uint8Array.from(atob(normalized+"=".repeat((4-normalized.length%4)%4)),ch=>ch.charCodeAt(0));
 }catch{return null;}
}
function rnd(size=24){const bytes=new Uint8Array(size);crypto.getRandomValues(bytes);return base64(bytes);}
function cookieValue(request,name){
 const raw=request.headers.get("Cookie")||"";
 const value=raw.split(";").map(s=>s.trim()).find(s=>s.startsWith(name+"="));
 return value?value.slice(name.length+1):null;
}
function cookie(name,value,domain,seconds,csrf=false){
 // Each registered domain has a distinct first-party cookie shared only with
 // its own subdomains, never a super-cookie across .com and .si.
 return name+"="+value+"; Domain="+domain+"; Path="+(csrf?API:"/")+
  "; Secure; SameSite=Lax; "+(csrf?"":"HttpOnly; ")+"Max-Age="+seconds;
}
async function hkey(secret){
 return crypto.subtle.importKey("raw",te.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
}
async function sig(secret,text){
 return base64(new Uint8Array(await crypto.subtle.sign("HMAC",await hkey(secret),te.encode(text))));
}
async function verify(secret,value,signature){
 const bytes=decode(signature);
 if(!bytes||bytes.length!==32)return false;
 return crypto.subtle.verify("HMAC",await hkey(secret),bytes,te.encode(value));
}
export function consentRoot(host){
 const h=typeof host==="string"?host.toLowerCase().replace(/\.$/,""):"";
 return CONSENT_DOMAINS.find(root=>h===root||h.endsWith("."+root))||null;
}
function isSet(s,n){return typeof s==="string"&&s.length>=n;}
function ready(env){
 return env?.CONSENT_CMP_ENABLED==="true"&&
 env?.CONSENT_KV&&["get","put","list"].every(m=>typeof env.CONSENT_KV[m]==="function")&&
 isSet(env.CONSENT_COOKIE_SECRET,32);
}
export async function signedSSO(request,env,root){
 // Must be issued only by real SSO after a server-validated login.
 // Format: base64url(JSON({sub,status,host,exp,sid})).HMAC-SHA256(payload).
 // Never trust a browser-declared status, user_metadata, location or IP.
 if(!root||!isSet(env?.CONSENT_SSO_SIGNING_SECRET,32))return null;
 const raw=cookieValue(request,SSO_COOKIE);
 if(!raw||raw.length>750)return null;
 const parts=raw.split(".");
 if(parts.length!==2||!await verify(env.CONSENT_SSO_SIGNING_SECRET,parts[0],parts[1]))return null;
 const bytes=decode(parts[0]);
 if(!bytes)return null;
 let claim;try{claim=JSON.parse(new TextDecoder().decode(bytes));}catch{return null;}
 const now=Math.floor(Date.now()/1000);
 if(!claim||typeof claim.sub!=="string"||claim.sub.length<8||claim.sub.length>128||
    !/^[a-zA-Z0-9:_-]+$/.test(claim.sub)||
    typeof claim.sid!=="string"||claim.sid.length<8||claim.sid.length>128||
    !/^[a-zA-Z0-9:_-]+$/.test(claim.sid)||
    claim.host!==root||!Number.isInteger(claim.exp)||
    claim.exp<=now||claim.exp>now+900||
    typeof claim.status!=="string"||claim.status.length>32)return null;
 return {sub:claim.sub,status:claim.status,sid:claim.sid,exp:claim.exp};
}
export async function shieldAccountExempt(request,env,root){
 const identity=await signedSSO(request,env,root);
 return !!identity&&TRUSTED_STATUSES.has(identity.status);
}
async function subjectKey(env,sub){
 const key=env.CONSENT_COOKIE_SECRET;
 const signed=await sig(key,"subject:"+sub);
 return signed.slice(0,43);
}
function parseAnon(request,env,root){
 const raw=cookieValue(request,SID_COOKIE);
 if(!raw||raw.length>260)return null;
 const chunks=raw.split(".");
 if(chunks.length!==3||chunks[0]!=="a"||!/^[A-Za-z0-9_-]{32}$/.test(chunks[1]))return null;
 return {id:chunks[1],signature:chunks[2]};
}
async function anonIdentity(request,env,root){
 const data=parseAnon(request,env,root);
 if(!data)return null;
 return await verify(env.CONSENT_COOKIE_SECRET,"anon|"+root+"|"+data.id,data.signature)?data.id:null;
}

// Cross-domain SSO: vynalthai.com is the *only* authority that can originate
// linked identities. The target never reads that domain's cookies directly.
// The existing vynalthai.com login backend must issue the canonical signed
// host-bound SSO Cookie after validating the real logged-in user.
function errorPage(status,title,message){
 const safe=String(message).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");
 return new Response('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>'+title+'</title><body style="font:16px system-ui;background:#070b16;color:#eef3fb;max-width:650px;margin:6vh auto;padding:24px"><h1>'+title+'</h1><p>'+safe+'</p><p><a href="https://vynalthai.com" style="color:#a4ceff">在 Vynalth AI 主站登录 / Sign in at vynalthai.com</a></p></body></html>',{
  status,headers:{...RESP,"Content-Type":"text/html; charset=utf-8",
   "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
   "Referrer-Policy":"no-referrer"}
 });
}
function safeRedirect(url){
 return new Response(null,{status:302,headers:{...RESP,"Location":url,
  "Referrer-Policy":"no-referrer"}});
}
function linkCodeKey(code){return "vynalth:consent:v1:sso-link:"+code;}
function parseLinkState(state,root){
 if(typeof state!=="string"||state.length>200)return null;
 const arr=state.split(".");
 if(arr.length!==3)return null;
 const [expiry,nonce,mac]=arr;
 if(!/^\d{10,12}$/.test(expiry)||!/^[A-Za-z0-9_-]{32}$/.test(nonce))return null;
 const now=Math.floor(Date.now()/1000),end=Number(expiry);
 return end>now&&end<=now+LINK_SECONDS?{expiry,nonce,mac}:null;
}
async function beginLinkResponse(request,env,url,root){
 const exp=Math.floor(Date.now()/1000)+LINK_SECONDS,nonce=rnd(24);
 const state=[exp,nonce,await sig(env.CONSENT_COOKIE_SECRET,["sso-link",root,exp,nonce].join("|"))].join(".");
 const dest="https://"+HUB_ROOT+API+"/authorize?client="+encodeURIComponent(root)+"&state="+encodeURIComponent(state);
 const headers=new Headers(RESP);
 headers.set("Location",dest);
 headers.set("Referrer-Policy","no-referrer");
 headers.append("Set-Cookie",cookie(LINK_COOKIE,state,root,LINK_SECONDS));
 return new Response(null,{status:302,headers});
}
async function authorizeAtHub(request,env,url,root){
 if(request.method!=="GET"||root!==HUB_ROOT)return output(404,{error:"NOT_FOUND"});
 const target=url.searchParams.get("client");
 const state=url.searchParams.get("state");
 if(!CONSENT_DOMAINS.includes(target)||target===HUB_ROOT||!parseLinkState(state,target))
  return output(400,{error:"INVALID_SSO_TARGET_OR_STATE"});
 const identity=await signedSSO(request,env,HUB_ROOT);
 if(!identity)return errorPage(401,"Vynalth AI SSO","请先在 vynalthai.com 登录，然后从需要同步的网站重新点击连接。账号资料仅以主站服务端验证结果为准。");
 const code=rnd(32),now=Math.floor(Date.now()/1000);
 try{
  // Ephemeral KV ticket. KV deletion is not atomic: do not claim strict
  // one-time redemption under concurrent replay or POP propagation.
  await env.CONSENT_KV.put(linkCodeKey(code),JSON.stringify({
   sub:identity.sub,status:identity.status,sid:identity.sid,
   target,state,exp:now+CODE_SECONDS,issuer:HUB_ROOT
  }),{expirationTtl:CODE_SECONDS});
 }catch{return output(503,{error:"SSO_TICKET_STORAGE_UNAVAILABLE"});}
 const redirect=new URL("https://"+target+API+"/callback");
 redirect.searchParams.set("code",code);
 redirect.searchParams.set("state",state);
 return safeRedirect(redirect.toString());
}
async function completeLink(request,env,url,root){
 if(request.method!=="GET"||root===HUB_ROOT)return output(404,{error:"NOT_FOUND"});
 if(!isSet(env.CONSENT_SSO_SIGNING_SECRET,32))return output(503,{error:"SSO_SIGNING_NOT_CONFIGURED"});
 const state=url.searchParams.get("state");
 const saved=cookieValue(request,LINK_COOKIE);
 const parsed=parseLinkState(state,root);
 if(!parsed||!saved||saved!==state||
    !await verify(env.CONSENT_COOKIE_SECRET,["sso-link",root,parsed.expiry,parsed.nonce].join("|"),parsed.mac))
   return output(403,{error:"SSO_STATE_INVALID_OR_MISSING"});
 const code=url.searchParams.get("code");
 if(!/^[A-Za-z0-9_-]{43}$/.test(code||""))return output(403,{error:"SSO_CODE_INVALID"});
 let ticket;
 try{
  const raw=await env.CONSENT_KV.get(linkCodeKey(code));
  if(!raw)return output(403,{error:"SSO_CODE_EXPIRED_OR_USED"});
  ticket=JSON.parse(raw);
  if(!ticket||ticket.target!==root||ticket.issuer!==HUB_ROOT||ticket.state!==state||
     !Number.isInteger(ticket.exp)||ticket.exp<=Math.floor(Date.now()/1000)||
     !/^[A-Za-z0-9:_-]{8,128}$/.test(ticket.sub||"")||
     !/^[A-Za-z0-9:_-]{8,128}$/.test(ticket.sid||"")||
     typeof ticket.status!=="string"||ticket.status.length>32)
   return output(403,{error:"SSO_TICKET_INVALID"});
  await env.CONSENT_KV.delete(linkCodeKey(code));
 }catch{return output(503,{error:"SSO_TICKET_UNAVAILABLE"});}
 const exp=Math.floor(Date.now()/1000)+BOUND_SSO_SECONDS;
 const payload=base64(te.encode(JSON.stringify({
  sub:ticket.sub,status:ticket.status,sid:ticket.sid,host:root,exp
 })));
 const signature=await sig(env.CONSENT_SSO_SIGNING_SECRET,payload);
 const headers=new Headers(RESP);
 headers.set("Location",API);
 headers.set("Referrer-Policy","no-referrer");
 headers.append("Set-Cookie",cookie(SSO_COOKIE,payload+"."+signature,root,BOUND_SSO_SECONDS));
 headers.append("Set-Cookie",cookie(LINK_COOKIE,"",root,0));
 return new Response(null,{status:302,headers});
}

async function newAnonCookie(env,root,id){
 return cookie(SID_COOKIE,"a."+id+"."+(await sig(env.CONSENT_COOKIE_SECRET,"anon|"+root+"|"+id)),root,COOKIE_SECONDS);
}
async function authDisplayCookie(env,root,userKey,revision){
 const payload="u|"+root+"|"+userKey+"|"+revision;
 return cookie(SID_COOKIE,"u."+userKey+"."+revision+"."+(await sig(env.CONSENT_COOKIE_SECRET,payload)),root,COOKIE_SECONDS);
}
function purposes(input){
 if(!input||typeof input!=="object"||Array.isArray(input))return null;
 const names=["analytics","personalization","marketing"];
 if(Object.keys(input).some(k=>!names.includes(k))||
    names.some(k=>typeof input[k]!=="boolean"))return null;
 return {essential:true,analytics:input.analytics,personalization:input.personalization,marketing:input.marketing};
}
const defaults=()=>({essential:true,analytics:false,personalization:false,marketing:false});
function keys(root,identity,anon){
 if(identity)return "vynalth:consent:v1:subject:"+identity;
 if(anon)return "vynalth:consent:v1:anonymous:"+root+":"+anon;
 return null;
}
function prefKey(prefix,scope,root){return prefix+":"+(scope==="shared"?"shared":root)+":current";}
function histKey(prefix,scope,root){return prefix+":"+(scope==="shared"?"shared":root)+":event:";}
async function readKV(kv,key){
 if(!key)return null;
 try{const raw=await kv.get(key);return raw?JSON.parse(raw):null;}catch{return null;}
}
async function current(env,root,identity,anonId){
 const kv=env.CONSENT_KV;
 const userId=identity?await subjectKey(env,identity.sub):null;
 const localRoot=keys(root,userId,anonId);
 if(!localRoot)return {userId:null,scope:"none",value:null,choices:defaults()};
 const local=await readKV(kv,prefKey(localRoot,"site",root));
 if(!identity)return {userId:null,scope:"site",value:local,choices:local?.choices||defaults()};
 const shared=await readKV(kv,prefKey(localRoot,"shared",root));
 // A shared grant only applies if the user affirmed the four-domain scope.
 // A newer site-specific refusal overrides older affirmative shared grants.
 const allowedShared=shared&&shared.sharedScope===true&&shared.noticeVersion===SHARED_NOTICE_VERSION;
 const newerLocal=local&&allowedShared&&Date.parse(local.updatedAt)>=Date.parse(shared.updatedAt);
 const effective=(allowedShared&&!newerLocal)?shared:local;
 return {userId,scope:effective===shared&&allowedShared?"shared":"site",
         value:effective,choices:effective?.choices||defaults()};
}
function publicState(root,state,authenticated){
 return {domain:root,authenticated,consentVersion:CONSENT_VERSION,
  sharedNoticeVersion:SHARED_NOTICE_VERSION,scope:state.scope,
  choices:state.choices,sharedAcrossDomains:state.scope==="shared",
  updatedAt:state.value?.updatedAt||null,
  withdrawnAt:state.value?.withdrawnAt||null,
  revision:state.value?.revision||0};
}
function sameOrigin(request,url){
 const origin=request.headers.get("Origin");
 const site=request.headers.get("Sec-Fetch-Site");
 return origin===url.origin&&(!site||site==="same-origin");
}
async function jsonBody(request){
 if(!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))return null;
 if(Number(request.headers.get("Content-Length")||0)>2048)return null;
 try{
  const raw=await request.text();if(raw.length>2048)return null;
  const data=JSON.parse(raw);
  return data&&typeof data==="object"&&!Array.isArray(data)?data:null;
 }catch{return null;}
}
function documentPage(root){
 return new Response('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Vynalth Consent</title><style>body{font-family:system-ui;background:#080b12;color:#e8f1ff;max-width:650px;margin:5vh auto;padding:30px;line-height:1.7}fieldset{border:1px solid #526075;padding:20px}button{padding:12px;margin:8px 8px 8px 0;border-radius:8px;cursor:pointer}p{color:#b4c5db}a{color:#accfff}</style><h1>Vynalth Universal Cookie Consent</h1><p>中文：必要 Cookie 始终启用。分析、个性化及营销均可单独选择，拒绝或撤回不会阻止基本使用。</p><p lang="ms">Kuki penting sentiasa aktif. Analitik, pemperibadian dan pemasaran adalah pilihan.</p><p lang="en">Essential cookies are required; analytics, personalization and marketing are optional.</p><p>跨站范围：vynalthai.com、vyncuslim.com、vynalthai.si、vyncuslim.si。仅在你明确允许跨站共享且已登录同一 Vynalth SSO 时，同步肯定同意。</p><p>Cross-site sharing is optional. No fingerprinting or third-party cookies are used.</p><p>统一登录来源为 <strong>vynalthai.com</strong>。其他网站通过主站验证和短期授权码建立各自的第一方会话。</p><p><a href="/__vynalth/consent/link">🔗 连接 vynalthai.com 账号 / Link Vynalth AI SSO</a></p><fieldset><legend>Consent choices</legend><label><input type="checkbox" checked disabled> Essential / 必要</label><div><label><input id="analytics" type="checkbox"> Analytics / 分析</label></div><div><label><input id="personalization" type="checkbox"> Personalization / 个性化</label></div><div><label><input id="marketing" type="checkbox"> Marketing / 营销</label></div><hr><label><input id="share" type="checkbox"> I explicitly agree to apply these choices across all 4 Vynalth domains (logged-in SSO only).</label></fieldset><button id="save">Save preferences</button><button id="deny">Reject optional</button><button id="withdraw">Withdraw consent</button><p id="status" role="status" aria-live="polite"></p><p><a href="https://vynalthai.com/en/legal/privacy">Privacy policy</a></p><script src="/__vynalth/consent/client.js" defer></script></html>',{
  headers:{...RESP,"Content-Type":"text/html; charset=utf-8",
  "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"}
 });
}
const CLIENT=String.raw`"use strict";let token="";const el=id=>document.getElementById(id);function msg(x){el("status").textContent=x}
async function get(path){const r=await fetch("/__vynalth/consent/"+path,{credentials:"same-origin",cache:"no-store"});if(!r.ok)throw Error("HTTP "+r.status);return r.json()}
async function load(){try{const s=await get("session");token=s.csrf;const x=await get("state");["analytics","personalization","marketing"].forEach(k=>el(k).checked=!!x.choices[k]);el("share").checked=!!x.sharedAcrossDomains;if(!x.authenticated)el("share").disabled=true;msg(x.authenticated?"SSO linked. You can manage consent.":"Guest: consent applies only to this site. SSO link requires your existing login integration.")}catch(e){msg("Consent service unavailable: "+e.message)}}
async function save(withdraw=false,deny=false){try{const choices={analytics:!deny&&el("analytics").checked,personalization:!deny&&el("personalization").checked,marketing:!deny&&el("marketing").checked};const sharedScope=!deny&&!withdraw&&el("share").checked;const r=await fetch("/__vynalth/consent/preferences",{method:"POST",credentials:"same-origin",cache:"no-store",headers:{"Content-Type":"application/json","X-Vynalth-Consent-CSRF":token},body:JSON.stringify({action:withdraw?"withdraw":"save",choices,sharedScope,sharedScopeAcknowledged:sharedScope,noticeVersion:"vynalth-four-domains-v1"})});const x=await r.json();if(!r.ok)throw Error(x.error||"Update failed");msg(withdraw?"Consent withdrawn.":deny?"Optional cookies declined.":"Preferences saved.");await load()}catch(e){msg(e.message)}}
el("save").onclick=()=>save();el("deny").onclick=()=>save(false,true);el("withdraw").onclick=()=>save(true);load();`;
function clientPage(){
 return new Response(CLIENT,{headers:{...RESP,"Content-Type":"application/javascript; charset=utf-8"}});
}
async function issueCsrf(root){
 const value=rnd(24);
 return {csrf:value,header:cookie(CSRF_COOKIE,value,root,3600,true)};
}
function csrfOkay(request,root,url){
 if(!sameOrigin(request,url))return false;
 const header=request.headers.get("X-Vynalth-Consent-CSRF");
 const c=cookieValue(request,CSRF_COOKIE);
 return typeof header==="string"&&/^[A-Za-z0-9_-]{32}$/.test(header)&&header===c;
}
function policyCheck(data,identity){
 if(!["save","withdraw"].includes(data.action))return "INVALID_ACTION";
 if(data.action==="save"&&!purposes(data.choices))return "INVALID_CHOICES";
 if(data.sharedScope===true&&(!identity||data.sharedScopeAcknowledged!==true||data.noticeVersion!==SHARED_NOTICE_VERSION))return "SHARED_SCOPE_REQUIRES_VERIFIED_SSO_AND_EXPLICIT_NOTICE";
 if(data.sharedScope!==undefined&&typeof data.sharedScope!=="boolean")return "INVALID_SHARED_SCOPE";
 return null;
}
async function writeConsent(env,root,identity,anonId,input){
 const kv=env.CONSENT_KV;
 let id=anonId;
 let generated=false;
 if(!identity&&!id){id=rnd(24);generated=true;}
 const userKey=identity?await subjectKey(env,identity.sub):null;
 const prefix=keys(root,userKey,id);
 const existingShared=identity?await readKV(kv,prefKey(prefix,"shared",root)):null;
 const scope=identity&&(input.sharedScope===true||
   (input.action==="withdraw"&&existingShared?.sharedScope===true))?"shared":"site";
 const key=prefKey(prefix,scope,root);
 const before=await readKV(kv,key);
 const now=new Date().toISOString();
 const withdraw=input.action==="withdraw";
 const currentChoices=withdraw?defaults():purposes(input.choices);
 const record={
  consentVersion:CONSENT_VERSION,
  noticeVersion:scope==="shared"?SHARED_NOTICE_VERSION:null,
  sharedScope:scope==="shared",
  choices:currentChoices,
  revision:(before?.revision||0)+1,
  updatedAt:now,
  withdrawnAt:withdraw?now:null,
  eventId:crypto.randomUUID()
 };
 const event={...record,action:input.action,domain:root,scope};
 try{
  // Immutable event keys preserve withdrawal history; materialized KV head is
  // eventual-consistent. Never claim transactional durability from Workers KV.
  await kv.put(histKey(prefix,scope,root)+now+":"+record.eventId,
    JSON.stringify(event),{expirationTtl:AUDIT_SECONDS});
  await kv.put(key,JSON.stringify(record));
 }catch{return {error:"KV_WRITE_UNAVAILABLE"};}
 const header=identity?await authDisplayCookie(env,root,userKey,record.revision):
   await newAnonCookie(env,root,id);
 return {record,generated,header};
}
export async function handleUniversalConsent(request,env,url,root){
 if(!root||!url.pathname.startsWith(API))return null;
 // Do not capture unrelated endpoints with the same initial prefix.
 if(url.pathname!==API&& !url.pathname.startsWith(API+"/"))return null;
 if(url.pathname===API||url.pathname===API+"/")return documentPage(root);
 if(url.pathname===API+"/client.js")return clientPage();
 if(!ready(env))return output(503,{error:"CONSENT_SERVICE_NOT_CONFIGURED"});
 const endpoint=url.pathname.slice(API.length+1);
 if(endpoint==="link")return beginLinkResponse(request,env,url,root);
 if(endpoint==="authorize")return authorizeAtHub(request,env,url,root);
 if(endpoint==="callback")return completeLink(request,env,url,root);
 const identity=await signedSSO(request,env,root);
 const anon=identity?null:await anonIdentity(request,env,root);
 if(endpoint==="session"&&request.method==="GET"){
  const challenge=await issueCsrf(root);
  return output(200,{csrf:challenge.csrf,authenticated:!!identity,status:identity?.status||null,
    cookieDomain:root,consentVersion:CONSENT_VERSION},{ "Set-Cookie":challenge.header });
 }
 if(endpoint==="state"&&request.method==="GET"){
  const state=await current(env,root,identity,anon);
  const headers=identity?{"Set-Cookie":await authDisplayCookie(env,root,state.userId,state.value?.revision||0)}:{};
  return output(200,publicState(root,state,!!identity),headers);
 }
 if(endpoint==="history"&&request.method==="GET"){
  const scope=url.searchParams.get("scope")==="shared"?"shared":"site";
  if(scope==="shared"&&!identity)return output(403,{error:"SSO_REQUIRED"});
  const prefix=keys(root,identity?await subjectKey(env,identity.sub):null,anon);
  if(!prefix)return output(200,{events:[],nextCursor:null});
  const cursor=url.searchParams.get("cursor");
  if(cursor&&cursor.length>1024)return output(400,{error:"INVALID_CURSOR"});
  try{
   const list=await env.CONSENT_KV.list({prefix:histKey(prefix,scope,root),limit:50,...(cursor?{cursor}:{})});
   const events=await Promise.all((list.keys||[]).map(async x=>readKV(env.CONSENT_KV,x.name)));
   return output(200,{events:events.filter(Boolean).sort((a,b)=>b.updatedAt.localeCompare(a.updatedAt)),
      nextCursor:list.list_complete?null:list.cursor||null});
  }catch{return output(503,{error:"HISTORY_UNAVAILABLE"});}
 }
 if(endpoint==="preferences"&&request.method==="POST"){
  if(!csrfOkay(request,root,url))return output(403,{error:"CSRF_OR_ORIGIN_REJECTED"});
  const input=await jsonBody(request);
  if(!input)return output(400,{error:"INVALID_JSON"});
  const problem=policyCheck(input,identity);
  if(problem)return output(400,{error:problem});
  const applied=await writeConsent(env,root,identity,anon,input);
  if(applied.error)return output(503,{error:applied.error});
  const state=await current(env,root,identity,identity?null:(await anonIdentity(request,env,root))||null);
  return output(200,{saved:true,withdrawn:input.action==="withdraw",domain:root,
    revision:applied.record.revision,choices:applied.record.choices,
    sharedScope:applied.record.sharedScope,updatedAt:applied.record.updatedAt,
    effectiveState:identity?publicState(root,state,true):null},{
     "Set-Cookie":applied.header
    });
 }
 return output(405,{error:"METHOD_NOT_ALLOWED"});
}
