/**
 * vynalthai.com temporary owner GPS-pass portal.
 *
 * This is NOT an application admin login or SSO assertion. Never mint an
 * ordinary user/admin session or skip the separate WAF/School IP policies.
 * The code and signing key live only in Cloudflare Worker Secrets.
 */
const HOST="vynalthai.com";
export const OWNER_PORTAL="/admin/121@121.1234.vynucslim";
export const OWNER_ACCESS_TTL=600;
const MAX_ATTEMPTS=5;
const ATTEMPT_TTL=900;
const PASS="__Host-vynalth-owner-pass";
const CSRF="__Host-vynalth-owner-csrf";
const ENC=new TextEncoder();
const HEAD={
 "Cache-Control":"private, no-store, max-age=0",
 "X-Content-Type-Options":"nosniff",
 "Referrer-Policy":"no-referrer",
 "X-Robots-Tag":"noindex,nofollow,noarchive",
 "X-Frame-Options":"DENY",
 "Permissions-Policy":"geolocation=()"
};
function base64(bytes){
 let s="";for(const n of bytes)s+=String.fromCharCode(n);
 return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"");
}
function unbase64(s){
 if(!/^[A-Za-z0-9_-]{43}$/.test(s||""))return null;
 try{const b=atob(s.replaceAll("-","+").replaceAll("_","/")+"=");return Uint8Array.from(b,x=>x.charCodeAt(0));}
 catch{return null}
}
function randomHex(len=16){const a=new Uint8Array(len);crypto.getRandomValues(a);return Array.from(a,x=>x.toString(16).padStart(2,"0")).join("")}
async function signingKey(env){
 return crypto.subtle.importKey("raw",ENC.encode(env.VYNALTH_TEMP_ACCESS_SIGNING_SECRET),
  {name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
}
function secretsReady(env){
 return env?.VYNALTH_TEMP_ACCESS_ENABLED==="true" &&
   typeof env.VYNALTH_TEMP_ACCESS_CODE==="string"&&env.VYNALTH_TEMP_ACCESS_CODE.length>=12&&
   typeof env.VYNALTH_TEMP_ACCESS_SIGNING_SECRET==="string"&&
   env.VYNALTH_TEMP_ACCESS_SIGNING_SECRET.length>=32;
}
function getCookie(req,name){
 return (req.headers.get("Cookie")||"").split(";").map(x=>x.trim())
  .find(x=>x.startsWith(name+"="))?.slice(name.length+1)||null;
}
function clientIp(req){
 const ip=req.headers.get("CF-Connecting-IP");
 return typeof ip==="string"&&ip.length<=64&&/^[a-fA-F0-9:.]+$/.test(ip)?ip:null;
}
function binding(req,ip,exp,nonce){
 return ["temporary-gps-owner-v1",HOST,exp,nonce,ip,req.headers.get("User-Agent")||""].join("|");
}
function cookie(name,value,age){
 return name+"="+value+"; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age="+age;
}
function policyResponse(body,status=200,headers={}){
 return new Response(body,{status,headers:{...HEAD,...headers}});
}
function html(error="",csrf=""){
 const message=error?'<p role="alert" class="error">The code was not accepted, or the request is temporarily unavailable.</p>':"";
 return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
  '<meta name="viewport" content="width=device-width,initial-scale=1">'+
  '<meta name="referrer" content="no-referrer"><title>Temporary access · Vynalth AI</title>'+
  '<style>:root{color-scheme:dark;font:16px system-ui,sans-serif;background:#080d16;color:#eaf1fb}'+
  'body{min-height:100vh;display:grid;place-items:center;margin:0;padding:20px}'+
  'main{width:min(100%,420px);border:1px solid #334363;border-radius:16px;background:#101a2a;padding:30px}'+
  'h1{font-size:24px}p{line-height:1.6;color:#b9c7d8}label{display:block;margin:18px 0 8px}'+
  'input{box-sizing:border-box;width:100%;padding:12px;background:#0a1020;border:1px solid #657b9a;border-radius:8px;color:#fff}'+
  'button{margin-top:18px;padding:12px 20px;background:#a4caff;color:#07111c;border:0;border-radius:8px;font-weight:700}'+
  '.error{color:#ffb7b7}</style></head><body><main><small>VYNALTH AI · OWNER ACCESS</small>'+
  '<h1>Temporary website access</h1><p>Enter your access code to request a 10-minute GPS-gate exemption on this site. '+
  'This does not sign you in to an administrator account or override other security rules.</p>'+message+
  '<form action="'+OWNER_PORTAL+'" method="POST" autocomplete="off">'+
  '<input type="hidden" name="csrf" value="'+csrf+'">'+
  '<label for="code">Access code</label><input id="code" name="code" type="password" required '+
  'maxlength="128" autocomplete="off" spellcheck="false">'+
  '<button type="submit">Verify and continue</button></form>'+
  '<p><a href="/contact" style="color:#a4caff">Contact support</a></p></main></body></html>';
}
function portalResponse(csrf,error="",status=200){
 return policyResponse(html(error,csrf),status,{
  "Content-Type":"text/html; charset=utf-8",
  "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "Set-Cookie":cookie(CSRF,csrf,300)
 });
}
async function keyForIp(req,env,ip){
 const key=await signingKey(env);
 const buf=new Uint8Array(await crypto.subtle.sign("HMAC",key,ENC.encode("temp-owner-tries:"+ip)));
 return "temp-owner-tries:"+base64(buf);
}
async function readAttempts(kv,key){
 const value=await kv.get(key);
 if(!value)return 0;
 const n=Number(value);
 if(!Number.isSafeInteger(n)||n<0)return MAX_ATTEMPTS;
 return n;
}
async function compareCode(value,expected){
 if(typeof value!=="string"||value.length>128)return false;
 // Constant-work digest comparison avoids leaking the secret through a
 // character-by-character early exit.
 const [a,b]=await Promise.all([
  crypto.subtle.digest("SHA-256",ENC.encode(value)),
  crypto.subtle.digest("SHA-256",ENC.encode(expected))
 ]);
 const aa=new Uint8Array(a),bb=new Uint8Array(b);let diff=0;
 for(let i=0;i<32;i++)diff|=aa[i]^bb[i];
 return diff===0;
}
export async function hasTemporaryOwnerPass(req,env,url){
 if(url.hostname!==HOST||!secretsReady(env))return false;
 const ip=clientIp(req);if(!ip)return false;
 const raw=getCookie(req,PASS);
 if(!raw||raw.length>250)return false;
 const [exp,nonce,tag,...extra]=raw.split(".");
 if(extra.length||!(/^\d{10}$/.test(exp||""))||
   !/^[a-f0-9]{32}$/.test(nonce||""))return false;
 const now=Math.floor(Date.now()/1000);
 if(Number(exp)<=now||Number(exp)>now+OWNER_ACCESS_TTL)return false;
 const actual=unbase64(tag);if(!actual||actual.length!==32)return false;
 try{
  const key=await signingKey(env);
  return await crypto.subtle.verify("HMAC",key,actual,
   ENC.encode(binding(req,ip,exp,nonce)));
 }catch{return false}
}
export async function handleTemporaryOwnerAccess(req,env,url){
 if(url.hostname!==HOST||url.pathname!==OWNER_PORTAL)return null;
 // Do not make the portal available on foreign/sibling domains.
 if(env?.VYNALTH_TEMP_ACCESS_ENABLED!=="true")
  return policyResponse("Not Found",404);
 if(!secretsReady(env)||!env.CONSENT_KV||
   typeof env.CONSENT_KV.get!=="function"||
   typeof env.CONSENT_KV.put!=="function"||
   typeof env.CONSENT_KV.delete!=="function")
  return policyResponse("Temporary access is not configured",503);
 if(req.method==="GET"){
  return portalResponse(randomHex(20));
 }
 if(req.method!=="POST")return policyResponse("Method Not Allowed",405,{"Allow":"GET, POST"});
 if(req.headers.get("Origin")!=="https://"+HOST||req.headers.get("Sec-Fetch-Site")==="cross-site")
  return policyResponse("Forbidden",403);
 if((req.headers.get("Content-Type")||"").split(";")[0]!=="application/x-www-form-urlencoded")
  return policyResponse("Unsupported Media Type",415);
 if(Number(req.headers.get("Content-Length")||0)>512)return policyResponse("Payload Too Large",413);
 const ip=clientIp(req);if(!ip)return policyResponse("Forbidden",403);
 const saved=getCookie(req,CSRF);
 let values;
 try{
  const body=await req.text();if(body.length>512)throw Error("long");
  values=new URLSearchParams(body);
 }catch{return policyResponse("Invalid request",400);}
 if(!saved||!/^[a-f0-9]{40}$/.test(saved)||
    values.get("csrf")!==saved)return policyResponse("Forbidden",403);
 const attemptKey=await keyForIp(req,env,ip);
 try{
  const failed=await readAttempts(env.CONSENT_KV,attemptKey);
  if(failed>=MAX_ATTEMPTS)
   return policyResponse("Too many attempts. Try again later.",429,{"Retry-After":"900"});
  if(!await compareCode(values.get("code"),env.VYNALTH_TEMP_ACCESS_CODE)){
   await env.CONSENT_KV.put(attemptKey,String(failed+1),{expirationTtl:ATTEMPT_TTL});
   return portalResponse(randomHex(20),"invalid",403);
  }
  await env.CONSENT_KV.delete(attemptKey);
  const exp=String(Math.floor(Date.now()/1000)+OWNER_ACCESS_TTL),nonce=randomHex();
  const signature=base64(new Uint8Array(await crypto.subtle.sign("HMAC",
   await signingKey(env),ENC.encode(binding(req,ip,exp,nonce)))));
  const headers=new Headers({
   ...HEAD,"Location":"https://"+HOST+"/",
   "Set-Cookie":cookie(PASS,[exp,nonce,signature].join("."),OWNER_ACCESS_TTL)
  });
  headers.append("Set-Cookie",cookie(CSRF,"",0));
  return new Response(null,{status:303,headers});
 }catch{
  console.error("temp-owner-access-storage-unavailable");
  return policyResponse("Temporary access is unavailable",503);
 }
}
