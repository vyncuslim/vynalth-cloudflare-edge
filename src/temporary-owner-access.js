/**
 * 10-minute first-party GPS-only owner access.
 *
 * Public source code intentionally contains NO reusable cookie-signing
 * secret and NO plaintext access code. A salted PBKDF2 verifier checks the
 * owner-chosen code, while Cloudflare KV holds random, opaque 600s sessions.
 *
 * This is NOT an administrator sign-in or application authorization.
 */
const HOST="vynalthai.com";
export const OWNER_PORTAL="/admin/121@121.1234.vynucslim";
export const OWNER_ACCESS_TTL=600;
const MAX_ATTEMPTS=5;
const ATTEMPT_TTL=900;
const PASS="__Host-vynalth-owner-pass";
const CSRF="__Host-vynalth-owner-csrf";
const ENC=new TextEncoder();
// Public, salted one-way code verifier. Never commit the entered code.
// A public code verifier still permits offline guessing; rotate codes if
// disclosed, and apply a Cloudflare WAF rate limit to this endpoint.
const CODE_SALT_HEX="a1d2d778e2adfc91e66b813b6230406e651c4db1a91d06fa";
const CODE_VERIFIER_HEX="5f72bdc4c45eb62ba47b41f180abde5d5027354328159b017d64e36e9bf0566f";
const CODE_ITERATIONS=180000;
const HEAD={
 "Cache-Control":"private, no-store, max-age=0",
 "Vary":"Cookie",
 "X-Content-Type-Options":"nosniff",
 "Referrer-Policy":"no-referrer",
 "X-Robots-Tag":"noindex,nofollow,noarchive",
 "X-Frame-Options":"DENY",
 "Permissions-Policy":"geolocation=()"
};
const toHex=a=>Array.from(a,x=>x.toString(16).padStart(2,"0")).join("");
const fromHex=h=>Uint8Array.from(h.match(/../g)||[],x=>parseInt(x,16));
function base64(bytes){
 let s="";for(const n of bytes)s+=String.fromCharCode(n);
 return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"");
}
function randomBytes(len){const a=new Uint8Array(len);crypto.getRandomValues(a);return a}
function randomHex(len=16){return toHex(randomBytes(len))}
async function shaHex(message){
 const data=await crypto.subtle.digest("SHA-256",ENC.encode(message));
 return toHex(new Uint8Array(data));
}
function active(env){
 return env?.VYNALTH_TEMP_ACCESS_ENABLED==="true" &&
  env?.CONSENT_KV &&
  ["get","put","delete"].every(name=>typeof env.CONSENT_KV[name]==="function");
}
function getCookie(req,name){
 return (req.headers.get("Cookie")||"").split(";").map(x=>x.trim())
  .find(x=>x.startsWith(name+"="))?.slice(name.length+1)||null;
}
function clientIp(req){
 const ip=req.headers.get("CF-Connecting-IP");
 return typeof ip==="string"&&ip.length<=64&&/^[a-fA-F0-9:.]+$/.test(ip)?ip:null;
}
function sessionFingerprint(req,ip){
 return ["temporary-gps-owner-v2",HOST,ip,req.headers.get("User-Agent")||""].join("|");
}
function cookie(name,value,age){
 return name+"="+value+"; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age="+age;
}
function response(body,status=200,headers={}){
 return new Response(body,{status,headers:{...HEAD,...headers}});
}
function formHtml(csrf,error=false){
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
  '<h1>Temporary website access</h1><p>Enter your access code for a 10-minute GPS-gate exemption. '+
  'This does not sign you in to an administrator account or override other security rules.</p>'+message+
  '<form action="'+OWNER_PORTAL+'" method="POST" autocomplete="off">'+
  '<input type="hidden" name="csrf" value="'+csrf+'">'+
  '<label for="code">Access code</label><input id="code" name="code" type="password" required '+
  'maxlength="128" autocomplete="off" spellcheck="false">'+
  '<button type="submit">Verify and continue</button></form>'+
  '<p><a href="/contact" style="color:#a4caff">Contact support</a></p></main></body></html>';
}
function formResponse(csrf,error=false,status=200){
 return response(formHtml(csrf,error),status,{
  "Content-Type":"text/html; charset=utf-8",
  "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "Set-Cookie":cookie(CSRF,csrf,300)
 });
}
async function attemptKey(ip){
 return "temp-owner-tries:v2:"+await shaHex(CODE_SALT_HEX+"|"+ip);
}
async function sessionKey(value){
 return "temp-owner-pass:v2:"+await shaHex("temp-owner-pass:v2:"+value);
}
async function readAttempts(kv,key){
 const raw=await kv.get(key);
 if(!raw)return 0;
 const value=Number(raw);
 return Number.isSafeInteger(value)&&value>=0?value:MAX_ATTEMPTS;
}
async function compareCode(value){
 if(typeof value!=="string"||value.length>128)return false;
 const key=await crypto.subtle.importKey("raw",ENC.encode(value),"PBKDF2",false,["deriveBits"]);
 const result=new Uint8Array(await crypto.subtle.deriveBits({
  name:"PBKDF2",salt:fromHex(CODE_SALT_HEX),iterations:CODE_ITERATIONS,hash:"SHA-256"
 },key,256));
 const expected=fromHex(CODE_VERIFIER_HEX);
 let diff=0;
 for(let i=0;i<32;i++)diff|=result[i]^expected[i];
 return diff===0;
}
export async function hasTemporaryOwnerPass(req,env,url){
 if(url.hostname!==HOST||!active(env))return false;
 const ip=clientIp(req);if(!ip)return false;
 const token=getCookie(req,PASS);
 if(!/^v2\.[A-Za-z0-9_-]{43}$/.test(token||""))return false;
 try{
  const raw=await env.CONSENT_KV.get(await sessionKey(token));
  if(!raw)return false;
  const record=JSON.parse(raw);
  const now=Math.floor(Date.now()/1000);
  if(!Number.isInteger(record?.exp)||record.exp<=now||record.exp>now+OWNER_ACCESS_TTL||
    typeof record.fingerprint!=="string"||record.fingerprint.length!==64)return false;
  return record.fingerprint===await shaHex(sessionFingerprint(req,ip));
 }catch{
  // Storage errors never grant access. No passwords, cookies, or IPs in logs.
  console.error("temp-owner-access-verification-unavailable");
  return false;
 }
}
export async function handleTemporaryOwnerAccess(req,env,url){
 if(url.hostname!==HOST||url.pathname!==OWNER_PORTAL)return null;
 if(env?.VYNALTH_TEMP_ACCESS_ENABLED!=="true")
  return response("Not Found",404);
 if(!active(env))
  return response("Temporary access KV binding is not configured",503);
 if(req.method==="GET")return formResponse(randomHex(20));
 if(req.method!=="POST")return response("Method Not Allowed",405,{"Allow":"GET, POST"});
 if(req.headers.get("Origin")!=="https://"+HOST||req.headers.get("Sec-Fetch-Site")==="cross-site")
  return response("Forbidden",403);
 if((req.headers.get("Content-Type")||"").split(";")[0]!=="application/x-www-form-urlencoded")
  return response("Unsupported Media Type",415);
 if(Number(req.headers.get("Content-Length")||0)>512)return response("Payload Too Large",413);
 const ip=clientIp(req);if(!ip)return response("Forbidden",403);
 const csrf=getCookie(req,CSRF);
 let params;
 try{
  const body=await req.text();
  if(body.length>512)throw Error("long");
  params=new URLSearchParams(body);
 }catch{return response("Invalid request",400)}
 if(!csrf||!/^[a-f0-9]{40}$/.test(csrf)||params.get("csrf")!==csrf)
  return response("Forbidden",403);
 try{
  const attempts=await attemptKey(ip);
  const failed=await readAttempts(env.CONSENT_KV,attempts);
  if(failed>=MAX_ATTEMPTS)
   return response("Too many attempts. Try again later.",429,{"Retry-After":"900"});
  if(!await compareCode(params.get("code"))){
   await env.CONSENT_KV.put(attempts,String(failed+1),{expirationTtl:ATTEMPT_TTL});
   return formResponse(randomHex(20),true,403);
  }
  const token="v2."+base64(randomBytes(32));
  const exp=Math.floor(Date.now()/1000)+OWNER_ACCESS_TTL;
  const fingerprint=await shaHex(sessionFingerprint(req,ip));
  await env.CONSENT_KV.put(await sessionKey(token),JSON.stringify({exp,fingerprint}),{
   expirationTtl:OWNER_ACCESS_TTL
  });
  await env.CONSENT_KV.delete(attempts);
  const headers=new Headers({
   ...HEAD,"Location":"https://"+HOST+"/",
   "Set-Cookie":cookie(PASS,token,OWNER_ACCESS_TTL)
  });
  headers.append("Set-Cookie",cookie(CSRF,"",0));
  return new Response(null,{status:303,headers});
 }catch{
  console.error("temp-owner-access-storage-unavailable");
  return response("Temporary access is unavailable",503);
 }
}
