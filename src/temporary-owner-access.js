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
const CODE_SALT_HEX="2995eb9e615196f4df1949cbf91f71dd1b04191bb4143488";
const CODE_VERIFIER_HEX="85e95aa49d1fdcae3a8d85fc2dc842421c2b32bccd44cbfc859d95cd318c0938";
// Cloudflare's production Workers runtime rejects PBKDF2 iterations > 100,000.
// 25,000 is intentionally below that runtime cap and leaves CPU headroom on
// low-tier Workers. This is GPS-only temporary access, not admin authentication.
// Keep the public verifier resistant to online guessing with WAF rate limiting.
export const OWNER_CODE_ITERATIONS=25000;
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
// Keep return navigation on the chat surface; never accept arbitrary URLs,
// protocol-relative URLs, control characters, or reserved security endpoints.
function safeReturnPath(value){
 if(value===null||value==="")return "/";
 if(typeof value!=="string"||value.length>220||
    !value.startsWith("/")||value.startsWith("//")||
    /[\\?#%\u0000-\u001f]/.test(value))return "/";
 return /^\/(?:en\/|cn\/|ms\/)?c(?:\/[A-Za-z0-9_-]{1,160})?\/?$/.test(value)?value:"/";
}
function formHtml(csrf,error=false,returnPath="/",reason=null){
 const message=!error?"":reason==="csrf"
  ? '<p role="alert" class="error">This verification form expired or could not be confirmed. Please enter your code again in the refreshed form.</p>'
  : '<p role="alert" class="error">Access code not accepted. Check uppercase letters and remove extra spaces before trying again.</p>';
 return '<!doctype html><html lang="en"><head><meta charset="utf-8">'+
  '<meta name="viewport" content="width=device-width,initial-scale=1">'+
  '<meta name="referrer" content="same-origin"><title>Temporary access · Vynalth AI</title>'+
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
  '<input type="hidden" name="return" value="'+returnPath+'">'+
  '<label for="code">Access code</label><input id="code" name="code" type="password" required '+
  'maxlength="128" autocomplete="off" spellcheck="false">'+
  '<button type="submit">Verify and continue</button></form>'+
  '<p><a href="/contact" style="color:#a4caff">Contact support</a></p></main></body></html>';
}
function codeVerifierMode(env){
 const hasSalt=env?.VYNALTH_TEMP_ACCESS_CODE_SALT_HEX!==undefined;
 const hasVerifier=env?.VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX!==undefined;
 return hasSalt&&hasVerifier?"configured":hasSalt||hasVerifier?"incomplete":"built-in";
}
function formResponse(csrf,error=false,status=200,reason=null,returnPath="/",env=null){
 return response(formHtml(csrf,error,returnPath,reason),status,{
  "Content-Type":"text/html; charset=utf-8",
  "Referrer-Policy":"same-origin",
  "X-Vynalth-Owner-Verifier-Mode":codeVerifierMode(env),
  ...(reason?{"X-Vynalth-Owner-Error":reason}:{}),
  "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
  "Set-Cookie":cookie(CSRF,csrf,300)
 });
}
// Some privacy-focused browsers omit Origin on a legitimate same-origin
// form POST. Preserve CSRF/host protections while accepting authoritative
// same-origin Fetch Metadata or same-origin Referer as safe fallbacks.
// A present but mismatched Origin is ALWAYS rejected.
function isSameOriginForm(req){
 const expected="https://"+HOST;
 const origin=req.headers.get("Origin");
 const site=req.headers.get("Sec-Fetch-Site");
 if(site==="cross-site"||site==="same-site")return false;
 if(origin!==null)return origin===expected;
 if(site==="same-origin")return true;
 const referer=req.headers.get("Referer");
 if(!referer)return false;
 try{
  const value=new URL(referer);
  return value.origin===expected&&value.protocol==="https:";
 }catch{return false}
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
async function compareCode(value,env){
 if(typeof value!=="string"||value.length>128)return false;
 // Optional non-secret code-verifier rotation. Both values must be supplied
 // and correctly formatted, or the code check fails closed.
 const hasOverride=env?.VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX!==undefined||
   env?.VYNALTH_TEMP_ACCESS_CODE_SALT_HEX!==undefined;
 const salt=hasOverride?env?.VYNALTH_TEMP_ACCESS_CODE_SALT_HEX:CODE_SALT_HEX;
 const expectedHex=hasOverride?env?.VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX:CODE_VERIFIER_HEX;
 if(typeof salt!=="string"||!/^[a-f0-9]{48}$/.test(salt)||
    typeof expectedHex!=="string"||!/^[a-f0-9]{64}$/.test(expectedHex))return false;
 // A pasted code may include accidental whitespace; normalize only at the
 // edges, never change case or remove interior characters.
 const clean=value.trim();
 if(!clean)return false;
 const key=await crypto.subtle.importKey("raw",ENC.encode(clean),"PBKDF2",false,["deriveBits"]);
 const result=new Uint8Array(await crypto.subtle.deriveBits({
  name:"PBKDF2",salt:fromHex(salt),iterations:OWNER_CODE_ITERATIONS,hash:"SHA-256"
 },key,256));
 const expected=fromHex(expectedHex);
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
 if(req.method==="GET")return formResponse(randomHex(20),false,200,null,
  safeReturnPath(url.searchParams.get("return")),env);
 if(req.method!=="POST")return response("Method Not Allowed",405,{"Allow":"GET, POST"});
 if(!isSameOriginForm(req))
  return response("Forbidden",403,{"X-Vynalth-Owner-Error":"origin"});
 if((req.headers.get("Content-Type")||"").split(";")[0]!=="application/x-www-form-urlencoded")
  return response("Unsupported Media Type",415);
 if(Number(req.headers.get("Content-Length")||0)>512)return response("Payload Too Large",413);
 const ip=clientIp(req);
 if(!ip)return response("Forbidden",403,{"X-Vynalth-Owner-Error":"client-ip"});
 const csrf=getCookie(req,CSRF);
 let params;
 try{
  const body=await req.text();
  if(body.length>512)throw Error("long");
  params=new URLSearchParams(body);
 }catch{return response("Invalid request",400)}
 const returnPath=safeReturnPath(params.get("return"));
 if(!csrf||!/^[a-f0-9]{40}$/.test(csrf)||params.get("csrf")!==csrf)
  return formResponse(randomHex(20),true,403,"csrf",returnPath,env);
 let stage="kv-read";
 try{
  const attempts=await attemptKey(ip);
  const failed=await readAttempts(env.CONSENT_KV,attempts);
  if(failed>=MAX_ATTEMPTS)
   return response("Too many attempts. Try again later.",429,{"Retry-After":"900"});
  stage="code-verification";
  if(!await compareCode(params.get("code"),env)){
   stage="kv-failure-counter";
   await env.CONSENT_KV.put(attempts,String(failed+1),{expirationTtl:ATTEMPT_TTL});
   return formResponse(randomHex(20),true,403,"code",returnPath,env);
  }
  const token="v2."+base64(randomBytes(32));
  const exp=Math.floor(Date.now()/1000)+OWNER_ACCESS_TTL;
  const fingerprint=await shaHex(sessionFingerprint(req,ip));
  stage="kv-session-write";
  await env.CONSENT_KV.put(await sessionKey(token),JSON.stringify({exp,fingerprint}),{
   expirationTtl:OWNER_ACCESS_TTL
  });
  // Session persistence succeeded. Failure to clear the attempt counter
  // must not turn a valid login into a 503 after already minting a token.
  try{await env.CONSENT_KV.delete(attempts)}
  catch{console.warn("temp-owner-access-attempt-cleanup-failed")}
  const headers=new Headers({
   ...HEAD,"Location":"https://"+HOST+returnPath,
   "Set-Cookie":cookie(PASS,token,OWNER_ACCESS_TTL)
  });
  headers.append("Set-Cookie",cookie(CSRF,"",0));
  return new Response(null,{status:303,headers});
 }catch{
  // Error categories are fixed strings; never log submitted codes, tokens,
  // incoming IPs, user agents, or raw KV exceptions.
  console.error("temp-owner-access-failed",stage);
  return response("Temporary access is unavailable",503,{
   "X-Vynalth-Owner-Error":stage
  });
 }
}
