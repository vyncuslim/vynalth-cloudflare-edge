import { normalizePolicyIp, runtimeEnforcement, ENFORCEMENT_KEY, MAX_ENFORCEMENT_SECONDS } from "./policy.js";

const COOKIE="__Host-vynalth-ip-admin";
const COOKIE_LIFE=1200;
const FAILURE_TTL=900;
const HEADERS={
  "Content-Type":"application/json; charset=utf-8",
  "Cache-Control":"private, no-store, max-age=0",
  "X-Content-Type-Options":"nosniff",
  "Referrer-Policy":"no-referrer",
  "X-Frame-Options":"DENY",
  "X-Robots-Tag":"noindex,nofollow"
};
const json=(status,body,extra={})=>new Response(JSON.stringify(body),{status,headers:{...HEADERS,...extra}});
const enc=new TextEncoder();

function b64(bytes) {
  let raw="";
  for(const value of bytes) raw+=String.fromCharCode(value);
  return btoa(raw).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/g,"");
}
function unb64(value) {
  if(!/^[A-Za-z0-9_-]{40,100}$/.test(value))return null;
  try{
    const src=value.replace(/-/g,"+").replace(/_/g,"/");
    return Uint8Array.from(atob(src+"=".repeat((4-src.length%4)%4)), c=>c.charCodeAt(0));
  }catch{return null;}
}
function rand(size=24){
  const bytes=new Uint8Array(size);
  crypto.getRandomValues(bytes);
  return b64(bytes);
}
function equals(a,b) {
  if(a.length!==b.length)return false;
  let result=0;
  for(let i=0;i<a.length;i++)result|=a[i]^b[i];
  return result===0;
}
async function checkPassword(value,expected){
  if(typeof value!=="string"||value.length>256||typeof expected!=="string")return false;
  const [a,b]=await Promise.all([
    crypto.subtle.digest("SHA-256",enc.encode(value)),
    crypto.subtle.digest("SHA-256",enc.encode(expected))
  ]);
  return equals(new Uint8Array(a),new Uint8Array(b));
}
async function hmacKey(secret){
  return crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
}
async function sign(secret,payload){
  const key=await hmacKey(secret);
  return b64(new Uint8Array(await crypto.subtle.sign("HMAC",key,enc.encode(payload))));
}
async function verify(secret,payload,signature){
  const bytes=unb64(signature);
  if(!bytes||bytes.length!==32)return false;
  const key=await hmacKey(secret);
  return crypto.subtle.verify("HMAC",key,bytes,enc.encode(payload));
}
function readCookie(request){
  const found=(request.headers.get("Cookie")||"").split(";").map(v=>v.trim())
    .find(v=>v.startsWith(COOKIE+"="));
  return found?found.slice(COOKIE.length+1):null;
}
async function newSession(secret){
  const expires=Math.floor(Date.now()/1000)+COOKIE_LIFE;
  const nonce=rand(),csrf=rand();
  const payload=expires+"."+nonce+"."+csrf;
  const signature=await sign(secret,payload);
  return { token:payload+"."+signature,csrf,expires };
}
async function session(request,secret){
  if(typeof secret!=="string"||secret.length<32)return null;
  const cookie=readCookie(request);
  if(!cookie||cookie.length>400)return null;
  const parts=cookie.split(".");
  if(parts.length!==4)return null;
  const [time,nonce,csrf,signature]=parts;
  if(!/^[0-9]{10,12}$/.test(time)||!/^[A-Za-z0-9_-]{32}$/.test(nonce)||
     !/^[A-Za-z0-9_-]{32}$/.test(csrf))return null;
  const now=Math.floor(Date.now()/1000),expiry=Number(time);
  if(expiry<=now||expiry>now+COOKIE_LIFE)return null;
  if(!await verify(secret,parts.slice(0,3).join("."),signature))return null;
  return { csrf,expiry };
}
function cookie(text,ttl){
  return COOKIE+"="+text+"; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age="+ttl;
}
function originMatches(req,url){
  const origin=req.headers.get("Origin");
  const site=req.headers.get("Sec-Fetch-Site");
  return origin===url.origin&&(!site||site==="same-origin");
}
function configured(env){
  const kv=env?.SCHOOL_IP_KV;
  return typeof env?.ADMIN_IP_PASSWORD==="string"&&env.ADMIN_IP_PASSWORD.length>=12&&
    typeof env?.ADMIN_IP_SESSION_SECRET==="string"&&env.ADMIN_IP_SESSION_SECRET.length>=32&&
    kv&&["get","put","list","delete"].every(name=>typeof kv[name]==="function");
}
async function bodyJson(req){
  if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))return null;
  if(Number(req.headers.get("Content-Length")||0)>1024)return null;
  try{
    const str=await req.text();
    if(str.length>1024)return null;
    const obj=JSON.parse(str);
    return obj&&typeof obj==="object"&&!Array.isArray(obj)?obj:null;
  }catch{return null;}
}
export function publicIp(input){
  const ip=normalizePolicyIp(input);
  if(!ip)return null;
  if(ip.includes(":"))return ip;
  const [a,b,c]=ip.split(".").map(Number);
  if(a===0||a===10||a===127||a>=224||
    a===169&&b===254||
    a===100&&b>=64&&b<=127||
    a===172&&b>=16&&b<=31||
    a===192&&(b===168||b===0)||
    a===198&&(b===18||b===19||b===51&&c===100)||
    a===203&&b===0&&c===113)return null;
  return ip;
}
function visitorIp(request){
  const raw=request.headers.get("CF-Connecting-IP");
  const normal=publicIp(raw);
  if(normal)return normal;
  const octets=typeof raw==="string"?raw.split(".").map(Number):[];
  if(octets.length===4&&octets.every(x=>Number.isInteger(x)&&x>=0&&x<=255)&&octets[0]>=240){
    const v6=publicIp(request.headers.get("CF-Connecting-IPv6"));
    if(v6&&v6.includes(":"))return v6;
  }
  return null;
}
function mode(env){return env?.MODE==="enforce"?"enforce":"observe";}
function badAuth(){return json(403,{error:"UNAUTHORIZED"});}

export async function adminApi(request,env,url){
  if(!configured(env))return json(503,{
    error:"ADMIN_NOT_CONFIGURED",
    hint:"Create Cloudflare Secrets ADMIN_IP_PASSWORD and ADMIN_IP_SESSION_SECRET."
  });
  const kv=env.SCHOOL_IP_KV;
  const endpoint=url.pathname.slice("/admin/ip/api/".length);
  if(endpoint==="login"){
    if(request.method!=="POST")return json(405,{error:"METHOD_NOT_ALLOWED"});
    if(!originMatches(request,url))return badAuth();
    const ip=visitorIp(request);
    if(!ip)return json(403,{error:"PUBLIC_SOURCE_IP_UNAVAILABLE"});
    const failureKey="admin-login-failed:"+ip;
    let failed=0;
    try{
      const v=await kv.get(failureKey);
      failed=v?JSON.parse(v).count||0:0;
    }catch{return json(503,{error:"LOGIN_RATE_LIMIT_UNAVAILABLE"});}
    if(failed>=5)return json(429,{error:"TOO_MANY_ATTEMPTS"});
    const input=await bodyJson(request);
    if(!input||typeof input.password!=="string")return json(400,{error:"PASSWORD_REQUIRED"});
    if(!await checkPassword(input.password,env.ADMIN_IP_PASSWORD)){
      try{
        await kv.put(failureKey,JSON.stringify({count:failed+1}),{expirationTtl:900});
      }catch{return json(503,{error:"LOGIN_RATE_LIMIT_UNAVAILABLE"});}
      return json(401,{error:"INVALID_CREDENTIALS"});
    }
    try{await kv.delete(failureKey);}catch{}
    const s=await newSession(env.ADMIN_IP_SESSION_SECRET);
    return json(200,{authenticated:true,csrf:s.csrf,expires:s.expires},{
      "Set-Cookie":cookie(s.token,COOKIE_LIFE)
    });
  }
  const auth=await session(request,env.ADMIN_IP_SESSION_SECRET);
  if(!auth)return badAuth();
  if(endpoint==="session"&&request.method==="GET")return json(200,{
    authenticated:true,csrf:auth.csrf,expires:auth.expiry,currentIp:visitorIp(request),
    mode:mode(env),edgeVerified:false,
    note:"KV blocklist changes require live MODE=enforce and verified Edge Service Binding on all target websites."
  });
  if(endpoint==="enforcement"&&request.method==="GET"){
    const state=await runtimeEnforcement(kv,env.MODE);
    return json(200,{
      enabled:state.enabled,
      source:state.source,
      expiresAt:state.expiresAt,
      appliesTo:"Policy Worker decisions on covered domains that actually call this service",
      edgeVerified:false,
      routeVerified:false,
      warning:"Cloudflare Edge routes and SCHOOL_POLICY_ENABLED must be verified independently."
    });
  }
  if(endpoint==="list"&&request.method==="GET"){
    const c=url.searchParams.get("cursor");
    if(c&&c.length>1024)return json(400,{error:"INVALID_CURSOR"});
    try{
      const opts={prefix:"blocked:",limit:50};
      if(c)opts.cursor=c;
      const list=await kv.list(opts);
      const items=(list.keys||[]).filter(x=>x.name.startsWith("blocked:")).map(x=>({
        ip:x.name.slice(8),
        addedAt:x.metadata?.addedAt||null,
        expiresAt:x.metadata?.expiresAt||(x.expiration?new Date(x.expiration*1000).toISOString():null),
        reason:x.metadata?.reason||"legacy"
      }));
      return json(200,{items,nextCursor:list.list_complete===false?list.cursor||null:null});
    }catch{return json(503,{error:"LIST_UNAVAILABLE"});}
  }
  if(request.method!=="POST")return json(405,{error:"METHOD_NOT_ALLOWED"});
  if(!originMatches(request,url)||request.headers.get("X-CSRF-Token")!==auth.csrf)return badAuth();

  if(endpoint==="logout"){
    return json(200,{ok:true},{"Set-Cookie":cookie("",0)});
  }
  const input=await bodyJson(request);
  if(!input)return json(400,{error:"INVALID_JSON"});
  if(endpoint==="enforcement"){
    if(typeof input.enabled!=="boolean")return json(400,{error:"BOOLEAN_ENABLED_REQUIRED"});
    // A destructive security policy change needs separate, explicit
    // confirmation in addition to the existing owner cookie + CSRF token.
    if(input.enabled){
      if(input.confirmSharedIpImpact!==true||
         input.confirmEdgePrerequisites!==true||
         input.confirmationText!=="ENABLE") {
        return json(400,{error:"CONFIRMATION_REQUIRED"});
      }
      const now=Date.now(),expiresMs=now+MAX_ENFORCEMENT_SECONDS*1000;
      const record={
        enabled:true,updatedAt:new Date(now).toISOString(),
        expiresAt:new Date(expiresMs).toISOString(),
        expiresAtMs:expiresMs,
        initiatedBy:"authenticated-admin"
      };
      try{
        // No KV TTL: leaving a stale on-record in place ensures that it
        // expires logically to OFF even when MODE=enforce elsewhere.
        await kv.put(ENFORCEMENT_KEY,JSON.stringify(record));
        return json(200,{
          controlSaved:true,
          enabled:true,
          expiresAt:record.expiresAt,
          edgeVerified:false,
          routeVerified:false,
          message:"Policy enforcement activated for up to 1h in KV; Edge routing is not yet verified."
        });
      }catch{return json(503,{error:"ENFORCEMENT_WRITE_FAILED"});}
    }
    // Emergency OFF is deliberately easier than ON, and persists through
    // expiry or deployment changes until an admin explicitly turns it on.
    try{
      await kv.put(ENFORCEMENT_KEY,JSON.stringify({
        enabled:false,updatedAt:new Date().toISOString(),
        initiatedBy:"authenticated-admin"
      }));
      return json(200,{
        controlSaved:true,enabled:false,edgeVerified:false,
        message:"Policy OFF saved. KV propagation may take time; independent Cloudflare WAF rules are unaffected."
      });
    }catch{return json(503,{error:"ENFORCEMENT_WRITE_FAILED"});}
  }
  if(endpoint==="add"){
    if(input.confirmSharedImpact!==true)return json(400,{error:"CONFIRM_SHARED_IMPACT"});
    if(!Number.isInteger(input.hours)||input.hours<1||input.hours>12)return json(400,{error:"TTL_MUST_BE_1_TO_12_HOURS"});
    let ip;
    if(input.kind==="current")ip=visitorIp(request);
    else if(input.kind==="manual")ip=publicIp(input.ip);
    else return json(400,{error:"INVALID_SOURCE_KIND"});
    if(!ip)return json(422,{error:"INVALID_OR_UNAVAILABLE_PUBLIC_IP"});
    const now=Date.now(),hours=input.hours;
    const metadata={
      addedAt:new Date(now).toISOString(),
      expiresAt:new Date(now+hours*3600000).toISOString(),
      reason:input.kind==="current"?"admin-current":"admin-manual"
    };
    try{
      await kv.put("blocked:"+ip,JSON.stringify(metadata),{
        expirationTtl:hours*3600,metadata
      });
      return json(201,{
        storedInKV:true,ip,expiresAt:metadata.expiresAt,mode:mode(env),
        effectiveAcrossWebsites:"unverified",
        note:"KV record created; live WAF and Edge routing not confirmed."
      });
    }catch{return json(503,{error:"KV_WRITE_FAILED"});}
  }
  if(endpoint==="remove"){
    const ip=publicIp(input.ip);
    if(!ip)return json(422,{error:"INVALID_PUBLIC_IP"});
    try{
      await kv.delete("blocked:"+ip);
      return json(200,{
        removedFromKV:true,ip,
        note:"KV deletion complete; propagation and independent Cloudflare WAF lists are separate."
      });
    }catch{return json(503,{error:"KV_DELETE_FAILED"});}
  }
  return json(404,{error:"NOT_FOUND"});
}
