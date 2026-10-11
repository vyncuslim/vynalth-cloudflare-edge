/**
 * Conditional GPS gate using trusted Cloudflare geo country and a client
 * timezone claim. Neither field proves real physical position nor VPN status.
 */
const COOKIE="__Host-vynalth-region";
const TTL=120;
const ENC=new TextEncoder();
const MALAYSIA_TIMEZONES=new Set(["Asia/Kuala_Lumpur","Asia/Kuching"]);
const HEAD={"Cache-Control":"private, no-store","Referrer-Policy":"no-referrer",
 "X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex,nofollow","Vary":"Cookie"};
const HTML="<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>Checking access | Vynalth AI</title><style>:root{color-scheme:dark;font-family:Inter,system-ui,sans-serif;background:#0b0c0f;color:#f4f5f7}body{min-height:100dvh;display:grid;place-items:center;margin:0;padding:24px}main{width:min(100%,440px);background:#131519;border:1px solid #ffffff22;border-radius:8px;padding:30px}small,a{color:#b8a8ff}p{line-height:1.6;color:#b7becb}button{background:#b8a8ff;border:0;padding:12px 18px;border-radius:8px;color:#0b0c0f;font-weight:700}</style><script src=\"/__shield/gps/region-client.js\" defer></script></head><body><main><small>VYNALTH AI · ACCESS</small><h1>Checking regional access</h1><p role=\"status\" id=\"message\">Checking your browser timezone. Location permission is not requested unless required.</p><button id=\"retry\" hidden type=\"button\">Try again</button><p><a href=\"/en/legal/privacy\">Privacy Policy</a> · <a href=\"/__shield/gps/disclaimer\">Disclaimer</a></p></main></body></html>";
const CLIENT="\"use strict\";\nasync function check(){\n const status=document.getElementById(\"message\"),retry=document.getElementById(\"retry\");\n retry.hidden=true;\n try{\n  const timezone=Intl.DateTimeFormat().resolvedOptions().timeZone||\"\";\n  const response=await fetch(\"/__shield/gps/region-check\",{method:\"POST\",\n   credentials:\"same-origin\",cache:\"no-store\",headers:{\"Content-Type\":\"application/json\"},\n   body:JSON.stringify({timezone})});\n  if(!response.ok)throw Error(\"regional-check-failed\");\n  const dest=new URL(location.href);dest.searchParams.delete(\"__vynalth_gps_visit\");\n  location.replace(dest.toString());\n }catch{\n  status.textContent=\"Unable to check regional access. Please retry.\";\n  retry.hidden=false;\n }\n}\ndocument.getElementById(\"retry\").addEventListener(\"click\",check);\ncheck();";
function random(){
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 return Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");
}
async function hmac(secret,msg){
 const key=await crypto.subtle.importKey("raw",ENC.encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bytes=new Uint8Array(await crypto.subtle.sign("HMAC",key,ENC.encode(msg)));
 return Array.from(bytes,x=>x.toString(16).padStart(2,"0")).join("");
}
function rawCookie(req){
 return (req.headers.get("Cookie")||"").split(";").map(x=>x.trim())
  .find(x=>x.startsWith(COOKIE+"="))?.slice(COOKIE.length+1)||null;
}
function trustedSource(req,url){
 const country=req.cf?.country;
 if(country==="MY")return {requireGPS:true};
 if(!/^[A-Z]{2}$/.test(country||"")||country==="XX"||country==="T1")
  return {requireGPS:true}; // Country unavailable or Tor: require GPS.
 const ip=req.headers.get("CF-Connecting-IP");
 if(!ip||ip.length>64)return {requireGPS:true};
 return {requireGPS:false,country,ip,host:url.hostname};
}
async function checkCookie(req,env,source){
 const raw=rawCookie(req);
 if(!raw)return null;
 const [expiry,decision,nonce,signature,...extra]=raw.split(".");
 if(extra.length||!/^\d{10}$/.test(expiry||"")||
   !/^(required|foreign)$/.test(decision||"")||
   !/^[a-f0-9]{32}$/.test(nonce||"")||
   !/^[a-f0-9]{64}$/.test(signature||""))return null;
 const now=Math.floor(Date.now()/1000);
 if(Number(expiry)<=now||Number(expiry)>now+TTL)return null;
 const data=[expiry,decision,nonce,source.host,source.country,source.ip].join("|");
 const expected=await hmac(env.GPS_GATE_SESSION_SECRET,data);
 return expected===signature?decision:null;
}
const json=(status,data)=>new Response(JSON.stringify(data),{status,
 headers:{...HEAD,"Content-Type":"application/json; charset=utf-8"}});
export async function gpsRegionalDecision(req,env,url){
 if(env?.GPS_REGION_TIMEZONE_ENABLED!=="true")return {requireGPS:true};
 const source=trustedSource(req,url);
 if(source.requireGPS)return {requireGPS:true};
 const decision=await checkCookie(req,env,source);
 if(decision==="required")return {requireGPS:true};
 if(decision==="foreign")return {skipGPS:true};
 if(url.pathname==="/__shield/gps/region-client.js"&&req.method==="GET")
  return {response:new Response(CLIENT,{status:200,headers:{...HEAD,
   "Content-Type":"application/javascript; charset=utf-8"}})};
 if(url.pathname==="/__shield/gps/region-check"){
  if(req.method!=="POST")return {response:json(405,{error:"METHOD_NOT_ALLOWED"})};
  if((req.headers.get("Content-Type")||"").split(";")[0]!=="application/json")
   return {response:json(415,{error:"INVALID_CONTENT_TYPE"})};
  if(Number(req.headers.get("Content-Length")||0)>256)
   return {response:json(413,{error:"REQUEST_TOO_LARGE"})};
  if(req.headers.get("Origin")!==url.origin||
    req.headers.get("Sec-Fetch-Site")==="cross-site")
   return {response:json(403,{error:"ORIGIN_INVALID"})};
  let data;
  try{const raw=await req.text();if(raw.length>256)throw Error("oversize");data=JSON.parse(raw);}
  catch{return {response:json(400,{error:"INVALID_BODY"})}};
  const tz=typeof data?.timezone==="string"&&data.timezone.length<64?data.timezone:"";
  const verdict=tz&&!MALAYSIA_TIMEZONES.has(tz)?"foreign":"required";
  const expiry=String(Math.floor(Date.now()/1000)+TTL),nonce=random();
  const signature=await hmac(env.GPS_GATE_SESSION_SECRET,
   [expiry,verdict,nonce,source.host,source.country,source.ip].join("|"));
  const cookieValue=[expiry,verdict,nonce,signature].join(".");
  const cookie=COOKIE+"="+cookieValue+"; Path=/; Max-Age="+TTL+
    "; Secure; HttpOnly; SameSite=Lax";
  return {response:new Response(JSON.stringify({checked:true,gpsRequired:verdict==="required"}),{
    status:200,headers:{...HEAD,"Content-Type":"application/json; charset=utf-8",
    "Set-Cookie":cookie}})};
 }
 if(req.method==="GET"&&(req.headers.get("Accept")||"").includes("text/html")&&
   (!req.headers.get("Sec-Fetch-Dest")||
   ["document","empty"].includes(req.headers.get("Sec-Fetch-Dest"))))
  return {response:new Response(HTML,{status:200,headers:{...HEAD,
   "Content-Type":"text/html; charset=utf-8",
   "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}})};
 return {response:json(403,{error:"REGIONAL_CHECK_REQUIRED"})};
}
