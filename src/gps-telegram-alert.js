/**
 * Optional Cloudflare Worker -> Telegram operational alert for GPS 403 decisions.
 * Never executed by the browser; all secrets remain Cloudflare Worker secrets.
 * Do not include location coordinates, raw IP, Cookie, or query strings.
 */
export const GPS_ALERT_EVENTS = Object.freeze([
  "CAMPUS_BOUNDARY_UNCERTAIN",
  "CAMPUS_RESTRICTED",
]);

const PER_CLIENT_COOLDOWN_SECONDS=900;
const GLOBAL_COOLDOWN_SECONDS=60;
const BOT_TOKEN_PATTERN=/^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$/;
const CHAT_ID_PATTERN=/^(?:-?[0-9]{3,24}|@[A-Za-z0-9_]{5,32})$/;
const encoder=new TextEncoder();

// This is a best-effort backoff for the GPS path, which shares the Bot API
// with other alert senders. It prevents repeated 429s within an isolate,
// without a new paid binding or any persistence of user identifiers.
// This is NOT globally atomic across Workers locations.
export function createGpsTelegramFloodControl(){
 let inFlight=false;
 let retryUntil=0;
 return {
  enter(now=Date.now()){
   if(inFlight||now<retryUntil)return false;
   inFlight=true;
   return true;
  },
  hold(retryAfterSeconds,now=Date.now()){
   const seconds=Number.isInteger(retryAfterSeconds)
    ?Math.max(1,Math.min(3600,retryAfterSeconds)):60;
   retryUntil=Math.max(retryUntil,now+seconds*1000);
  },
  release(){inFlight=false;}
 };
}
const defaultGpsFloodControl=createGpsTelegramFloodControl();

export function telegramGpsStatus(env){
 const enabled=env?.GPS_TELEGRAM_ALERTS_ENABLED==="true";
 const token=env?.GPS_TELEGRAM_BOT_TOKEN||env?.TELEGRAM_BOT_TOKEN;
 const chat=env?.GPS_TELEGRAM_CHAT_ID||env?.TELEGRAM_CHAT_ID||env?.ADMIN_TELEGRAM_CHAT_ID;
 const configured=typeof token==="string"&&BOT_TOKEN_PATTERN.test(token)&&
  typeof chat==="string"&&CHAT_ID_PATTERN.test(chat)&&
  typeof env?.CONSENT_KV?.get==="function"&&typeof env?.CONSENT_KV?.put==="function";
 return {enabled,configured};
}

async function pseudonym(secret,ip){
 if(!secret||!ip)return "anonymous";
 const key=await crypto.subtle.importKey("raw",encoder.encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bytes=new Uint8Array(await crypto.subtle.sign("HMAC",key,
  encoder.encode("vynalth-gps-telegram-dedupe-v1|"+ip)));
 return Array.from(bytes.slice(0,12),x=>x.toString(16).padStart(2,"0")).join("");
}

function sanitizeRef(s){
 return typeof s==="string"&&/^[a-zA-Z0-9_-]{8,64}$/.test(s)?s:"unavailable";
}
function sanitizeHost(s){
 return typeof s==="string"&&/^[a-z0-9.-]{1,160}$/.test(s)?s:"unavailable";
}
function buildMessage(event,host,ref){
 return [
  "🚨 Vynalth AI — GPS access denied",
  "Event: "+event,
  "Severity: "+(event==="CAMPUS_RESTRICTED"?"High":"Warning"),
  "Decision: HTTP 403 (access denied)",
  "Host: "+host,
  "Request ID: "+ref,
  "Time (UTC): "+new Date().toISOString(),
  event==="CAMPUS_BOUNDARY_UNCERTAIN"
   ?"Reason: Reported position inside an approximate campus polygon, near its boundary; retryable."
   :"Reason: Reported position classified inside an approximate campus polygon.",
  "Source: Cloudflare Worker",
  "Privacy: No GPS coordinates, raw IP, device ID or access token included.",
 ].join("\n");
}

async function dispatchGpsAlert({env,request,url,event,requestId,fetchImpl,
 floodControl=defaultGpsFloodControl,now=Date.now}){
 const status=telegramGpsStatus(env);
 if(!status.enabled)return {state:"disabled"};
 if(!status.configured)return {state:"unconfigured"};
 if(!GPS_ALERT_EVENTS.includes(event))return {state:"ignored"};
 const kv=env.CONSENT_KV;
 const host=sanitizeHost(url.hostname);
 const rawIp=request.headers.get("CF-Connecting-IP");
 const visitorKey=await pseudonym(env.GPS_GATE_SESSION_SECRET,rawIp);
 const prefix="gps:telegram:v1:"+event+":"+host+":";
 const globalKey=prefix+"global";
 const userKey=prefix+visitorKey;
 try{
  const [recentGlobal,recentUser]=await Promise.all([kv.get(globalKey),kv.get(userKey)]);
  if(recentGlobal||recentUser)return {state:"throttled"};
  // Cloudflare KV is eventually consistent. Do NOT set delivery cooldown
  // before a confirmed ack. The separate per-isolate limiter only prevents
  // simultaneous sends and respects explicit Bot API 429 retry_after.
  if(!floodControl.enter(now()))return {state:"throttled"};
  try {
  const token=env.GPS_TELEGRAM_BOT_TOKEN||env.TELEGRAM_BOT_TOKEN;
  const chat=env.GPS_TELEGRAM_CHAT_ID||env.TELEGRAM_CHAT_ID||env.ADMIN_TELEGRAM_CHAT_ID;
  const response=await fetchImpl("https://api.telegram.org/bot"+token+"/sendMessage",{
   method:"POST",
   headers:{"Content-Type":"application/json"},
   body:JSON.stringify({chat_id:chat,
    text:buildMessage(event,host,sanitizeRef(requestId)),
    disable_web_page_preview:true}),
   signal:AbortSignal.timeout(4500)
  });
  if(response.status===429){
   const denied=await response.json().catch(()=>null);
   floodControl.hold(denied?.parameters?.retry_after,now());
   console.warn("[GPS TELEGRAM] rate-limited; retry_after cooldown active");
   return {state:"rate_limited"};
  }
  if(!response.ok){
   console.warn("[GPS TELEGRAM] delivery rejected",response.status);
   return {state:"rejected"};
  }
  // HTTP 200 alone is insufficient evidence of a successful sendMessage.
  // Telegram's Bot API must explicitly acknowledge with ok=true and a
  // message_id. Do not log the token-bearing URL or message payload.
  const ack=await response.json().catch(()=>null);
  if(ack?.ok!==true||!Number.isInteger(ack?.result?.message_id)){
   console.warn("[GPS TELEGRAM] delivery acknowledgment missing");
   return {state:"unconfirmed"};
  }
  // Mark cooldown only *after* a confirmed Telegram acknowledgment.
  // KV write failures may increase duplicates but must not turn a confirmed
  // send into an unconfirmed event. KV is not an atomic distributed lock.
  try{
   await Promise.all([
    kv.put(globalKey,"1",{expirationTtl:GLOBAL_COOLDOWN_SECONDS}),
    kv.put(userKey,"1",{expirationTtl:PER_CLIENT_COOLDOWN_SECONDS})
   ]);
  }catch{
   console.warn("[GPS TELEGRAM] delivered, cooldown storage unavailable");
  }
  return {state:"sent"};
  }finally{
   floodControl.release();
  }
 }catch(err){
  // Never log fetch errors or URL strings; Telegram Bot URL includes token.
  console.warn("[GPS TELEGRAM] delivery unavailable");
  return {state:"failed"};
 }
}

export function scheduleGpsDenialAlert({env,request,url,event,requestId,ctx,
 fetchImpl=fetch,floodControl=defaultGpsFloodControl,now=Date.now}){
 const status=telegramGpsStatus(env);
 if(!status.enabled||!GPS_ALERT_EVENTS.includes(event))return;
 if(!status.configured){
  console.warn("[GPS TELEGRAM] alert enabled but missing Bot/Chat/KV secrets");
  return;
 }
 const task=dispatchGpsAlert({env,request,url,event,requestId,fetchImpl,floodControl,now});
 if(typeof ctx?.waitUntil==="function")ctx.waitUntil(task);
 else void task.catch(()=>console.warn("[GPS TELEGRAM] dispatch failed"));
}
