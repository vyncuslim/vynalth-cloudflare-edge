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

async function dispatchGpsAlert({env,request,url,event,requestId,fetchImpl}){
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
  // Cloudflare KV is eventually consistent. This is best-effort flood
  // control, not a distributed atomic lock.
  await kv.put(globalKey,"1",{expirationTtl:GLOBAL_COOLDOWN_SECONDS});
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
  if(!response.ok){
   console.warn("[GPS TELEGRAM] delivery rejected",response.status);
   return {state:"rejected"};
  }
  await kv.put(userKey,"1",{expirationTtl:PER_CLIENT_COOLDOWN_SECONDS});
  return {state:"sent"};
 }catch(err){
  // Never log fetch errors or URL strings; Telegram Bot URL includes token.
  console.warn("[GPS TELEGRAM] delivery unavailable");
  return {state:"failed"};
 }
}

export function scheduleGpsDenialAlert({env,request,url,event,requestId,ctx,fetchImpl=fetch}){
 const status=telegramGpsStatus(env);
 if(!status.enabled||!GPS_ALERT_EVENTS.includes(event))return;
 if(!status.configured){
  console.warn("[GPS TELEGRAM] alert enabled but missing Bot/Chat/KV secrets");
  return;
 }
 const task=dispatchGpsAlert({env,request,url,event,requestId,fetchImpl});
 if(typeof ctx?.waitUntil==="function")ctx.waitUntil(task);
 else void task.catch(()=>console.warn("[GPS TELEGRAM] dispatch failed"));
}
