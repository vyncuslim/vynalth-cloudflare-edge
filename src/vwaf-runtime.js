/** Request orchestration: Core + content + actor state + evidence. */
import {applyVynalthWaf,PILOT_HOSTS} from "./vynalth-waf-core.js";
import {inspectWafContent} from "./vwaf-content.js";
import {classifySiteRequest} from "./site-abuse-policy.js";
import {verifyEdgeDevice} from "./domain-device-id.js";
import {classifyNetworkAttribution} from "./axiom-honeypot.js";
import {HARD_IDS,sanitizeEvent} from "./vwaf-policy.js";
const enc=new TextEncoder();
export function rollout(request,env){
 const mode=env?.VYNALTH_WAF_MODE,host=new URL(request.url).hostname;
 return ["observe","enforce"].includes(mode)&&PILOT_HOSTS.includes(host)&&String(env.VYNALTH_WAF_HOSTS||"").split(",").map(x=>x.trim().toLowerCase()).includes(host)?mode:null;
}
async function digestActor(env,host,kind,value){
 const secret=env?.EDGE_DEVICE_ID_SIGNING_SECRET||env?.VISITOR_IP_SIGNING_SECRET;
 if(typeof secret!=="string"||secret.length<32)return null;
 const key=await crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const sig=await crypto.subtle.sign("HMAC",key,enc.encode("vwaf-actor-v1|"+host+"|"+kind+"|"+value));
 return Array.from(new Uint8Array(sig),x=>x.toString(16).padStart(2,"0")).join("");
}
export async function verifiedActors(request,env,verify=verifyEdgeDevice){
 const host=new URL(request.url).hostname,actors=[];
 const cookie=request.headers.get("cookie")||"";
 if(cookie.length<=8192&&/(?:^|;\s*)__Host-vyn_edge_device=/.test(cookie)){
  try{const d=await verify(request,env);if(["valid","rotated"].includes(d.state)&&typeof d.deviceId==="string"){
    const key=await digestActor(env,host,"device",d.deviceId);if(key)actors.push({kind:"device",key});
  }}catch{}
 }
 const net=classifyNetworkAttribution(request);
 if(net.attribution==="cloudflare_edge_observed"&&net.ip&&request.cf?.botManagement?.verifiedBot!==true){
  const key=await digestActor(env,host,"network",net.ip);if(key)actors.push({kind:"network",key});
 }
 return actors;
}
export function rateCategory(request){
 const base=classifySiteRequest(request);if(base)return base;
 const u=new URL(request.url);if(u.hostname!=="vynalthai.com"||request.method!=="POST")return null;
 const p=u.pathname.toLowerCase().replace(/\/+$/,"");
 if(/^\/api\/(?:auth\/)?(?:login|signin|sign-in)$/.test(p))return "LOGIN";
 if(/^\/api\/(?:chat|ai\/(?:chat|chat-chv|chat-router|chat-runtime|chat-generation|chat-guest))$/.test(p))return "CHAT";
 return null;
}
export async function stateCall(env,name,value){
 const ns=env?.SECURITY_DEVICE_RISK;if(!ns?.idFromName)return null;
 // Domain-separated names cannot collide with the legacy hex-only HMAC names.
 const r=await ns.get(ns.idFromName("vwaf:v1:"+name)).fetch("https://vwaf.internal/",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(value),signal:AbortSignal.timeout(1200)});
 if(!r.ok)throw Error("VWAF state unavailable");return r.json();
}
async function budget(env,name,host){
 const b=env?.[name];if(!b?.limit)return false;
 try{return (await b.limit({key:host}))?.success===true}catch{return false}
}
export function recordEvent(env,ctx,event){
 const safe=sanitizeEvent(event);if(!safe)return;
 console.info("[VYNALTH WAF]",JSON.stringify(safe));
 if(typeof ctx?.waitUntil!=="function")return;
 ctx.waitUntil((async()=>{
  if(await budget(env,"VWAF_EVENT_BUDGET",safe.host))await stateCall(env,"ledger-v1",{op:"event",event:safe});
 })().catch(()=>console.warn("[VYNALTH WAF] evidence ledger unavailable")));
}
function deny(status,request,retry){
 return new Response(request.method==="HEAD"?null:status===429?"Rate limit exceeded.":"Temporarily restricted.",{status,headers:{
  "Content-Type":"text/plain; charset=utf-8","Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff",
  "Retry-After":String(Math.max(1,retry)),"X-Robots-Tag":"noindex, nofollow",
  "X-Vynalth-Security-Action":status===429?"vwaf-rate-limit":"vwaf-device-restriction"
 }});
}
export async function enforceVynalthWaf(request,env,ctx,id){
 const mode=rollout(request,env);if(!mode)return null;
 const host=new URL(request.url).hostname;let event=null;
 const hardDenial=applyVynalthWaf(request,env,id,e=>{event=e});
 const hardRules=(event?.rule_ids||[]).filter(x=>HARD_IDS.includes(x));
 if(event)recordEvent(env,ctx,event);
 if(!hardDenial&&env.VYNALTH_WAF_CONTENT_ENABLED==="true"){
  const signals=await inspectWafContent(request);
  if(signals.length)recordEvent(env,ctx,{host,mode,action:"observe",request_id:id,rule_ids:signals.map(x=>x.id),score:Math.min(100,signals.reduce((n,s)=>n+s.score,0))});
 }
 const category=rateCategory(request);
 if((!category&&!hardRules.length)||!["observe","enforce"].includes(env.VYNALTH_WAF_STATE_MODE))return hardDenial;
 if(!await budget(env,"VWAF_STATE_BUDGET",host))return hardDenial;
 const actorMode=mode==="enforce"&&env.VYNALTH_WAF_STATE_MODE==="enforce"?"enforce":"observe";
 let restriction=null,rate=null;
 try{
  for(const actor of await verifiedActors(request,env)){
   const r=await stateCall(env,"actor-v1:"+actor.key,{op:"actor",host,mode:actorMode,kind:actor.kind,id,category,rules:hardRules});
   if(!r)continue;
   if(r.candidate)recordEvent(env,ctx,{host,mode:actorMode,action:r.newRestriction?"restriction":"candidate",request_id:id,rule_ids:[r.newRestriction?"VWAF-402":"VWAF-403"],score:100,actor_kind:actor.kind});
   if(r.newRate)recordEvent(env,ctx,{host,mode:actorMode,action:actorMode==="enforce"?"rate_limit":"observe",request_id:id,rule_ids:["VWAF-401"],score:40,actor_kind:actor.kind});
   if(actorMode==="enforce"&&actor.kind==="device"&&Number.isFinite(r.blockedUntil)&&r.blockedUntil>Date.now())restriction=deny(403,request,Math.ceil((r.blockedUntil-Date.now())/1000));
   if(actorMode==="enforce"&&r.rateExceeded===true)rate=deny(429,request,60);
  }
 }catch{console.warn("[VYNALTH WAF] supplemental state unavailable")}
 return hardDenial||restriction||rate;
}
