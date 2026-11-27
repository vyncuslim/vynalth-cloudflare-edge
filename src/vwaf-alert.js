/** VWAF Alert: fixed destinations, aggregate-only, no per-request sends. */
import {retryDeadline} from "./vwaf-policy.js";
const AXIOM="https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-security-logs";
export function configuredChannels(env){
 if(env?.VYNALTH_WAF_ALERTS_ENABLED!=="true")return [];
 const names=[];
 if(/^[A-Za-z0-9_-]{20,128}$/.test(env.VWAF_NTFY_TOPIC||"")&&typeof env.VWAF_NTFY_TOKEN==="string"&&env.VWAF_NTFY_TOKEN.length>=16)names.push("ntfy");
 if(/^\d{5,20}:[A-Za-z0-9_-]{25,}$/.test(env.VWAF_TELEGRAM_BOT_TOKEN||"")&&/^-?\d{3,24}$/.test(env.VWAF_TELEGRAM_CHAT_ID||""))names.push("telegram");
 if(typeof env.VWAF_AXIOM_INGEST_TOKEN==="string"&&env.VWAF_AXIOM_INGEST_TOKEN.length>=32)names.push("axiom");
 return names;
}
export async function sendDigest(channel,env,digest,fetchImpl=fetch,now=Date.now()){
 if(!configuredChannels(env).includes(channel))return{state:"not_configured"};
 const msg="Vynalth WAF: "+digest.count+" recorded security decisions. Mode: "+digest.mode+
  ". Latest rules: "+digest.rules.join(", ")+". Intrusion not verified. Review the authorized private security logs.";
 let url,headers={"Content-Type":"application/json"},body;
 if(channel==="ntfy"){
  url="https://ntfy.sh/"+encodeURIComponent(env.VWAF_NTFY_TOPIC);
  headers={Authorization:"Bearer "+env.VWAF_NTFY_TOKEN,"Content-Type":"text/plain","Title":"Vynalth WAF digest","Priority":"3"};body=msg;
 }else if(channel==="telegram"){
  url="https://api.telegram.org/bot"+env.VWAF_TELEGRAM_BOT_TOKEN+"/sendMessage";
  body=JSON.stringify({chat_id:env.VWAF_TELEGRAM_CHAT_ID,text:msg,disable_web_page_preview:true});
 }else{url=AXIOM;headers.Authorization="Bearer "+env.VWAF_AXIOM_INGEST_TOKEN;
  body=JSON.stringify([{event:"VYNALTH_WAF_DIGEST",_time:new Date(now).toISOString(),version:"2.0.0-rc.2",count:digest.count,
   mode:digest.mode,rule_ids:digest.rules,sequence:digest.sequence,intrusion_verified:false}]);}
 try{
  const r=await fetchImpl(url,{method:"POST",headers,body,redirect:"error",signal:AbortSignal.timeout(4500)});
  if(r.status===429){let until=retryDeadline(r.headers.get("retry-after"),now);
   if(channel==="telegram"){const b=await r.json().catch(()=>null);const t=b?.parameters?.retry_after;if(Number.isSafeInteger(t)&&t>0)until=Math.max(until,retryDeadline(String(t),now))}
   return{state:"rate_limited",nextAt:until};
  }
  if(!r.ok)return{state:"failed"};
  const b=await r.json().catch(()=>null);
  const ok=channel==="ntfy"?b?.event==="message"&&typeof b.id==="string":
   channel==="telegram"?b?.ok===true&&Number.isInteger(b?.result?.message_id):b?.ingested===1&&(!b.failed||b.failed===0);
  return{state:ok?"sent":"unconfirmed"};
 }catch{return{state:"failed"}}
}
