// Low-noise provider fan-out for classified first-party edge monitor signals.
// A provider acknowledgement never means the notification appeared on a phone.
const recent=new Map();
const WINDOW=5*60*1000;
const TOPIC=/^[a-zA-Z0-9_-]{24,64}$/;
const BOT=/^[0-9]{5,20}:[a-zA-Z0-9_-]{25,}$/;
const CHAT=/^(?:-?[0-9]{3,24}|@[A-Za-z0-9_]{5,32})$/;
const clean=(v,n=140)=>String(v??"").replace(/[\u0000-\u001f\u007f]/g," ").slice(0,n);
async function telegram(env,title,message){
 const bot=env?.SECURITY_MONITOR_TELEGRAM_BOT_TOKEN||env?.TELEGRAM_BOT_TOKEN;
 const chat=env?.SECURITY_MONITOR_TELEGRAM_CHAT_ID||env?.TELEGRAM_CHAT_ID;
 if(!BOT.test(bot||"")||!CHAT.test(chat||""))return "not_configured";
 try{
  const response=await fetch("https://api.telegram.org/bot"+bot+"/sendMessage",{
   method:"POST",headers:{"Content-Type":"application/json"},
   body:JSON.stringify({chat_id:chat,text:title+"\n"+message,
    disable_notification:true,disable_web_page_preview:true}),
   signal:AbortSignal.timeout(5000)});
  if(!response.ok)return "http_"+response.status;
  const json=await response.json();
  return json?.ok===true&&Number.isSafeInteger(json?.result?.message_id)?"accepted":"unverified_response";
 }catch{return "transport_failed";}
}
async function ntfy(env,title,message){
 const topic=env?.SECURITY_MONITOR_NTFY_TOPIC||env?.NTFY_TOPIC_MONITOR;
 if(!TOPIC.test(topic||""))return "not_configured";
 const token=env?.SECURITY_MONITOR_NTFY_TOKEN||env?.NTFY_TOKEN;
 try{
  const headers={"Content-Type":"application/json"};
  if(token)headers.Authorization="Bearer "+token;
  const response=await fetch("https://ntfy.sh/",{
   method:"POST",headers,
   body:JSON.stringify({topic,title,message,priority:2,tags:["shield"]}),
   signal:AbortSignal.timeout(5000)});
  return response.ok?"accepted":"http_"+response.status;
 }catch{return "transport_failed";}
}
export async function dispatchSecurityMonitorAlert(env,event,ingest){
 if(env?.SECURITY_MONITOR_ALERTS_ENABLED!=="true")return {ntfy:"disabled",telegram:"disabled"};
 const host=clean(event.host,90),path=clean(event.path,180),kind=clean(event.event,50);
 const key=[host,path,kind].join("|");
 if(recent.size>2000){for(const [k,t] of recent)if(t<Date.now())recent.delete(k);
  if(recent.size>2000)recent.clear();}
 const message=["Site: "+host,"Signal: "+kind,"Path: "+path,
  "This is a request observation, not proof of compromise."].join("\n");
 const title="🛡️ Vynalth AI website security";
 const outcome={ntfy:"deduplicated",telegram:"deduplicated"};
 const jobs=[];
 for(const [channel,send] of [["ntfy",ntfy],["telegram",telegram]]){
  if((recent.get(channel+":"+key)||0)>Date.now())continue;
  jobs.push((async()=>{
   const result=await send(env,title,message);
   outcome[channel]=result;
   if(result==="accepted")recent.set(channel+":"+key,Date.now()+WINDOW);
  })());
 }
 await Promise.allSettled(jobs);
 const audit={
  timestamp:new Date().toISOString(),service:"vynalth-edge",source:"cloudflare-worker",
  host,log_type:"security",event:"SITE_ALERT_DISPATCH_OUTCOME",request_id:clean(event.request_id),
  alert_type:kind,path,ntfy_status:outcome.ntfy,telegram_status:outcome.telegram,
  verification_status:"unverified_probe",alert_policy:"5m_best_effort_per_isolate",
 };
 await ingest(env,"vynalth-security-logs",audit);
 return outcome;
}
