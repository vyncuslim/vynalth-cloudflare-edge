import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import edge from "../src/index.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const key="test-shared-service-monitor-secret-012345678901234567";
function env(extra={}){
 return {
  SITE_MONITOR_SERVICE_ENABLED:"true",SECURITY_TELEMETRY_ENABLED:"true",
  SECURITY_HONEYPOT_ENABLED:"true",SECURITY_ACCESS_MONITOR_ENABLED:"true",
  AXIOM_SECURITY_INGEST_TOKEN:"test-axiom-ingest-token-000000000000",
  GPS_SERVICE_AUTH_SECRET:key,...extra,
 };
}
const jobs=()=>{const tasks=[];return {waitUntil(p){tasks.push(p);},async done(){await Promise.all(tasks)}}};
async function internal(kind,path,status=0,duration=0,secret=key){
 const ts=String(Math.floor(Date.now()/1000)),method="GET",
  url="https://vyncuslim.com"+path;
 const data=["site-monitor-v1",ts,kind,method,url,String(status),String(duration)].join("\n");
 const cryptoKey=await crypto.subtle.importKey("raw",new TextEncoder().encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const mac=new Uint8Array(await crypto.subtle.sign("HMAC",cryptoKey,new TextEncoder().encode(data)));
 const sig=Array.from(mac,x=>x.toString(16).padStart(2,"0")).join("");
 const headers=new Headers();
 for(const [k,v] of Object.entries({v:"1",ts,kind,status:String(status),
  duration:String(duration),sig}))headers.set("X-Vynalth-Site-Monitor-"+k,v);
 return new Request(url,{method,headers});
}
function fakeFetch(operations){
 const previous=globalThis.fetch;
 globalThis.fetch=async(url,opt={})=>{
  const u=String(url),payload=JSON.parse(opt.body);
  operations.push({url:u,payload});
  if(u.includes("axiom.co"))return Response.json({ingested:1,failed:0});
  if(u.includes("telegram.org"))return Response.json({ok:true,result:{message_id:15}});
  if(u==="https://ntfy.sh/")return Response.json({});
  throw new Error("Unexpected external fetch (potential apex recursion)");
 };
 return ()=>{globalThis.fetch=previous;};
}
test("signed decoy from vv reaches edge, returns 404 and logs host/status without origin access",async()=>{
 const operations=[],restore=fakeFetch(operations),ctx=jobs();
 try{
  const res=await edge.fetch(await internal("trap","/__vynalth-hp/.git/config"),env(),ctx);
  assert.equal(res.status,404);
  assert.equal(res.headers.get("X-Vynalth-Site-Monitor"),"decoy");
  await ctx.done();
  assert.equal(operations.length,1);
  const row=operations[0].payload[0];
  assert.equal(row.host,"vyncuslim.com");
  assert.equal(row.status_code,404);
  assert.equal(row.trap_mode,"active-decoy");
 }finally{restore();}
});
test("spoofed or incorrectly signed monitor call fails closed without contacting origin",async()=>{
 const operations=[],restore=fakeFetch(operations),ctx=jobs();
 try{
  const forged=await internal("trap","/__vynalth-hp/.env",0,0,"incorrect-secret-00000000000000000000000");
  const denied=await edge.fetch(forged,env(),ctx);
  assert.equal(denied.status,403);
  assert.equal(denied.headers.get("X-Vynalth-Site-Monitor"),"invalid-service-auth");
  assert.equal(operations.length,0);
  const disabled=await edge.fetch(await internal("trap","/__vynalth-hp/.env"),
   env({SITE_MONITOR_SERVICE_ENABLED:"false"}),ctx);
  assert.equal(disabled.status,403);
 }finally{restore();}
});
test("passive site probe is logged without blocking the owning vv handler",async()=>{
 const operations=[],restore=fakeFetch(operations),ctx=jobs();
 try{
  const reply=await edge.fetch(await internal("probe","/api/phpinfo.php"),env(),ctx);
  assert.equal(reply.status,204);
  await ctx.done();
  const row=operations[0].payload[0];
  assert.equal(row.event,"SENSITIVE_ROUTE_PROBE");
  assert.equal(row.host,"vyncuslim.com");
  assert.equal(row.status_code,undefined);
 }finally{restore();}
});
test("signed response status and latency feed access log without leaking private request headers",async()=>{
 const operations=[],restore=fakeFetch(operations),ctx=jobs();
 try{
  const res=await edge.fetch(await internal("access","/api/private",503,23),env(),ctx);
  assert.equal(res.status,204);
  await ctx.done();
  assert.equal(operations.length,1);
  const row=operations[0].payload[0];
  assert.equal(row.event,"ACCESS_REQUEST");
  assert.equal(row.status_code,503);
  assert.equal(row.host,"vyncuslim.com");
  assert.equal(row.response_time_ms>=23,true);
  assert.equal(row.ip_source,"unavailable");
 }finally{restore();}
});
test("classified personal-site events notify both Telegram and ntfy and audit provider acceptance",async()=>{
 const operations=[],restore=fakeFetch(operations),ctx=jobs();
 try{
  const e=env({
   SECURITY_MONITOR_ALERTS_ENABLED:"true",
   SECURITY_MONITOR_NTFY_TOPIC:"x".repeat(40),
   SECURITY_MONITOR_TELEGRAM_BOT_TOKEN:"123456789:abcdefghijklmnopqrstuvwxyzABCDE1234",
   SECURITY_MONITOR_TELEGRAM_CHAT_ID:"-1001234567890"
  });
  const res=await edge.fetch(await internal("trap","/__vynalth-hp/hidden-link"),e,ctx);
  assert.equal(res.status,404);await ctx.done();
  assert.equal(operations.filter(x=>x.url==="https://ntfy.sh/").length,1);
  assert.equal(operations.filter(x=>x.url.includes("telegram.org")).length,1);
  const audit=operations.filter(x=>x.url.includes("axiom.co"))
   .flatMap(x=>x.payload).find(x=>x.event==="SITE_ALERT_DISPATCH_OUTCOME");
  assert.equal(audit.host,"vyncuslim.com");
  assert.equal(audit.ntfy_status,"accepted");
  assert.equal(audit.telegram_status,"accepted");
  assert.equal(audit.verification_status,"unverified_probe");
  assert.doesNotMatch(JSON.stringify(audit),/123456789:abcdefghijklmnopqrstuvwxyz|1001234567890/);
 }finally{restore();}
});
