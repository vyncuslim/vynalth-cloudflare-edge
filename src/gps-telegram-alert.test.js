import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { scheduleGpsDenialAlert,telegramGpsStatus } from "./gps-telegram-alert.js";

if(!globalThis.crypto)globalThis.crypto=webcrypto;
const token="123456789:"+ "A".repeat(35);
const secret="sample-signing-secret-restricted-for-test-only-000000000000";
const makeKV=()=>{
 const map=new Map();
 return {
  map,
  async get(key){return map.get(key)||null;},
  async put(key,value,options){
   assert.ok(options.expirationTtl>=60);
   map.set(key,value);
  }
 };
};
function setup(){
 const kv=makeKV(),tasks=[],sent=[];
 const env={GPS_TELEGRAM_ALERTS_ENABLED:"true",
  TELEGRAM_BOT_TOKEN:token,TELEGRAM_CHAT_ID:"-1001234567890",
  GPS_GATE_SESSION_SECRET:secret,CONSENT_KV:kv};
 const ctx={waitUntil:p=>tasks.push(p)};
 const fetchImpl=async(url,options)=>{
  sent.push({url,options});
  return new Response(JSON.stringify({ok:true}),{status:200});
 };
 const request=new Request("https://vynalthai.com/__shield/gps/verify?secret=discard",{
  headers:{"CF-Connecting-IP":"198.51.100.45",
   "Cookie":"__Host-vynalth-geo=private-access-token"}});
 const args={env,request,url:new URL(request.url),requestId:"11111111-2222-3333-4444-555555555555",ctx,fetchImpl};
 return {kv,tasks,sent,env,args};
}
const flush=async tasks=>{while(tasks.length){const copy=tasks.splice(0);await Promise.all(copy);}};
test("Worker GPS alert status requires server-side Bot Chat and KV credentials",()=>{
 const {env}=setup();
 assert.deepEqual(telegramGpsStatus(env),{enabled:true,configured:true});
 assert.deepEqual(telegramGpsStatus({...env,GPS_TELEGRAM_ALERTS_ENABLED:"false"}),
  {enabled:false,configured:true});
 assert.deepEqual(telegramGpsStatus({...env,TELEGRAM_BOT_TOKEN:undefined}),
  {enabled:true,configured:false});
 assert.deepEqual(telegramGpsStatus({...env,CONSENT_KV:undefined}),
  {enabled:true,configured:false});
});
test("campus boundary 403 queues one Telegram message without GPS, IP or credentials",async()=>{
 const {args,tasks,sent,kv}=setup();
 const before={...args};
 scheduleGpsDenialAlert({...args,event:"CAMPUS_BOUNDARY_UNCERTAIN"});
 await flush(tasks);
 assert.equal(sent.length,1);
 assert.equal(sent[0].options.method,"POST");
 assert.equal(sent[0].url,"https://api.telegram.org/bot"+token+"/sendMessage");
 const payload=JSON.parse(sent[0].options.body);
 assert.equal(payload.chat_id,"-1001234567890");
 assert.match(payload.text,/CAMPUS_BOUNDARY_UNCERTAIN/);
 assert.match(payload.text,/HTTP 403/);
 assert.match(payload.text,/vynalthai\.com/);
 assert.match(payload.text,/11111111-2222-3333-4444-555555555555/);
 for(const secretString of ["198.51.100.45","private-access-token","secret=discard",token,secret,
  "5.36870","100.220435"])assert.equal(payload.text.includes(secretString),false);
 assert.ok([...kv.map.keys()].every(key=>!key.includes("198.51.100.45")));
 assert.deepEqual(before.env,args.env);
});
test("global/per-client cooldown prevents refresh-triggered alert spam",async()=>{
 const {args,tasks,sent}=setup();
 scheduleGpsDenialAlert({...args,event:"CAMPUS_BOUNDARY_UNCERTAIN"});
 await flush(tasks);
 scheduleGpsDenialAlert({...args,event:"CAMPUS_BOUNDARY_UNCERTAIN"});
 await flush(tasks);
 assert.equal(sent.length,1,"Repeated same decision cannot immediately spam Telegram");
 scheduleGpsDenialAlert({...args,event:"CAMPUS_RESTRICTED"});
 await flush(tasks);
 assert.equal(sent.length,2,"Distinct confirmed-inside decision gets its own alert");
});
test("Telegram outage never changes access response; missing config is a no-op",async()=>{
 const {args,tasks,sent}=setup();
 const errors=[];
 const fail={...args,fetchImpl:async()=>new Response("unavailable",{status:503})};
 scheduleGpsDenialAlert({...fail,event:"CAMPUS_BOUNDARY_UNCERTAIN"});
 await flush(tasks);
 assert.equal(sent.length,0);
 scheduleGpsDenialAlert({...args,env:{...args.env,TELEGRAM_BOT_TOKEN:""},event:"CAMPUS_RESTRICTED"});
 assert.equal(tasks.length,0);
 scheduleGpsDenialAlert({...args,event:"OUTSIDE"});
 assert.equal(tasks.length,0);
 scheduleGpsDenialAlert({...args,env:{...args.env,GPS_TELEGRAM_ALERTS_ENABLED:"false"},event:"CAMPUS_RESTRICTED"});
 assert.equal(tasks.length,0);
});
