import test from "node:test";
import assert from "node:assert/strict";
import {inspectStructuredContent,inspectWafContent} from "./vwaf-content.js";
import {actorTransition,BAN,WINDOW,RETAIN,freshLedger,reserveChannel,retryDeadline,sanitizeEvent} from "./vwaf-policy.js";
import {sendDigest,configuredChannels} from "./vwaf-alert.js";
import {verifiedActors,rateCategory,enforceVynalthWaf} from "./vwaf-runtime.js";
import {VynalthWafState,evidenceDigest} from "./vwaf-state.js";
import {SecurityDeviceRisk} from "./site-abuse-policy.js";
import {stateCall} from "./vwaf-runtime.js";
import {handleWafHoneypot} from "./vwaf-honeypot.js";
import {archiveRestriction} from "./vwaf-archive.js";
import {canonicalRestriction,reserveArchive} from "./vwaf-policy.js";
import {restrictionScope} from "./vwaf-runtime.js";
const now=Date.UTC(2026,10,27),id=n=>"00000000-0000-4000-8000-"+String(n).padStart(12,"0");
const req=(path,init={})=>new Request("https://vynalthai.com"+path,init);
const input=(n,over={})=>({id:id(n),kind:"device",mode:"enforce",host:"vynalthai.com",category:null,rules:[["VWAF-101","VWAF-102","VWAF-103"][n%3]],...over});
test("structured content observes signals without scanning prompts or credentials",()=>{
 assert.equal(inspectStructuredContent({prompt:"<script>",password:"union select",email:"user"}).length,0);
 assert.ok(inspectStructuredContent({id:"union select",path:"../file",url:"http://localhost/"}).length>=3);
 assert.ok(inspectStructuredContent(JSON.parse('{"__proto__":{}}')).some(x=>x.id==="VWAF-305"));
});
test("bounded JSON content preserves original body and ignores unknown routes",async()=>{
 const body=JSON.stringify({id:"union select",prompt:"keep private"});
 const r=req("/api/web-search",{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
 assert.ok((await inspectWafContent(r)).some(x=>x.id==="VWAF-301"));assert.equal(await r.text(),body);
 assert.deepEqual(await inspectWafContent(req("/api/chat",{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(body.length)},body})),[]);
});
test("unknown length, encoding, malformed content and oversize content skip",async()=>{
 for(const headers of [{"Content-Type":"application/json"},{"Content-Type":"application/json","Content-Length":"99999"},{"Content-Type":"application/json","Content-Length":"2","Content-Encoding":"gzip"},{"Content-Type":"application/json","Content-Length":"1"}]){
  const r=req("/api/web-search",{method:"POST",headers,body:"{}"});assert.deepEqual(await inspectWafContent(r),[]);assert.equal(await r.text(),"{}");
 }
});
test("device threshold requires five distinct observations and three rule classes",()=>{
 let s;let r;for(let i=1;i<=5;i++){r=actorTransition(s,input(i),now+i);s=r.state}
 assert.equal(r.decision.newRestriction,true);assert.equal(s.blockedUntil,now+5+BAN);assert.equal(s.evidence.requestIds.length,5);
 const retry=actorTransition(s,input(6),now+10);assert.equal(retry.state.blockedUntil,s.blockedUntil);assert.equal(retry.decision.newRestriction,false);
 assert.equal(actorTransition(s,input(7),now+5+BAN).decision.blockedUntil,0);
});
test("observe and network actors never create a restriction",()=>{
 for(const opts of [{mode:"observe"},{kind:"network"}]){
  let s,r;for(let i=1;i<=5;i++){r=actorTransition(s,input(i,opts),now+i);s=r.state}
  assert.equal(r.decision.candidate,true);assert.equal(r.decision.newRestriction,false);assert.equal(s.blockedUntil,0);
 }
});
test("replay, stale and heuristic signals cannot trigger a device restriction",()=>{
 let s,r;for(let i=1;i<=12;i++){r=actorTransition(s,input(1,{rules:["VWAF-201"]}),now+i);s=r.state}
 assert.equal(s.blockedUntil,0);
 for(let i=1;i<=5;i++){r=actorTransition(s,input(1,{rules:["VWAF-101","VWAF-102","VWAF-103"]}),now+i+WINDOW);s=r.state}
 assert.equal(s.blockedUntil,0);
});
test("sliding rate buckets enforce explicit category without minute boundary bursts",()=>{
 let s,r;for(let i=1;i<=4;i++){r=actorTransition(s,input(i,{category:"IMAGE",rules:[]}),now+i);s=r.state}
 assert.equal(r.decision.rateExceeded,true);assert.equal(r.decision.newRate,true);
 assert.equal(actorTransition(s,input(5,{category:"IMAGE",rules:[]}),now+5).decision.newRate,false);
 assert.equal(actorTransition(s,input(6,{category:"IMAGE",rules:[]}),now+60000).decision.rateExceeded,true);
 assert.equal(actorTransition(s,input(7,{category:"IMAGE",rules:[]}),now+60005).decision.rateExceeded,false);
});
test("mode transition does not promote historical observations into a ban",()=>{
 let s;for(let i=1;i<=4;i++)s=actorTransition(s,input(i,{mode:"observe"}),now+i).state;
 assert.equal(actorTransition(s,input(5),now+5).decision.newRestriction,false);
});
test("alert budget reserves at most eight per rolling day and honors retry-after",()=>{
 const s=freshLedger(null,now);s.seq=1;
 for(let i=0;i<8;i++){assert.equal(reserveChannel(s,"ntfy",now+i*900000),true)}
 assert.equal(reserveChannel(s,"ntfy",now+8*900000),false);
 assert.equal(retryDeadline("7200",now),now+7200000);
});
test("event sanitization never forwards arbitrary request data",()=>{
 const e=sanitizeEvent({host:"vynalthai.com",request_id:id(1),mode:"observe",action:"observe",rule_ids:["VWAF-101","evil"],score:100,path:"SECRET",cookie:"SECRET",ip:"SECRET"});
 assert.deepEqual(e.rule_ids,["VWAF-101"]);assert.ok(!JSON.stringify(e).includes("SECRET"));
});
test("alert configuration fails closed and uses fixed destinations",async()=>{
 assert.deepEqual(configuredChannels({}),[]);
 const env={VYNALTH_WAF_ALERTS_ENABLED:"true",VWAF_NTFY_TOPIC:"test_topic_0123456789012345",VWAF_NTFY_TOKEN:"test_token_0123456789012345",VWAF_AXIOM_INGEST_TOKEN:"x".repeat(40),VWAF_TELEGRAM_BOT_TOKEN:"123456:"+"a".repeat(30),VWAF_TELEGRAM_CHAT_ID:"123456"};
 const d={count:5,mode:"observe",rules:["VWAF-101"],sequence:5};
 for(const ch of configuredChannels(env)){
  let called=false;const r=await sendDigest(ch,env,d,async (url,opts)=>{called=true;assert.ok(["ntfy.sh","api.telegram.org","us-east-1.aws.edge.axiom.co"].includes(new URL(url).hostname));assert.equal(opts.redirect,"error");return Response.json(ch==="ntfy"?{event:"message",id:"test"}:ch==="telegram"?{ok:true,result:{message_id:1}}:{ingested:1})},now);
  assert.ok(called);assert.equal(r.state,"sent");
 }
 const r=await sendDigest("ntfy",env,d,async()=>new Response(null,{status:429,headers:{"Retry-After":"7200"}}),now);
 assert.equal(r.state,"rate_limited");assert.equal(r.nextAt,now+7200000);
});
test("unverified device headers and spoofed IP do not create actor keys",async()=>{
 const env={EDGE_DEVICE_ID_SIGNING_SECRET:"x".repeat(40)};
 assert.deepEqual(await verifiedActors(req("/",{headers:{"X-Device-ID":"fake","CF-Connecting-IP":"1.2.3.4"}}),env),[]);
 const r=req("/",{headers:{Cookie:"__Host-vyn_edge_device=fixture","CF-Connecting-IP":"2a06:98c0:3600::103"}});
 Object.defineProperty(r,"cf",{value:{}});
 const a=await verifiedActors(r,env,async()=>({state:"valid",deviceId:id(1)}));
 assert.equal(a.length,1);assert.equal(a[0].kind,"device");assert.equal(a[0].key.length,64);
});
test("rate policy excludes recovery, legal, assets, preflight and unrelated hosts",()=>{
 for(const path of ["/recover","/assets/main.js","/__ops/vwaf/api/status","/api/health"])assert.equal(rateCategory(req(path)),null);
 assert.equal(rateCategory(req("/api/ai/chat",{method:"POST"})),"CHAT");
 assert.equal(rateCategory(req("/api/auth/login",{method:"POST"})),"LOGIN");
});
function fakeStorage(){
 const m=new Map();let alarm=null;const s={get:async k=>structuredClone(m.get(k)),put:async(k,v)=>{m.set(k,structuredClone(v))},delete:async k=>m.delete(k),getAlarm:async()=>alarm,setAlarm:async v=>{alarm=v},transaction:async fn=>fn(s)};return s;
}
const call=(obj,data)=>obj.fetch(new Request("https://vwaf.internal/",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(data)}));
test("DO records integrity checked private evidence and deduplicates events",async()=>{
 const d=new VynalthWafState({storage:fakeStorage()},{});
 const e={host:"vynalthai.com",request_id:id(1),mode:"observe",action:"observe",rule_ids:["VWAF-101"],score:100};
 assert.equal((await (await call(d,{op:"event",event:e})).json()).saved,true);
 assert.equal((await (await call(d,{op:"event",event:e})).json()).saved,false);
 const s=await (await call(d,{op:"status"})).json();assert.equal(s.sequence,1);assert.equal(s.events[0].integrity,true);
 assert.equal(s.events[0].sha256.length,64);
});
test("DO restriction is persisted with evidence digest in the same state",async()=>{
 const storage=fakeStorage(),d=new VynalthWafState({storage},{});
 let r;for(let i=1;i<=5;i++)r=await (await call(d,{op:"actor",...input(i)})).json();
 assert.equal(r.newRestriction,true);assert.ok(r.blockedUntil>Date.now());
 const {sha256,...record}=(await storage.get("actor")).evidence;
 assert.equal(sha256,await evidenceDigest(record));
});
test("former console is static, no credentials, state or origin access",async()=>{
 const events=[],env={VYNALTH_WAF_HONEYPOT_ENABLED:"true",VWAF_CONSOLE_TOKEN:"A".repeat(43)};
 const marker="SYNTHETIC_PRIVATE_TEST";
 for(const path of ["/__ops/vwaf","/__ops/vwaf/api/status","/__ops/vwaf/anything","/__ops/%76waf/api/status"]){
  const r=req(path+"?secret="+marker,{method:"POST",headers:{Authorization:"Bearer "+marker,Cookie:"fake="+marker},body:marker});
  const res=handleWafHoneypot(r,env,new URL(r.url),{},id(1),(e,c,v)=>events.push(v));
  assert.equal(res.status,404);assert.equal(await res.text(),"Resource unavailable.");assert.equal(await r.text(),marker);
  assert.ok(!JSON.stringify(events).includes(marker));assert.ok(!res.headers.has("set-cookie"));
 }
 assert.equal(events.length,4);assert.ok(events.every(e=>e.action==="honeypot"));
 const r=req("/__ops/vwaf");
 assert.equal(handleWafHoneypot(r,{},new URL(r.url),{},id(2)).status,404);
 assert.equal(handleWafHoneypot(req("/robots.txt"),env,new URL(req("/robots.txt").url)),null);
});
test("state and telemetry outage cannot bypass deterministic core protection",async()=>{
 const env={VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:"vynalthai.com",VYNALTH_WAF_STATE_MODE:"enforce"};
 assert.equal((await enforceVynalthWaf(req("/.env"),env,{},id(1))).status,403);
 assert.equal(await enforceVynalthWaf(req("/robots.txt"),env,{},id(2)),null);
});

test("existing deployed namespace isolates legacy device state and VWAF objects",async()=>{
 const old=fakeStorage(),fresh=fakeStorage();
 const legacy=new SecurityDeviceRisk({storage:old},{}),next=new SecurityDeviceRisk({storage:fresh},{});
 const legacyReq=body=>new Request("https://device-risk.internal/",{method:"POST",body:JSON.stringify(body)});
 const original={blockUntil:Date.now()+60000,probes:[]};await old.put("risk",original);
 assert.ok((await(await legacy.fetch(legacyReq({op:"status"}))).json()).blockedUntil>Date.now());
 assert.equal((await call(legacy,{op:"actor",...input(1)})).status,409);
 assert.deepEqual(await old.get("risk"),original);
 assert.equal((await call(next,{op:"actor",...input(1)})).status,200);
 assert.equal((await next.fetch(legacyReq({op:"status"}))).status,409);
 assert.equal(await fresh.get("risk"),undefined);
 await next.alarm();assert.ok(await fresh.get("actor"));
 await legacy.alarm();assert.deepEqual(await old.get("risk"),original);
});
test("runtime uses disjoint object names and does not alter old device bindings",async()=>{
 let named;
 const env={SECURITY_DEVICE_RISK:{idFromName:n=>{named=n;return n},get:()=>({fetch:async(url,options)=>{
  assert.equal(url,"https://vwaf.internal/");assert.ok(options.signal);
  return Response.json({sequence:0})
 }})}};
 assert.deepEqual(await stateCall(env,"ledger-v1",{op:"status"}),{sequence:0});
 assert.equal(named,"vwaf:v1:ledger-v1");
});

test("content inspection scans bounded metadata containers, never auth bodies",async()=>{
 assert.ok(inspectStructuredContent({options:{filters:{id:"union select"}}}).some(x=>x.id==="VWAF-301"));
 assert.equal(inspectStructuredContent({prompt:{id:"union select"},password:{id:"union select"}}).length,0);
 const body=JSON.stringify({id:"union select",password:"fixture"});
 const r=req("/api/auth/signup",{method:"POST",headers:{"content-type":"application/json","content-length":String(body.length)},body});
 assert.deepEqual(await inspectWafContent(r),[]);assert.equal(await r.text(),body);
});
test("restriction checks expand to ordinary authenticated APIs but exclude recovery and services",()=>{
 assert.equal(restrictionScope(req("/api/account/profile")),true);
 for(const path of ["/api/health","/api/security/device/federation/status","/api/webhooks/payment","/__ops/vwaf","/recover","/robots.txt","/en/contact","/assets/main.js"])assert.equal(restrictionScope(req(path)),false);
});
test("new device restrictions retain canonical per-request evidence; R2 only accepts verified records",async()=>{
 let s,r;for(let i=1;i<=5;i++){r=actorTransition(s,input(i),now+i);s=r.state}
 const record=canonicalRestriction(s.evidence,now+10);assert.ok(record);assert.equal(record.observations.length,5);
 const sha256=await evidenceDigest(record);let key,bytes,puts=0;
 const env={VYNALTH_WAF_ARCHIVE_ENABLED:"true",VWAF_EVIDENCE:{put:async(k,b)=>{key=k;bytes=b.slice();puts++},get:async()=>bytes?({size:bytes.length,arrayBuffer:async()=>bytes.buffer}):null}};
 const result=await archiveRestriction(env,{record,sha256},now+10);
 assert.equal(result.state,"archived");assert.ok(key.endsWith(sha256+".json"));assert.equal(puts,1);
 assert.equal((await archiveRestriction(env,{record,sha256:"0".repeat(64)},now+10)).state,"invalid");assert.equal(puts,1);
 const bad={...record,observations:record.observations.map(x=>({...x,id:record.observations[0].id}))};
 assert.equal(canonicalRestriction(bad,now+10),null);
 assert.equal((await archiveRestriction({}, {record,sha256},now+10)).state,"not_configured");
});
test("archive attempts are reserved before writing, capped globally",()=>{
 const s=freshLedger(null,now);s.archive.pending=Array.from({length:5},(_,i)=>({record:{expiresAt:now+RETAIN},sha256:String(i).repeat(64),tries:0}));
 for(let i=0;i<12;i++)assert.ok(reserveArchive(s,now+i*900000));
 assert.equal(reserveArchive(s,now+12*900000),null);
});
test("multi-rule requests cannot manufacture multiple primary categories",()=>{
 let s,r;for(let i=1;i<=6;i++){r=actorTransition(s,input(i,{rules:["VWAF-101","VWAF-102","VWAF-103"]}),now+i);s=r.state}
 assert.equal(r.decision.newRestriction,false);assert.equal(s.blockedUntil,0);
});
test("actor status read checks active signed device restriction without mutation",async()=>{
 const storage=fakeStorage(),d=new VynalthWafState({storage},{});
 for(let i=1;i<=5;i++)await call(d,{op:"actor",...input(i)});
 const prior=await storage.get("actor");
 const r=await(await call(d,{op:"actor-status",host:"vynalthai.com",kind:"device"})).json();
 assert.equal(r.blockedUntil,prior.blockedUntil);assert.deepEqual(await storage.get("actor"),prior);
});
test("ledger keeps core and content events with same correlation ID and queues only verified restriction",async()=>{
 const store=fakeStorage(),d=new VynalthWafState({storage:store},{});
 const e={host:"vynalthai.com",request_id:id(1),mode:"observe",action:"observe",rule_ids:["VWAF-101"],score:100};
 assert.equal((await(await call(d,{op:"event",event:e})).json()).saved,true);
 assert.equal((await(await call(d,{op:"event",event:{...e,rule_ids:["VWAF-301"]}})).json()).saved,true);
 let s,r;const t=Date.now();for(let i=1;i<=5;i++){r=actorTransition(s,input(i),t+i-10);s=r.state}
 const record=s.evidence,sha256=await evidenceDigest(record);
 const restriction={host:"vynalthai.com",request_id:id(5),mode:"enforce",action:"restriction",rule_ids:["VWAF-402"],score:100,actor_kind:"device",evidence_sha256:sha256};
 assert.equal((await(await call(d,{op:"event",event:restriction,evidence:record})).json()).saved,true);
 const out=await(await call(d,{op:"status"})).json();assert.equal(out.sequence,3);assert.equal(out.archive.pending,1);
});

test("R2 verified archive is idempotent and refuses to overwrite a conflicting object",async()=>{
 let s;for(let i=1;i<=5;i++)s=actorTransition(s,input(i),now+i).state;
 const record=canonicalRestriction(s.evidence,now+10),sha256=await evidenceDigest(record);
 let bytes=null,writes=0;
 const env={VYNALTH_WAF_ARCHIVE_ENABLED:"true",VWAF_EVIDENCE:{get:async()=>bytes?{size:bytes.length,arrayBuffer:async()=>bytes.buffer}:null,
 put:async(k,v,o)=>{assert.equal(o.onlyIf.get("If-None-Match"),"*");bytes=v.slice();writes++}}};
 assert.equal((await archiveRestriction(env,{record,sha256},now+10)).state,"archived");
 assert.equal((await archiveRestriction(env,{record,sha256},now+10)).state,"archived");assert.equal(writes,1);
 bytes=new Uint8Array([1,2,3]);
 assert.equal((await archiveRestriction(env,{record,sha256},now+10)).state,"invalid");assert.equal(writes,1);
});
test("restriction outbox survives dropped initial event and retries with bounded attempts",async()=>{
 const store=fakeStorage(),ledgerStore=fakeStorage();
 const ledger=new VynalthWafState({storage:ledgerStore},{});let calls=0;
 const env={VWAF_EVENT_BUDGET:{limit:async()=>({success:true})},SECURITY_DEVICE_RISK:{idFromName:n=>n,get:()=>({fetch:async(url,init)=>{
   calls++;if(calls===1)throw Error("temporary outage");return ledger.fetch(new Request(url,init))
 }})}};
 const actor=new VynalthWafState({storage:store},env);
 for(let i=1;i<=5;i++)await call(actor,{op:"actor",...input(i)});
 let s=await store.get("actor");assert.equal(s.delivery.state,"pending");assert.equal(s.delivery.attempts,0);
 const deadline=s.blockedUntil;
 s.delivery.nextAt=Date.now()-1;await store.put("actor",s);await actor.alarm();
 s=await store.get("actor");assert.equal(s.delivery.attempts,1);assert.equal(s.delivery.state,"pending");
 s.delivery.nextAt=Date.now()-1;await store.put("actor",s);await actor.alarm();
 s=await store.get("actor");assert.equal(s.delivery.attempts,2);assert.equal(s.delivery.state,"accepted");assert.equal(s.blockedUntil,deadline);
 const status=await(await call(ledger,{op:"status"})).json();assert.equal(status.archive.pending,1);
});
test("duplicate restriction delivery can enqueue after archive backpressure without double counting",async()=>{
 const store=fakeStorage(),d=new VynalthWafState({storage:store},{});
 let s;const t=Date.now();for(let i=1;i<=5;i++)s=actorTransition(s,input(i),t+i-10).state;
 const record=s.evidence,sha256=await evidenceDigest(record);
 const e={host:"vynalthai.com",request_id:id(5),mode:"enforce",action:"restriction",rule_ids:["VWAF-402"],score:100,actor_kind:"device",evidence_sha256:sha256};
 const q=freshLedger(null,t);q.archive.pending=Array.from({length:8},(_,i)=>({record:{expiresAt:t+RETAIN},sha256:String(i).repeat(64),tries:0}));
 await store.put("ledger",q);
 const first=await(await call(d,{op:"event",event:e,evidence:record})).json();assert.equal(first.saved,true);assert.equal(first.archiveAccepted,false);
 const old=await store.get("ledger");old.archive.pending=[];await store.put("ledger",old);
 const second=await(await call(d,{op:"event",event:e,evidence:record})).json();assert.equal(second.saved,false);assert.equal(second.archiveAccepted,true);
 const status=await(await call(d,{op:"status"})).json();assert.equal(status.sequence,1);assert.equal(status.archive.pending,1);
});

test("internal retries do not consume extra rate slots or extend bans",async()=>{
 const store=fakeStorage(),d=new VynalthWafState({storage:store},{});
 for(let i=0;i<5;i++){
  const r=await(await call(d,{op:"actor",...input(1,{category:"IMAGE",rules:[]})})).json();
  assert.equal(r.rateExceeded,false);if(i>0)assert.equal(r.replayed,true);
 }
 const s=await store.get("actor");assert.equal(s.buckets.IMAGE.hits.length,1);
 assert.equal((await call(d,{op:"actor",...input(1,{category:"SEARCH",rules:[]})})).status,409);
 for(let i=2;i<=3;i++)await call(d,{op:"actor",...input(i,{category:"IMAGE",rules:[]})});
 const r=await(await call(d,{op:"actor",...input(4,{category:"IMAGE",rules:[]})})).json();assert.equal(r.rateExceeded,true);
 assert.equal((await(await call(d,{op:"actor",...input(4,{category:"IMAGE",rules:[]})})).json()).replayed,true);
});
test("restriction evidence and scheduled work commit in the same storage transaction",async()=>{
 const store=fakeStorage();let inTransaction=false;const original=store.transaction,alarm=store.setAlarm;
 store.transaction=async fn=>original(async txn=>{inTransaction=true;try{return await fn(txn)}finally{inTransaction=false}});
 store.setAlarm=async at=>{assert.equal(inTransaction,true);return alarm(at)};
 const d=new VynalthWafState({storage:store},{});
 for(let i=1;i<=5;i++)await call(d,{op:"actor",...input(i)});
 const s=await store.get("actor");assert.ok(s.evidence.sha256);assert.ok((await store.getAlarm())<=s.delivery.nextAt+1000);
});
test("single-category bursts are observed once and never become automatic bans",()=>{
 let s,r,bursts=0;
 for(let i=1;i<=20;i++){r=actorTransition(s,input(i,{rules:["VWAF-101"]}),now+i);s=r.state;if(r.decision.burst)bursts++}
 assert.equal(bursts,1);assert.equal(s.blockedUntil,0);
});
test("exhausted R2 attempt is never restarted after interrupted final write",()=>{
 const s=freshLedger(null,now);
 s.archive.pending=[{record:{expiresAt:now+RETAIN},sha256:"a".repeat(64),tries:3}];
 assert.equal(reserveArchive(s,now),null);assert.equal(s.archive.pending.length,0);
 assert.equal(s.archive.completed[0].state,"unconfirmed");
});
test("critical evidence dedup survives eviction from recent events",async()=>{
 const store=fakeStorage(),d=new VynalthWafState({storage:store},{});
 let s;const t=Date.now();for(let i=1;i<=5;i++)s=actorTransition(s,input(i),t+i-10).state;
 const record=s.evidence,sha256=await evidenceDigest(record);
 const event={host:"vynalthai.com",request_id:id(5),mode:"enforce",action:"restriction",rule_ids:["VWAF-402"],score:100,actor_kind:"device",evidence_sha256:sha256};
 assert.equal((await(await call(d,{op:"event",event,evidence:record})).json()).saved,true);
 const ledger=await store.get("ledger");ledger.entries=[];await store.put("ledger",ledger);
 const r=await(await call(d,{op:"event",event,evidence:record})).json();assert.equal(r.saved,false);assert.equal(r.archiveAccepted,true);
 assert.equal((await store.get("ledger")).seq,1);
 assert.equal((await call(d,{op:"event",event,evidence:{...record,at:0}})).status,400);
});
