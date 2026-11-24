import test from "node:test";
import assert from "node:assert/strict";
import { handleTidbAcceptance } from "./tidb-acceptance.js";
import {
  runTidbAcceptanceProbe, runTidbAcceptanceAuthCheck, tidbAcceptanceConnectionStatus,
} from "./tidb-honeypot.js";

const HOST="gateway01.ap-southeast-1.prod.aws.tidbcloud.com";
const writer="mysql://instance.honey_writer:fake_password@"+HOST+"/vynalth_honeypot";
const reader="mysql://instance.honey_reader:read_password@"+HOST+"/vynalth_honeypot";
const BASE="https://vynalthai.com/__ops/tidb-acceptance";
const CSRF="session-csrf-test";
const MARKER="/__ops/tidb-acceptance/11111111-2222-4333-8444-555555555555";
const auth=async()=>({csrf:CSRF,expiry:Math.floor(Date.now()/1000)+300});
const makeEnv=()=>{
 const store=new Map();
 return {TIDB_HONEYPOT_DATABASE_URL:writer,
  SCHOOL_IP_KV:{
   async get(k){return store.get(k)||null;},
   async put(k,v,options){if(options)assert.ok(options.expirationTtl>=60);store.set(k,v);},
   async delete(k){store.delete(k);}
  }
 };
};
function post(headers={},body={confirm:"RUN_SINGLE_PROBE"}){
 return new Request(BASE+"/api/run",{method:"POST",headers:{
  "Origin":"https://vynalthai.com","Sec-Fetch-Site":"same-origin",
  "Content-Type":"application/json","X-CSRF-Token":CSRF,...headers},
  body:JSON.stringify(body)});
}
test("admin-only page is safely served, never publicly exposes status or write API",async()=>{
 const env=makeEnv();
 const page=await handleTidbAcceptance(new Request(BASE),env,new URL(BASE));
 assert.equal(page.status,200);
 assert.match(await page.text(),/TiDB 真实入库验收/);
 assert.match(page.headers.get("Content-Security-Policy"),/frame-ancestors 'none'/);
 assert.equal(page.headers.get("Cache-Control").includes("no-store"),true);
 const script=await handleTidbAcceptance(new Request(BASE+"/app.js"),env,new URL(BASE+"/app.js"));
 assert.equal(script.status,200);
 assert.match(await script.text(),/RUN_SINGLE_PROBE/);
 const unauth=await handleTidbAcceptance(new Request(BASE+"/api/status"),
  env,new URL(BASE+"/api/status"),{authenticate:async()=>null});
 assert.equal(unauth.status,401);
 assert.equal((await unauth.text()).includes("fake_password"),false);
 const forbidden=await handleTidbAcceptance(new Request(BASE.replace("vynalthai.com","evil.invalid")),
  env,new URL(BASE.replace("vynalthai.com","evil.invalid")));
 assert.equal(forbidden,null);
});
test("authorized status reports configuration only, not credentials",async()=>{
 const env=makeEnv();
 let res=await handleTidbAcceptance(new Request(BASE+"/api/status"),env,
  new URL(BASE+"/api/status"),{authenticate:auth});
 let body=await res.json();
 assert.equal(body.writerConfigured,true);
 assert.equal(body.readerConfigured,false);
 assert.equal(body.csrf,CSRF);
 assert.equal(JSON.stringify(body).includes("fake_password"),false);
 env.TIDB_HONEYPOT_READONLY_DATABASE_URL=reader;
 res=await handleTidbAcceptance(new Request(BASE+"/api/status"),env,
  new URL(BASE+"/api/status"),{authenticate:auth});
 assert.equal((await res.json()).readerConfigured,true);
});
test("CSRF, origin and explicit confirmation are required before any write",async()=>{
 let attempts=0;const opts={authenticate:auth,runProbe:async()=>{attempts++;return {state:"verified"}}};
 for(const [headers,body] of [
  [{"Origin":"https://attacker.invalid"}, {confirm:"RUN_SINGLE_PROBE"}],
  [{"X-CSRF-Token":"wrong"}, {confirm:"RUN_SINGLE_PROBE"}],
  [{"Sec-Fetch-Site":"cross-site"}, {confirm:"RUN_SINGLE_PROBE"}],
  [{}, {confirm:"YES"}],
  [{}, {confirm:"RUN_SINGLE_PROBE",sql:"SELECT * FROM secrets"}],
 ]){
  const req=post(headers,body);
  const res=await handleTidbAcceptance(req,makeEnv(),new URL(req.url),opts);
  assert.ok([400,403].includes(res.status));
 }
 assert.equal(attempts,0);
});
test("one accepted operator request performs at most one insert attempt with privacy-safe output",async()=>{
 const env=makeEnv();let count=0;const opts={authenticate:auth,
  runProbe:async(_env,marker)=>{count++;assert.match(marker,
   /^\/__ops\/tidb-acceptance\/[a-f0-9-]{36}$/);return {state:"failed",reason:"auth",stage:"execute",error:"SECRET_LEAK"}}};
 const first=post();
 const result=await handleTidbAcceptance(first,env,new URL(first.url),opts);
 assert.equal(result.status,200);
 const body=await result.json();
 assert.equal(body.state,"failed");assert.equal(body.reason,"auth");assert.equal(body.stage,"execute");
 assert.equal(JSON.stringify(body).includes("SECRET_LEAK"),false);
 const second=post();
 const again=await handleTidbAcceptance(second,env,new URL(second.url),opts);
 assert.equal(again.status,429);assert.equal(count,1);
});
test("actual TiDB probe uses unique acceptance event, the INSERT-only principal cannot SELECT",async()=>{
 const env=makeEnv();const executions=[];
 const result=await runTidbAcceptanceProbe(env,MARKER,config=>({
  async execute(sql,params){executions.push({username:config.username,sql,params});return [];}
 }));
 assert.deepEqual(result,{state:"insert_acknowledged",readback:"manual_required"});
 assert.equal(executions.length,1);
 assert.match(executions[0].sql,/INSERT INTO vynalth_honeypot\.honeypot_events/);
 assert.deepEqual(executions[0].params,[
  "acceptance_probe","cloudflare_worker","HTTP",null,null,MARKER,"logged"]);
 assert.equal(executions[0].username,"instance.honey_writer");
 assert.equal(JSON.stringify(executions).includes("fake_password"),false);
});
test("optional distinct read-only principal must match the inserted marker to claim PASS",async()=>{
 const env={...makeEnv(),TIDB_HONEYPOT_READONLY_DATABASE_URL:reader};
 let writerCalls=0,readerCalls=0;
 const result=await runTidbAcceptanceProbe(env,MARKER,config=>{
  if(config.username==="instance.honey_writer")return {async execute(){writerCalls++;return [];}};
  assert.equal(config.username,"instance.honey_reader");
  return {async execute(sql,params){
   readerCalls++;assert.match(sql,/SELECT id FROM/);
   assert.deepEqual(params,["cloudflare_worker","acceptance_probe",MARKER]);
   return [{id:1}];
  }};
 });
 assert.deepEqual(result,{state:"verified",readback:"confirmed"});
 assert.equal(writerCalls,1);assert.equal(readerCalls,1);
});
test("readback miss or errors cannot falsely claim PASS; invalid marker fails closed",async()=>{
 const env={...makeEnv(),TIDB_HONEYPOT_READONLY_DATABASE_URL:reader};
 let runs=0;
 const driver=config=>({async execute(){runs++;
  if(config.username==="instance.honey_reader")return [];
  return {};
 }});
 assert.deepEqual(await runTidbAcceptanceProbe(env,MARKER,driver),
  {state:"insert_acknowledged",readback:"not_found"});
 assert.equal(runs,2);
 assert.deepEqual(await runTidbAcceptanceProbe(env,"/evil/path",driver),
  {state:"invalid_marker"});
 assert.equal(runs,2);
 const failed=await runTidbAcceptanceProbe(env,MARKER,config=>({
  async execute(){if(config.username==="instance.honey_reader")throw Error("fetch failed SECRET");return [];}
 }));
 assert.deepEqual(failed,{state:"insert_acknowledged",readback:"failed",readbackReason:"transport"});
});
test("TiDB rejection returns only fixed-label stage/reason and not raw credentials",async()=>{
 const env=makeEnv();
 const result=await runTidbAcceptanceProbe(env,MARKER,()=>({
  async execute(){throw Error("access denied; mysql://user:SUPER_SECRET@private.internal");}
 }));
 assert.deepEqual(result,{state:"failed",reason:"auth",stage:"execute"});
 assert.equal(JSON.stringify(result).includes("SUPER_SECRET"),false);
 assert.deepEqual(tidbAcceptanceConnectionStatus({}),{
  writerConfigured:false,readerConfigured:false});
});

test("temporary acceptance page can be closed by authorized operator and returns HTTP 410",async()=>{
 const env=makeEnv();
 const endpoint=BASE+"/api/close";
 const request=new Request(endpoint,{method:"POST",headers:{
   "Origin":"https://vynalthai.com","Sec-Fetch-Site":"same-origin",
   "Content-Type":"application/json","X-CSRF-Token":CSRF
 },body:JSON.stringify({confirm:"CLOSE_TEMP_PAGE"})});
 const response=await handleTidbAcceptance(request,env,new URL(endpoint),{authenticate:auth});
 assert.equal(response.status,200);
 assert.equal((await response.json()).state,"closed");
 const again=await handleTidbAcceptance(new Request(BASE),env,new URL(BASE));
 assert.equal(again.status,410);
});


test("safe read-only auth probe validates actual SELECT 1 response, never emits SQL data", async()=>{
 const env=makeEnv();let reads=0;
 const good=await runTidbAcceptanceAuthCheck(env,(_config)=>({
   async execute(sql){reads++;assert.equal(sql,"SELECT 1 AS vynalth_connection_ok");
     return [{vynalth_connection_ok:1}];}
 }));
 assert.deepEqual(good,{state:"authenticated"});assert.equal(reads,1);
 const unexpected=await runTidbAcceptanceAuthCheck(env,()=>({async execute(){return []}}));
 assert.deepEqual(unexpected,{state:"unexpected_response"});
 const bad=await runTidbAcceptanceAuthCheck(env,()=>({async execute(){
   const e=Error("Access denied; mysql://secret:VERY_SENSITIVE@private.example");
   e.status=401;e.details={code:"1045",message:"SENSITIVE"};throw e;
 }}));
 assert.deepEqual(bad,{state:"failed",reason:"auth",stage:"execute",httpStatus:401,dbErrorCode:"1045"});
 assert.equal(JSON.stringify(bad).includes("SENSITIVE"),false);
});

test("private read-only auth endpoint requires CSRF, explicit intent and throttles",async()=>{
 const env=makeEnv(),url=new URL(BASE+"/api/check-auth");
 let checks=0;
 const opts={authenticate:auth,checkAuth:async()=>{checks++;return {state:"authenticated"};}};
 const bad=new Request(url,{method:"POST",headers:{"Origin":"https://vynalthai.com",
  "Content-Type":"application/json"},body:JSON.stringify({confirm:"CHECK_TIDB_AUTH"})});
 const denied=await handleTidbAcceptance(bad,env,url,opts);
 assert.equal(denied.status,403);assert.equal(checks,0);
 const wrong=new Request(url,{method:"POST",headers:{"Origin":"https://vynalthai.com",
  "X-CSRF-Token":CSRF,"Content-Type":"application/json"},body:JSON.stringify({confirm:"RUN_SINGLE_PROBE"})});
 const rejected=await handleTidbAcceptance(wrong,env,url,opts);
 assert.equal(rejected.status,400);assert.equal(checks,0);
 const make=()=>new Request(url,{method:"POST",headers:{"Origin":"https://vynalthai.com",
  "X-CSRF-Token":CSRF,"Content-Type":"application/json"},body:JSON.stringify({confirm:"CHECK_TIDB_AUTH"})});
 const first=await handleTidbAcceptance(make(),env,url,opts);
 assert.equal(first.status,200);assert.deepEqual(await first.json(),{state:"authenticated"});
 const second=await handleTidbAcceptance(make(),env,url,opts);
 assert.equal(second.status,429);assert.equal(checks,1);
});

test("auth diagnostics output drops unknown codes/statuses and secret error fields",async()=>{
 const env=makeEnv(),url=new URL(BASE+"/api/check-auth");
 const req=new Request(url,{method:"POST",headers:{"Origin":"https://vynalthai.com",
  "X-CSRF-Token":CSRF,"Content-Type":"application/json"},body:JSON.stringify({confirm:"CHECK_TIDB_AUTH"})});
 const res=await handleTidbAcceptance(req,env,url,{authenticate:auth,
  checkAuth:async()=>({state:"failed",reason:"auth",stage:"execute",
    httpStatus:418,dbErrorCode:"TOPSECRET",password:"SENSITIVE"})});
 assert.equal(res.status,200);assert.deepEqual(await res.json(),{state:"failed",reason:"auth",stage:"execute"});
});
