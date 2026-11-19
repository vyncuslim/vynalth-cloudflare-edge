import test from "node:test";
import assert from "node:assert/strict";
import { SENSOR_INTAKE_PATH, validateSensorSummary, handleSensorIngest } from "./sensor-ingest.js";

const DB = "mysql://abc.honeypot_writer:dummy_secret@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot";
const KEY = "k".repeat(48);
const NOW = Date.parse("2026-11-19T08:00:00.000Z");
const goodEvent = Object.freeze({
 event_type:"suspicious_probe", source:"cowrie",protocol:"SSH",
 source_ip_hash:null,country_code:null,request_path:"/ssh/login_attempt",action_taken:"observed"
});
const env = Object.freeze({
 HONEY_SENSOR_INGEST_ENABLED:"true",HONEY_SENSOR_INGEST_KEY:KEY,
 TIDB_HONEYPOT_DATABASE_URL:DB,HONEY_SENSOR_SAMPLE_RATE:"1"
});
async function sign(body,ts,nonce) {
 const k=await crypto.subtle.importKey("raw",new TextEncoder().encode(KEY),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bits=new Uint8Array(await crypto.subtle.sign("HMAC",k,
  new TextEncoder().encode(ts+"\n"+nonce+"\n"+body)));
 return [...bits].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function fixture(payload=goodEvent, ts=String(NOW/1000)) {
 const nonce="11111111-2222-4333-8444-555555555555";
 const raw=JSON.stringify(payload);
 return new Request("https://vynalthai.com"+SENSOR_INTAKE_PATH,{
  method:"POST",headers:{"Content-Type":"application/json",
   "x-vynalth-sensor-time":ts,"x-vynalth-sensor-nonce":nonce,
   "x-vynalth-sensor-signature":await sign(raw,ts,nonce)},body:raw
 });
}
test("disabled and no-secret endpoints refuse input without DB calls",async()=>{
 assert.equal((await handleSensorIngest(await fixture(),{})).status,404);
 assert.equal((await handleSensorIngest(await fixture(),{
  HONEY_SENSOR_INGEST_ENABLED:"true",TIDB_HONEYPOT_DATABASE_URL:DB
 })).status,503);
 const root={...env,TIDB_HONEYPOT_DATABASE_URL:DB.replace(".honeypot_writer",".root")};
 assert.equal((await handleSensorIngest(await fixture(),root)).status,503);
});
test("HMAC authenticated event inserts only seven allowlisted values",async()=>{
 const calls=[];
 const answer=await handleSensorIngest(await fixture(),env,{now:NOW,connectImpl:({url})=>{
  assert.equal(url,DB);
  return {execute(sql,params){calls.push({sql,params});return Promise.resolve({})}};
 }});
 assert.equal(answer.status,201);
 assert.equal(calls.length,1);
 assert.deepEqual(calls[0].params,[
  "suspicious_probe","cowrie","SSH",null,null,"/ssh/login_attempt","observed"
 ]);
 assert.equal((calls[0].sql.match(/\?/g)||[]).length,7);
});
test("faked credentials or unsanctioned fields never enter TiDB",async()=>{
 const malicious={...goodEvent,password:"NEVER_SEND_OR_LOG",
   input:"bash -c attacker command",src_ip:"198.51.100.10"};
 const response=await handleSensorIngest(await fixture(malicious),env,{now:NOW,
  connectImpl:()=>{throw Error("should not be invoked");}});
 assert.equal(response.status,422);
 assert.equal(validateSensorSummary(malicious),null);
 const bad={...goodEvent,request_path:"/ssh/../../admin.php"};
 assert.equal(validateSensorSummary(bad),null);
 assert.equal(validateSensorSummary({...goodEvent,protocol:"MYSQL"}),null);
});
test("unsigned, invalid, replayed-old or oversized events cannot connect",async()=>{
 const bad=await fixture();
 bad.headers.set("x-vynalth-sensor-signature","0".repeat(64));
 assert.equal((await handleSensorIngest(bad,env,{now:NOW})).status,401);
 const old=await fixture(goodEvent,String((NOW/1000)-200));
 assert.equal((await handleSensorIngest(old,env,{now:NOW})).status,401);
 const huge=await fixture({...goodEvent,input:"x".repeat(5000)});
 assert.equal((await handleSensorIngest(huge,env,{now:NOW})).status,413);
});
test("sampled-out response never claims database storage",async()=>{
 const response=await handleSensorIngest(await fixture(),
  {...env,HONEY_SENSOR_SAMPLE_RATE:"0.1"},{now:NOW,random:()=>0.9,
  connectImpl:()=>{throw Error("must not call db");}});
 assert.equal(response.status,202);
 assert.deepEqual(await response.json(),{status:"sampled_out"});
});
test("database errors return generic availability only",async()=>{
 const oldWarn=console.warn;const logs=[];
 console.warn=(...xs)=>logs.push(xs.join(" "));
 try{
  const result=await handleSensorIngest(await fixture(),env,{now:NOW,
   connectImpl:()=>{throw Error("real connection string NEVER_PRINT");}});
  assert.equal(result.status,503);
  assert.equal(JSON.stringify(logs).includes("NEVER_PRINT"),false);
 }finally{console.warn=oldWarn;}
});
