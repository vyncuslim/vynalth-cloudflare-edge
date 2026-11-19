import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {
  handleSensorIngestV2,SENSOR_INTAKE_V2_PATH,SENSOR_V2_SIGNING_DOMAIN,
} from "./sensor-ingest-v2.js";
import {
  claimEvent,settleEvent,initializeLedger,SENSOR_LEDGER_CAP,
} from "./sensor-replay-ledger-core.js";

const KEY="K".repeat(48);
const DB="mysql://ci.honeypot_writer:test-only@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot";
const NOW=Date.parse("2026-11-19T08:00:00Z");
const REF="a".repeat(64);
const good={event_type:"suspicious_probe",source:"cowrie",
  protocol:"SSH",source_ip_hash:null,country_code:null,
  request_path:"/ssh/login_attempt",action_taken:"observed"};

class FakeSql {
  constructor(){this.rows=new Map();}
  exec(query,...p){
    if(query.startsWith("CREATE TABLE"))return {rowsWritten:0};
    if(query.startsWith("SELECT event_ref")){
      return {toArray:()=>this.rows.has(p[0])?[{event_ref:p[0]}]:[]};
    }
    if(query.startsWith("SELECT COUNT")){
      return {one:()=>({total:this.rows.size})};
    }
    if(query.startsWith("INSERT OR IGNORE")){
      if(this.rows.has(p[0]))return {rowsWritten:0};
      this.rows.set(p[0],{claimed_ms:p[1],state:"reserved"});
      return {rowsWritten:1};
    }
    if(query.startsWith("UPDATE")){
      const [status,ref]=p;
      const row=this.rows.get(ref);
      if(!row||row.state!=="reserved")return {rowsWritten:0};
      row.state=status;
      return {rowsWritten:1};
    }
    throw Error("Unexpected fake ledger SQL");
  }
}
function ledger(){
  const sql=new FakeSql();
  initializeLedger(sql);
  return {
    sql,
    claim:async(ref,now)=>({
      status:{"claimed":201,"duplicate":409,"capacity":503,
              "invalid":400}[claimEvent(sql,ref,now)],
    }),
    settle:async(ref,status)=>({
      status:settleEvent(sql,ref,status)?200:409,
    }),
  };
}
async function sign(raw,ref=REF,ts=String(NOW/1000),nonce="11111111-2222-4333-8444-555555555555",key=KEY){
  const cryptoKey=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(key),{name:"HMAC",hash:"SHA-256"},
    false,["sign"]);
  const message=[SENSOR_V2_SIGNING_DOMAIN,ts,nonce,ref,raw].join("\n");
  const bytes=new Uint8Array(await crypto.subtle.sign(
    "HMAC",cryptoKey,new TextEncoder().encode(message)));
  return [...bytes].map(x=>x.toString(16).padStart(2,"0")).join("");
}
async function request(obj=good,ref=REF){
  const raw=JSON.stringify(obj),ts=String(NOW/1000);
  return new Request("https://vynalthai.com"+SENSOR_INTAKE_V2_PATH,{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      "X-Vynalth-Sensor-Time":ts,
      "X-Vynalth-Sensor-Nonce":"11111111-2222-4333-8444-555555555555",
      "X-Vynalth-Sensor-Event-Ref":ref,
      "X-Vynalth-Sensor-Signature":await sign(raw,ref),
    },body:raw,
  });
}
const env={
  HONEY_SENSOR_V2_ENABLED:"true",
  HONEY_SENSOR_V2_KEY:KEY,
  HONEY_SENSOR_V2_SAMPLE_RATE:"1",
  TIDB_HONEYPOT_DATABASE_URL:DB,
};

test("SQL ledger INSERT OR IGNORE prevents duplicate ref and state changes",()=>{
  const sql=new FakeSql();
  initializeLedger(sql);
  assert.equal(claimEvent(sql,REF,NOW),"claimed");
  assert.equal(claimEvent(sql,REF,NOW),"duplicate");
  assert.equal(settleEvent(sql,REF,"insert_acknowledged"),true);
  assert.equal(settleEvent(sql,REF,"sampled_out"),false);
  assert.equal(sql.rows.get(REF).state,"insert_acknowledged");
  assert.equal(claimEvent(sql,"B".repeat(64),NOW),"invalid");
  assert.equal(claimEvent(sql,"x".repeat(64),NOW),"invalid");
});
test("ledger capacity fails closed without evicting previous claims",()=>{
  const sql=new FakeSql();
  for(let i=0;i<SENSOR_LEDGER_CAP;i++)
    sql.rows.set(i.toString(16).padStart(64,"0"),{state:"reserved"});
  assert.equal(claimEvent(sql,"f".repeat(64),NOW),"capacity");
  assert.equal(claimEvent(sql,"0".repeat(64),NOW),"duplicate");
});
test("disabled, missing-key, and missing replay storage refuse request",async()=>{
  assert.equal((await handleSensorIngestV2(await request(),{})).status,404);
  assert.equal((await handleSensorIngestV2(await request(),{
    ...env,HONEY_SENSOR_V2_KEY:""
  },{now:NOW})).status,503);
  assert.equal((await handleSensorIngestV2(await request(),env,{
    now:NOW,connectImpl:()=>{throw Error("never connect");},
  })).status,503);
});
test("signed ref claimed before TiDB, duplicate never reaches INSERT",async()=>{
  const seen=ledger();let writes=0;
  const opts={now:NOW,ledgerClaim:seen.claim,ledgerSettle:seen.settle,
    connectImpl:()=>({execute:async(sql,args)=>{
      assert.match(sql,/^INSERT INTO vynalth_honeypot\.honeypot_events /);
      assert.deepEqual(args,["suspicious_probe","cowrie","SSH",null,null,
                             "/ssh/login_attempt","observed"]);
      writes++;
    }}),
  };
  const first=await handleSensorIngestV2(await request(),env,opts);
  assert.equal(first.status,201);
  assert.equal((await first.json()).outcome,"insert_acknowledged");
  assert.equal(writes,1);
  const second=await handleSensorIngestV2(await request(),env,opts);
  assert.equal(second.status,409);
  assert.equal(writes,1);
});
test("new nonce with unchanged eventRef remains duplicate",async()=>{
  const seen=ledger();
  seen.claim(REF,NOW);
  const req=await request();
  const raw=JSON.stringify(good);
  const ts=String(NOW/1000);
  const nonce="22222222-2222-4333-8444-555555555555";
  req.headers.set("x-vynalth-sensor-nonce",nonce);
  req.headers.set("x-vynalth-sensor-signature",await sign(raw,REF,ts,nonce));
  const outcome=await handleSensorIngestV2(req,env,{
    now:NOW,ledgerClaim:seen.claim,ledgerSettle:seen.settle,
    connectImpl:()=>{throw Error("replay should not access database");},
  });
  assert.equal(outcome.status,409);
});
test("signature binds event reference and exact JSON; invalid never claims",async()=>{
  let calls=0;
  const noDb={now:NOW,ledgerClaim:()=>{
    calls++;return {status:201};
  },connectImpl:()=>{throw Error("must not execute");}};
  const badRef=await request();
  badRef.headers.set("x-vynalth-sensor-event-ref","b".repeat(64));
  assert.equal((await handleSensorIngestV2(badRef,env,noDb)).status,401);
  const forged=await request();
  forged.headers.set("x-vynalth-sensor-signature","0".repeat(64));
  assert.equal((await handleSensorIngestV2(forged,env,noDb)).status,401);
  const missing=await request({...good,password:"DO_NOT_CAPTURE"});
  assert.equal((await handleSensorIngestV2(missing,env,noDb)).status,422);
  const old=await request();
  assert.equal((await handleSensorIngestV2(old,env,{
    ...noDb,now:NOW+200000,
  })).status,401);
  assert.equal(calls,0);
});
test("random sampling occurs AFTER claim, and keeps its eventRef",async()=>{
  const seen=ledger();
  const opts={now:NOW,ledgerClaim:seen.claim,ledgerSettle:seen.settle,
    random:()=>0.95,connectImpl:()=>{throw Error("must not contact TiDB");}};
  const answer=await handleSensorIngestV2(await request(),{
    ...env,HONEY_SENSOR_V2_SAMPLE_RATE:"0.1",
  },opts);
  assert.equal(answer.status,202);
  assert.equal(seen.sql.rows.get(REF).state,"sampled_out");
  const again=await handleSensorIngestV2(await request(),env,opts);
  assert.equal(again.status,409);
});
test("database errors hold event; never auto-release the claim",async()=>{
  const seen=ledger();
  const opts={now:NOW,ledgerClaim:seen.claim,ledgerSettle:seen.settle,
    connectImpl:()=>{throw Error("private DB URL!");}};
  const answer=await handleSensorIngestV2(await request(),env,opts);
  assert.equal(answer.status,503);
  assert.equal((await answer.json()).outcome,"database_unavailable");
  assert.equal(seen.sql.rows.get(REF).state,"database_uncertain");
  assert.equal((await handleSensorIngestV2(await request(),env,opts)).status,409);
});
test("failed ledger settle after successful TiDB INSERT returns uncertain",async()=>{
  const seen=ledger();
  const opts={now:NOW,ledgerClaim:seen.claim,
    ledgerSettle:async()=>({status:503}),
    connectImpl:()=>({execute:async()=>({})})};
  const answer=await handleSensorIngestV2(await request(),env,opts);
  assert.equal(answer.status,503);
  assert.equal((await answer.json()).outcome,"outcome_uncertain");
  assert.equal(seen.sql.rows.get(REF).state,"reserved");
});
test("Python-signed V2 event crosses Worker auth to mock TiDB",{
  skip:!process.env.VYNALTH_OUTBOX_CI_FIXTURE,
},async()=>{
  const f=JSON.parse(fs.readFileSync(process.env.VYNALTH_OUTBOX_CI_FIXTURE,"utf8"));
  const req=new Request("https://vynalthai.com"+SENSOR_INTAKE_V2_PATH,{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      "X-Vynalth-Sensor-Time":f.timestamp,
      "X-Vynalth-Sensor-Nonce":f.nonce,
      "X-Vynalth-Sensor-Event-Ref":f.event_ref,
      "X-Vynalth-Sensor-Signature":f.v2_signature,
    },body:f.body,
  });
  const seen=ledger();let inserts=0;
  const r=await handleSensorIngestV2(req,{
    ...env,HONEY_SENSOR_V2_KEY:f.key,
  },{
    now:Number(f.timestamp)*1000,ledgerClaim:seen.claim,
    ledgerSettle:seen.settle,connectImpl:()=>({execute:async()=>{
      inserts++;
    }}),
  });
  assert.equal(r.status,201);
  assert.equal(inserts,1);
  assert.equal(seen.sql.rows.get(f.event_ref).state,"insert_acknowledged");
});
