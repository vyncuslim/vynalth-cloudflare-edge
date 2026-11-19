import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import {handleSensorIngest,SENSOR_INTAKE_PATH} from "./sensor-ingest.js";

const path=process.env.VYNALTH_OUTBOX_CI_FIXTURE;

test("signed Python Cowrie outbox -> JS Worker -> MOCK TiDB INSERT",{
  skip:!path,
},async()=>{
  const fixture=JSON.parse(fs.readFileSync(path,"utf8"));
  const data=JSON.parse(fixture.body);
  assert.equal(data.source,"cowrie");
  assert.equal(data.protocol,"SSH");
  assert.equal(data.request_path,"/ssh/login_attempt");
  assert.equal(data.country_code,null);
  assert.equal(data.source_ip_hash,null);
  const endpoint="https://vynalthai.com"+SENSOR_INTAKE_PATH;
  const req=new Request(endpoint,{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      "X-Vynalth-Sensor-Time":fixture.timestamp,
      "X-Vynalth-Sensor-Nonce":fixture.nonce,
      "X-Vynalth-Sensor-Signature":fixture.signature,
    },
    body:fixture.body,
  });
  const env={
    HONEY_SENSOR_INGEST_ENABLED:"true",
    HONEY_SENSOR_INGEST_KEY:fixture.key,
    HONEY_SENSOR_SAMPLE_RATE:"1",
    TIDB_HONEYPOT_DATABASE_URL:"mysql://ci.honeypot_writer:test-key-only@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot",
  };
  let calls=0;
  const conn=()=>({
    async execute(sql,values){
      assert.match(sql,/^INSERT INTO vynalth_honeypot\.honeypot_events /);
      assert.deepEqual(values,[
        "suspicious_probe","cowrie","SSH",null,null,
        "/ssh/login_attempt","observed",
      ]);
      calls++;
      return {};
    },
  });
  const now=Number(fixture.timestamp)*1000;
  const result=await handleSensorIngest(req,env,{now,connectImpl:conn});
  assert.equal(result.status,201);
  assert.deepEqual(await result.json(),{status:"inserted"});
  assert.equal(calls,1);

  const bodyWithLeak=fixture.body.replace("login_attempt","password_leak");
  const forged=new Request(endpoint,{
    method:"POST",
    headers:{
      "X-Vynalth-Sensor-Time":fixture.timestamp,
      "X-Vynalth-Sensor-Nonce":fixture.nonce,
      "X-Vynalth-Sensor-Signature":fixture.signature,
    },
    body:bodyWithLeak,
  });
  assert.equal((await handleSensorIngest(forged,env,{
    now,connectImpl:()=>{throw Error("must not write forged events")},
  })).status,401);
  assert.equal(calls,1);

  const sampled=new Request(endpoint,{
    method:"POST",
    headers:{
      "X-Vynalth-Sensor-Time":fixture.timestamp,
      "X-Vynalth-Sensor-Nonce":fixture.nonce,
      "X-Vynalth-Sensor-Signature":fixture.signature,
    },
    body:fixture.body,
  });
  const response=await handleSensorIngest(sampled,{
    ...env,HONEY_SENSOR_SAMPLE_RATE:"0.1",
  },{
    now,random:()=>0.99,
    connectImpl:()=>{throw Error("sampled event must not write")},
  });
  assert.equal(response.status,202);
  assert.deepEqual(await response.json(),{status:"sampled_out"});

  const disabled=new Request(endpoint,{method:"POST",body:fixture.body});
  assert.equal((await handleSensorIngest(disabled,{
    ...env,HONEY_SENSOR_INGEST_ENABLED:"false",
  })).status,404);
});
