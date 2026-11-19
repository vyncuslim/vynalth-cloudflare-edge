/**
 * Explicitly disabled V2 signed intake. Event-reference HMAC binding plus a
 * SQLite Durable Object claim BEFORE any sampled insert prevents same-ref
 * duplicate writes (at-most-once attempt, NOT guaranteed delivery).
 * Missing DO binding, full ledger, or ambiguous DB outcome fails CLOSED.
 */
import { connect } from "@tidbcloud/serverless";
import { validateSensorSummary } from "./sensor-ingest.js";

export const SENSOR_INTAKE_V2_PATH="/__vynalth/honeypot/sensors/v2";
export const SENSOR_V2_SIGNING_DOMAIN="vynalth-sensor-v2";
const HOST="gateway01.ap-southeast-1.prod.aws.tidbcloud.com";
const INSERT_SQL="INSERT INTO vynalth_honeypot.honeypot_events "+
    "(event_type,source,protocol,source_ip_hash,country_code,request_path,action_taken) "+
    "VALUES (?,?,?,?,?,?,?)";
const HEADERS={
  "Content-Type":"application/json; charset=utf-8",
  "Cache-Control":"no-store",
  "X-Content-Type-Options":"nosniff",
  "X-Robots-Tag":"noindex, nofollow"
};
const reply=(status,outcome)=>new Response(JSON.stringify({outcome}),
    {status,headers:HEADERS});
const HEX64=/^[a-f0-9]{64}$/;
const UUID4=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function databaseUrl(env){
  const raw=env?.TIDB_HONEYPOT_DATABASE_URL;
  if(typeof raw!=="string"||raw.length>1024)return null;
  try{
    const u=new URL(raw);
    if(u.protocol!=="mysql:"||u.hostname!==HOST||u.port||
       u.pathname!=="/vynalth_honeypot"||u.search||u.hash||
       !u.username||!u.password||/(^root$|\.root$)/i.test(u.username))
      return null;
    return raw;
  }catch{return null;}
}

async function readBody(request){
  if(!request.body)return null;
  const reader=request.body.getReader();
  const parts=[];let total=0;
  for(;;){
    const r=await reader.read();
    if(r.done)break;
    total+=r.value.byteLength;
    if(total>1024){await reader.cancel();return null;}
    parts.push(r.value);
  }
  const result=new Uint8Array(total);let offset=0;
  for(const part of parts){result.set(part,offset);offset+=part.byteLength;}
  try{return new TextDecoder("utf-8",{fatal:true}).decode(result);}
  catch{return null;}
}

async function authenticate(request,raw,key,now){
  if(typeof key!=="string"||key.length<32)return null;
  const ts=request.headers.get("x-vynalth-sensor-time")||"";
  const nonce=request.headers.get("x-vynalth-sensor-nonce")||"";
  const ref=request.headers.get("x-vynalth-sensor-event-ref")||"";
  const signature=request.headers.get("x-vynalth-sensor-signature")||"";
  if(!/^\d{10}$/.test(ts)||!UUID4.test(nonce)||!HEX64.test(ref)||
     !HEX64.test(signature)||!Number.isFinite(now)||
     Math.abs(now-Number(ts)*1000)>90000)return null;
  const keyObject=await crypto.subtle.importKey(
    "raw",new TextEncoder().encode(key),{name:"HMAC",hash:"SHA-256"},
    false,["verify"]);
  const payload=SENSOR_V2_SIGNING_DOMAIN+"\n"+ts+"\n"+nonce+"\n"+ref+"\n"+raw;
  const bits=Uint8Array.from(signature.match(/../g),x=>parseInt(x,16));
  return await crypto.subtle.verify(
      "HMAC",keyObject,bits,new TextEncoder().encode(payload)) ? ref : null;
}

async function ledgerOperation(env,action,payload){
  const binding=env?.SENSOR_REPLAY_LEDGER;
  if(!binding||typeof binding.idFromName!=="function"||
     typeof binding.get!=="function")return {status:503};
  try{
    // A single private ledger avoids cross-shard race conditions. Bounded
    // record count is enforced inside the Durable Object.
    const id=binding.idFromName("vynalth-protocol-sensor-ledger-v2");
    const stub=binding.get(id);
    const request=new Request("https://internal.vynalth.invalid/"+action,{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload),
    });
    const response=await stub.fetch(request);
    return {status:response.status};
  }catch{return {status:503};}
}

export async function handleSensorIngestV2(request,env,options={}){
  if(env?.HONEY_SENSOR_V2_ENABLED!=="true")return reply(404,"disabled");
  if(request.method!=="POST")return reply(405,"method_not_allowed");
  // No DB request or ledger claim without all required bindings.
  const url=databaseUrl(env);
  if(!url||typeof env?.HONEY_SENSOR_V2_KEY!=="string"||
     env.HONEY_SENSOR_V2_KEY.length<32)return reply(503,"not_configured");
  const length=request.headers.get("content-length");
  if(length!==null&&Number(length)>1024)return reply(413,"body_too_large");
  const raw=await readBody(request);
  if(raw===null||raw.length<2)return reply(400,"invalid_body");
  let ref;
  try{
    ref=await authenticate(request,raw,env.HONEY_SENSOR_V2_KEY,
                           options.now??Date.now());
  }catch{return reply(401,"unauthorized");}
  if(!ref)return reply(401,"unauthorized");
  let body;
  try{body=JSON.parse(raw);}catch{return reply(400,"invalid_json");}
  const args=validateSensorSummary(body);
  if(!args)return reply(422,"invalid_schema");
  const rate=Number(env.HONEY_SENSOR_V2_SAMPLE_RATE??"0.1");
  if(!Number.isFinite(rate)||rate<=0||rate>1)
    return reply(503,"sampling_not_configured");
  const claim=await (options.ledgerClaim?
       options.ledgerClaim(ref,options.now??Date.now()):
       ledgerOperation(env,"claim",{eventRef:ref,nowMs:options.now??Date.now()}));
  if(claim?.status===409)return reply(409,"duplicate_held");
  if(claim?.status!==201)return reply(503,"ledger_unavailable");
  // Claim is durable BEFORE random sampling or external TiDB I/O.
  async function settle(state){
    return await (options.ledgerSettle?
      options.ledgerSettle(ref,state):
      ledgerOperation(env,"settle",{eventRef:ref,state}));
  }
  if(rate!==1&&(options.random??Math.random)()>=rate){
    const outcome=await settle("sampled_out");
    return outcome?.status===200?reply(202,"sampled_out"):
      reply(503,"outcome_uncertain");
  }
  try{
    const conn=(options.connectImpl??connect)({url});
    await conn.execute(INSERT_SQL,args);
    const outcome=await settle("insert_acknowledged");
    return outcome?.status===200?reply(201,"insert_acknowledged"):
      reply(503,"outcome_uncertain");
  }catch{
    // DB failure is ambiguous; never release a claim for automatic replay.
    await settle("database_uncertain");
    return reply(503,"database_unavailable");
  }
}
