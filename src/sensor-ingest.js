/**
 * Authenticated protocol-sensor summary intake. Disabled by default.
 * No credentials, commands, downloads, URLs or raw IP may enter this API.
 * Replay is time bounded (~90 seconds), not durable-nonce deduplicated.
 */
import { connect } from "@tidbcloud/serverless";
export const SENSOR_INTAKE_PATH = "/__vynalth/honeypot/sensors/v1";
const HOST = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com";
const INSERT_SQL = "INSERT INTO vynalth_honeypot.honeypot_events " +
 "(event_type, source, protocol, source_ip_hash, country_code, request_path, action_taken) " +
 "VALUES (?, ?, ?, ?, ?, ?, ?)";
const COWRIE_ACTIONS = new Set(["connect","disconnect","login_attempt",
 "command_observed","session_replay_available","file_observed"]);
const PROTOCOLS = Object.freeze({
 FTP:"opencanary",MYSQL:"opencanary",REDIS:"opencanary",SSH:"cowrie",TELNET:"cowrie"
});
const TOO_LARGE = Symbol("body-too-large");
const HEADERS = Object.freeze({
 "Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",
 "X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex, nofollow"
});
function reply(code,status) {
 return new Response(JSON.stringify({status}),{status:code,headers:HEADERS});
}
function validatedUrl(env) {
 const raw=env?.TIDB_HONEYPOT_DATABASE_URL;
 if (typeof raw!=="string"||raw.length>1024) return null;
 try {
  const u=new URL(raw);
  if(u.protocol!=="mysql:"||u.hostname!==HOST||u.port||
     u.pathname!=="/vynalth_honeypot"||u.search||u.hash||
     !u.username||!u.password||/(^root$|\.root$)/i.test(u.username))return null;
  return raw;
 }catch{return null;}
}
export function validateSensorSummary(x) {
 if(!x||typeof x!=="object"||Array.isArray(x))return null;
 const allowed=["event_type","source","protocol","source_ip_hash",
 "country_code","request_path","action_taken"];
 if(Object.keys(x).some(k=>!allowed.includes(k)))return null;
 if(x.event_type!=="suspicious_probe"||x.action_taken!=="observed"||
    PROTOCOLS[x.protocol]!==x.source)return null;
 const route=x.source==="opencanary"?"/"+x.protocol.toLowerCase()+"/probe":null;
 const segments=typeof x.request_path==="string"?x.request_path.split("/"):[];
 const pathValid=x.source==="cowrie" ?
  segments.length===3&&segments[0]==="" &&
  segments[1]===x.protocol.toLowerCase() && COWRIE_ACTIONS.has(segments[2])
  : x.request_path===route;
 if(!pathValid||(x.country_code!==null&&x.country_code!==undefined)||
    (x.source_ip_hash!==null&&x.source_ip_hash!==undefined &&
     !(typeof x.source_ip_hash==="string"&&/^[a-f0-9]{64}$/i.test(x.source_ip_hash))))
  return null;
 return ["suspicious_probe",x.source,x.protocol,x.source_ip_hash||null,
  null,x.request_path,"observed"];
}
async function boundedRead(request) {
 if(!request.body)return null;
 const reader=request.body.getReader();let total=0;const parts=[];
 for(;;){
  const item=await reader.read();
  if(item.done)break;
  total+=item.value.byteLength;
  if(total>1024){await reader.cancel();return TOO_LARGE;}
  parts.push(item.value);
 }
 const joined=new Uint8Array(total);let pos=0;
 for(const p of parts){joined.set(p,pos);pos+=p.byteLength;}
 try{return new TextDecoder("utf-8",{fatal:true}).decode(joined);}
 catch{return null;}
}
async function authorized(request,raw,key,now) {
 if(typeof key!=="string"||key.length<32)return false;
 const ts=request.headers.get("x-vynalth-sensor-time")||"";
 const nonce=request.headers.get("x-vynalth-sensor-nonce")||"";
 const proof=request.headers.get("x-vynalth-sensor-signature")||"";
 if(!/^\d{10}$/.test(ts)||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(nonce)||
    !/^[0-9a-f]{64}$/i.test(proof)||
    Math.abs(now-Number(ts)*1000)>90000)return false;
 const hmacKey=await crypto.subtle.importKey("raw",new TextEncoder().encode(key),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bytes=new Uint8Array(await crypto.subtle.sign("HMAC",hmacKey,
  new TextEncoder().encode(ts+"\n"+nonce+"\n"+raw)));
 const expected=Array.from(bytes).map(v=>v.toString(16).padStart(2,"0")).join("");
 const actual=proof.toLowerCase();let diff=0;
 for(let i=0;i<64;i++)diff|=expected.charCodeAt(i)^actual.charCodeAt(i);
 return diff===0;
}
export async function handleSensorIngest(request,env,options={}) {
 if(env?.HONEY_SENSOR_INGEST_ENABLED!=="true")return reply(404,"disabled");
 if(request.method!=="POST")return reply(405,"method_not_allowed");
 const url=validatedUrl(env);
 if(!url||typeof env?.HONEY_SENSOR_INGEST_KEY!=="string"||
  env.HONEY_SENSOR_INGEST_KEY.length<32)return reply(503,"not_configured");
 const length=request.headers.get("content-length");
 if(length!==null&&Number(length)>1024)return reply(413,"body_too_large");
 const raw=await boundedRead(request);
 if(raw===TOO_LARGE)return reply(413,"body_too_large");
 if(typeof raw!=="string"||raw.length<2)return reply(400,"invalid_body");
 if(!(await authorized(request,raw,env.HONEY_SENSOR_INGEST_KEY,
   options.now??Date.now())))return reply(401,"unauthorized");
 let json;
 try{json=JSON.parse(raw);}catch{return reply(400,"invalid_json");}
 const args=validateSensorSummary(json);
 if(!args)return reply(422,"invalid_schema");
 const rate=Number(env.HONEY_SENSOR_SAMPLE_RATE??"0.1");
 if(!Number.isFinite(rate)||rate<=0||rate>1)return reply(503,"bad_rate");
 if(rate!==1&&(options.random??Math.random)()>=rate)return reply(202,"sampled_out");
 try{
  const conn=(options.connectImpl??connect)({url});
  await conn.execute(INSERT_SQL,args);
  return reply(201,"inserted");
 }catch{
  console.warn("[HONEY SENSOR] insert failed");
  return reply(503,"database_unavailable");
 }
}
