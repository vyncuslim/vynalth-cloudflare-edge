/**
 * VWAF bounded content and reviewed schema inspection. No forwarding,
 * persistence or logging of input. Only known JSON routes; unframed opt-in.
 */
import {isLocalDestination} from "./vwaf-network.js";
import {inspectApiSchema} from "./vwaf-schema.js";
const MAX_BYTES=8192, MAX_FIELDS=32, MAX_VALUE=512;
// Never clone login/signup bodies: they may carry credentials.
const ROUTES=new Set(["/api/web-search","/api/ai/image","/api/cloud-browser-live"]);
const FIELDS=new Set(["id","page","limit","offset","sort","order","file","path","redirect","return","next","url"]);
const RULES=[
 ["VWAF-301","sql_body_signal",/\bunion\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+\d+\s*=\s*\d+/i],
 ["VWAF-302","script_body_signal",/<\s*script(?:\s|>|\/)|\bon(?:load|error)\s*=|javascript\s*:/i],
 ["VWAF-303","file_body_signal",/(?:^|[\\/])\.\.(?:[\\/]|$)|(?:file|php):\/\//i]
];
function hit(id,category,score=40){return {id,category,score,blocking:false}}
export function inspectStructuredContent(value){
 const signals=new Map();const add=x=>signals.set(x.id,x);
 const containers=new Set(["options","filters","pagination","parameters"]);
 let visited=0,exhausted=false;
 function scan(node,depth){
  if(exhausted||!node||typeof node!=="object"||Array.isArray(node)||depth>2)return;
  const keys=Object.keys(node);
  for(const key of keys){
   if(exhausted)return;
   if(++visited>MAX_FIELDS){exhausted=true;add(hit("VWAF-304","content_budget",10));return}
   if(["__proto__","constructor","prototype"].includes(key))add(hit("VWAF-305","object_key_signal"));
   const k=key.toLowerCase(),v=node[key];
   if(containers.has(k)){if(depth<2)scan(v,depth+1);continue}
   if(!FIELDS.has(k)||typeof v!=="string")continue;
   if(v.length>MAX_VALUE){add(hit("VWAF-304","content_budget",10));continue}
   for(const [id,category,re] of RULES)if(re.test(v))add(hit(id,category));
   if(["url","redirect","return","next"].includes(k)&&isLocalDestination(v))
    add(hit("VWAF-306","local_destination_signal"));
  }
 }
 scan(value,0);return [...signals.values()];
}
export function isWafContentCandidate(request,{allowUnframed=false}={}){
 const u=new URL(request.url);
 if(u.hostname!=="vynalthai.com"||request.method!=="POST"||!ROUTES.has(u.pathname.replace(/\/+$/,"")))return false;
 if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type")||""))return false;
 const coding=request.headers.get("content-encoding");if(coding&&coding.toLowerCase()!=="identity")return false;
 const raw=request.headers.get("content-length");
 if(raw===null)return allowUnframed===true&&request.body!==null;
 return /^\d{1,5}$/.test(raw)&&Number(raw)>=1&&Number(raw)<=MAX_BYTES;
}
export async function inspectWafContent(request,options={}){
 if(!isWafContentCandidate(request,options))return [];
 const raw=request.headers.get("content-length"),declared=raw===null?null:Number(raw);
 let reader,timer;
 try{
  reader=request.clone().body?.getReader();if(!reader)return [];
  const deadline=new Promise(resolve=>{timer=setTimeout(()=>resolve({timeout:true}),75)});
  // One fixed-size buffer, global byte and empty-chunk budget. The deadline
  // also applies to completion, not just the first chunk. Never parse partial JSON.
  const cap=declared??MAX_BYTES,bytes=new Uint8Array(cap);let total=0,empty=0;
  for(;;){
   const r=await Promise.race([reader.read(),deadline]);if(r.timeout)return [];
   if(r.done)break;
   if(!(r.value instanceof Uint8Array))return [];
   if(!r.value.byteLength){if(++empty>32)return [];continue}
   if(total+r.value.byteLength>cap)return [];
   bytes.set(r.value,total);total+=r.value.byteLength;
  }
  if(total===0||(declared!==null&&total!==declared))return [];
  const value=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes.subarray(0,total)));
  const route=new URL(request.url).pathname.replace(/\/+$/,"");
  // The live-browser route is scanned only for its explicit navigation URL
  // contract. No session/stream identifiers, credentials or generic body scan.
  const signals=route==="/api/cloud-browser-live"?inspectApiSchema(route,value):
    [...inspectStructuredContent(value),...inspectApiSchema(route,value)];
  return [...new Map(signals.map(s=>[s.id,s])).values()];
 }catch{return []}finally{
  clearTimeout(timer);
  // Cancellation of a tee branch can wait for the original consumer. Do not await.
  if(reader){try{void reader.cancel().catch(()=>{})}catch{}}
 }
}
