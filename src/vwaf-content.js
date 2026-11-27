/**
 * VWAF Core content inspection. Observation only. No forwarding, persistence,
 * or logging of input. Small explicitly framed JSON on known routes only.
 */
import {isLocalDestination} from "./vwaf-network.js";
const MAX_BYTES=8192, MAX_FIELDS=32, MAX_VALUE=512;
// Never clone login/signup bodies: they may carry credentials.
const ROUTES=new Set(["/api/web-search","/api/ai/image"]);
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
 let visited=0;
 function scan(node,depth){
  if(!node||typeof node!=="object"||Array.isArray(node)||depth>2)return;
  const keys=Object.keys(node);
  for(const key of keys){
   if(++visited>MAX_FIELDS){add(hit("VWAF-304","content_budget",10));return}
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
export function isWafContentCandidate(request){
 const u=new URL(request.url);
 if(u.hostname!=="vynalthai.com"||request.method!=="POST"||!ROUTES.has(u.pathname.replace(/\/+$/,"")))return false;
 if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type")||""))return false;
 const coding=request.headers.get("content-encoding");if(coding&&coding.toLowerCase()!=="identity")return false;
 const raw=request.headers.get("content-length");
 return !!raw&&/^\d{1,5}$/.test(raw)&&Number(raw)>=1&&Number(raw)<=MAX_BYTES;
}
export async function inspectWafContent(request){
 if(!isWafContentCandidate(request))return [];
 const raw=request.headers.get("content-length");
 let reader,timer;
 try{
  reader=request.clone().body?.getReader();if(!reader)return [];
  const deadline=new Promise(resolve=>{timer=setTimeout(()=>resolve({timeout:true}),75)});
  const chunks=[];let total=0;
  for(;;){
   const r=await Promise.race([reader.read(),deadline]);if(r.timeout)return [];
   if(r.done)break;
   total+=r.value.byteLength;if(total>MAX_BYTES||total>Number(raw))return [];
   chunks.push(r.value);
  }
  if(total!==Number(raw))return [];
  const bytes=new Uint8Array(total);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.byteLength}
  return inspectStructuredContent(JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes)));
 }catch{return []}finally{
  clearTimeout(timer);
  // Cancellation of a tee branch can wait for the original consumer. Do not await.
  if(reader){try{void reader.cancel().catch(()=>{})}catch{}}
 }
}
