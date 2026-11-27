/**
 * VWAF Core content inspection. Observation only. No forwarding, persistence,
 * or logging of input. Small explicitly framed JSON on known routes only.
 */
const MAX_BYTES=8192, MAX_FIELDS=32, MAX_VALUE=512;
const ROUTES=new Set(["/api/web-search","/api/signup","/api/auth/signup","/api/ai/image"]);
const FIELDS=new Set(["id","page","limit","offset","sort","order","file","path","redirect","return","next","url"]);
const RULES=[
 ["VWAF-301","sql_body_signal",/\bunion\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+\d+\s*=\s*\d+/i],
 ["VWAF-302","script_body_signal",/<\s*script(?:\s|>|\/)|\bon(?:load|error)\s*=|javascript\s*:/i],
 ["VWAF-303","file_body_signal",/(?:^|[\\/])\.\.(?:[\\/]|$)|(?:file|php):\/\//i]
];
function hit(id,category,score=40){return {id,category,score,blocking:false}}
export function inspectStructuredContent(value){
 const signals=new Map();const add=x=>signals.set(x.id,x);
 if(!value||typeof value!=="object"||Array.isArray(value))return [];
 const keys=Object.keys(value);
 if(keys.length>MAX_FIELDS)add(hit("VWAF-304","content_budget",10));
 for(const key of keys.slice(0,MAX_FIELDS)){
  if(["__proto__","constructor","prototype"].includes(key))add(hit("VWAF-305","object_key_signal"));
  // Prompt, email, password, uploaded content and arbitrary nested objects are not scanned.
  if(!FIELDS.has(key.toLowerCase()))continue;
  const v=value[key];if(typeof v!=="string")continue;
  if(v.length>MAX_VALUE){add(hit("VWAF-304","content_budget",10));continue}
  for(const [id,category,re] of RULES)if(re.test(v))add(hit(id,category));
  if(["url","redirect","return","next"].includes(key.toLowerCase())){
   try{const u=new URL(v);if(["file:","ftp:"].includes(u.protocol)||/^(?:localhost|127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|169\.254(?:\.\d{1,3}){2}|\[::1\])$/i.test(u.hostname))add(hit("VWAF-306","local_destination_signal"))}catch{}
  }
 }
 return [...signals.values()];
}
export async function inspectWafContent(request){
 const u=new URL(request.url);
 if(u.hostname!=="vynalthai.com"||request.method!=="POST"||!ROUTES.has(u.pathname.replace(/\/+$/,"")))return [];
 if(!/^application\/json(?:\s*;|$)/i.test(request.headers.get("content-type")||""))return [];
 const coding=request.headers.get("content-encoding");if(coding&&coding.toLowerCase()!=="identity")return [];
 const raw=request.headers.get("content-length");
 if(!raw||!/^\d{1,5}$/.test(raw)||Number(raw)<1||Number(raw)>MAX_BYTES)return [];
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
