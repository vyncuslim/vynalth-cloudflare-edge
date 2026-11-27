/** Advisory-only refresh. A trusted caller supplies an exact approved HTTPS URL,
 * Ed25519 trust anchor and durable atomic store. No request data controls egress.
 * Never changes enforcement rules or treats a network indicator as identity.
 */
import {verifyIntelEnvelope} from "./vwaf-intel.js";
const LIMIT=100000;
async function boundedEnvelope(response){
 if(!response.ok||response.redirected||!/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type")||"")){
  try{await response.body?.cancel()}catch{}
  throw Error("Unexpected intelligence response");
 }
 const advertised=response.headers.get("content-length");
 if(advertised!==null&&(!/^\d+$/.test(advertised)||Number(advertised)>LIMIT)){
  try{await response.body?.cancel()}catch{}
  throw Error("Intelligence response exceeds limit");
 }
 const reader=response.body?.getReader();if(!reader)throw Error("Missing intelligence body");
 const decoder=new TextDecoder("utf-8",{fatal:true});let bytes=0,value="";
 try{
  for(;;){const item=await reader.read();if(item.done)break;
   bytes+=item.value.byteLength;if(bytes>LIMIT)throw Error("Intelligence response exceeds limit");
   value+=decoder.decode(item.value,{stream:true});
  }
  return JSON.parse(value+decoder.decode());
 }finally{try{await reader.cancel()}catch{}}
}
export async function refreshSignedIntel({feedUrl,publicKey,store,fetchImpl=fetch,now=Date.now}={}){
 // Configuration comes from a privileged deployment, never from request input.
 const url=new URL(feedUrl);
 if(url.protocol!=="https:"||url.username||url.password||url.hash||url.search||url.port)
  throw Error("Feed must be an approved HTTPS endpoint");
 if(typeof publicKey!=="string"||!/^[A-Za-z0-9_-]{43}$/.test(publicKey)||
  typeof store?.load!=="function"||typeof store?.compareAndSwap!=="function")
  throw Error("Missing trusted intelligence configuration");
 const previous=await store.load();
 // Initialization must be explicit; storage corruption or failure never resets sequence.
 if(!previous||!Number.isSafeInteger(previous.sequence)||previous.sequence<0||
  (previous.sequence===0?previous.manifest!==null:previous.manifest?.sequence!==previous.sequence))
  throw Error("Invalid persisted intelligence state");
 const response=await fetchImpl(url.href,{method:"GET",redirect:"error",cache:"no-store",
  headers:{Accept:"application/json"},signal:AbortSignal.timeout(5000)});
 const envelope=await boundedEnvelope(response);
 const candidate=await verifyIntelEnvelope(envelope,publicKey,0,now());
 if(candidate.sequence<previous.sequence)throw Error("Intelligence rollback rejected");
 if(candidate.sequence===previous.sequence){
  if(JSON.stringify(candidate)!==JSON.stringify(previous.manifest))throw Error("Conflicting intelligence sequence");
  return {updated:false,sequence:candidate.sequence,expiresAt:candidate.expiresAt};
 }
 // CAS must commit both fields atomically and reject concurrent stale writers.
 if(await store.compareAndSwap(previous.sequence,{sequence:candidate.sequence,manifest:candidate})!==true)
  throw Error("Concurrent intelligence refresh; retry on next scheduled run");
 return {updated:true,sequence:candidate.sequence,expiresAt:candidate.expiresAt};
}
