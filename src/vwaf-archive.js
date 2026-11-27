/** Bounded private R2 evidence writer. Never archives raw request data. */
import {canonicalRestriction} from "./vwaf-policy.js";
const enc=new TextEncoder();
async function sha(bytes){return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)),x=>x.toString(16).padStart(2,"0")).join("")}
export async function archiveRestriction(env,job,now=Date.now()){
 const bucket=env?.VWAF_EVIDENCE;
 if(env?.VYNALTH_WAF_ARCHIVE_ENABLED!=="true"||!bucket?.put||!bucket?.get)return {state:"not_configured"};
 const record=canonicalRestriction(job?.record,now);
 if(!record||!/^[a-f0-9]{64}$/.test(job.sha256||""))return {state:"invalid"};
 const bytes=enc.encode(JSON.stringify(record));
 if(bytes.length>16384||await sha(bytes)!==job.sha256)return {state:"invalid"};
 const key="vwaf/v1.2/restrictions/"+new Date(record.at).toISOString().slice(0,10)+"/"+job.sha256+".json";
 try{
  await bucket.put(key,bytes,{httpMetadata:{contentType:"application/json"},customMetadata:{sha256:job.sha256,source:"vwaf-v1.2"}});
  const result=await bucket.get(key);
  if(!result||result.size>16384||await sha(await result.arrayBuffer())!==job.sha256)return {state:"unconfirmed"};
  return {state:"archived",key};
 }catch{return {state:"failed"}}
}
