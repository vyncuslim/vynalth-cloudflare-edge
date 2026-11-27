/** Signed, expiring intelligence manifests; advisory indicators only.
 * Strict schema, no remote code, regex, wildcard host or range rules.
 * The trusted operator supplies the key and persisted high-water mark.
 */
import {canonicalNetworkAddress} from "./vwaf-network.js";
import {CORE_HOSTS} from "./vwaf-scope.js";
const MAX_BYTES=65536;
const encoder=new TextEncoder();
function decode(s){
 if(typeof s!=="string"||!/^[A-Za-z0-9_-]+$/.test(s)||s.length>100000)throw Error("Invalid base64url");
 const x=atob(s.replace(/-/g,"+").replace(/_/g,"/")+"=".repeat((4-s.length%4)%4));
 return Uint8Array.from(x,c=>c.charCodeAt(0));
}
export async function verifyIntelEnvelope(envelope,publicKey,highWater=0,now=Date.now()){
 if(!Number.isSafeInteger(highWater)||highWater<0||!Number.isSafeInteger(now))throw Error("Invalid trust state");
 if(!envelope||Object.keys(envelope).sort().join(",")!=="payload,signature")throw Error("Invalid envelope");
 const bytes=decode(envelope.payload),sig=decode(envelope.signature),key=decode(publicKey);
 if(bytes.length>MAX_BYTES||sig.length!==64||key.length!==32)throw Error("Invalid envelope length");
 const trust=await crypto.subtle.importKey("raw",key,{name:"Ed25519"},false,["verify"]);
 if(!await crypto.subtle.verify("Ed25519",trust,sig,bytes))throw Error("Untrusted manifest");
 const x=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(bytes));
 if(Object.keys(x).sort().join(",")!=="expiresAt,indicators,issuedAt,schema,sequence"||
  x.schema!=="vwaf-intel-v1"||!Number.isSafeInteger(x.sequence)||x.sequence<=highWater||
  !Number.isSafeInteger(x.issuedAt)||!Number.isSafeInteger(x.expiresAt)||
  x.issuedAt>now+60000||x.issuedAt<now-604800000||x.expiresAt<=now||x.expiresAt>x.issuedAt+604800000||
  !Array.isArray(x.indicators)||x.indicators.length>256)throw Error("Invalid or stale manifest");
 const indicators=[],seen=new Set();
 for(const e of x.indicators){
  if(!e||Object.keys(e).sort().join(",")!=="address,category,host"||!CORE_HOSTS.includes(e.host)||
   !["observed_scanning","provider_report"].includes(e.category))throw Error("Invalid indicator");
  const address=canonicalNetworkAddress(e.address);
  if(!address||address!==e.address)throw Error("Noncanonical address");
  const k=e.host+"|"+address;if(seen.has(k))throw Error("Duplicate indicator");seen.add(k);
  indicators.push(Object.freeze({host:e.host,address,category:e.category}));
 }
 return Object.freeze({sequence:x.sequence,issuedAt:x.issuedAt,expiresAt:x.expiresAt,indicators:Object.freeze(indicators)});
}
export function advisoryIntelMatch(manifest,host,trustedAddress,now=Date.now()){
 // Called only with an independently trusted runtime network address.
 if(!manifest||manifest.expiresAt<=now||manifest.issuedAt>now+60000)return null;
 const address=canonicalNetworkAddress(trustedAddress);if(!address)return null;
 return manifest.indicators.some(e=>e.host===host&&e.address===address)?
  {id:"VWAF-701",category:"signed_intel_match",score:25,blocking:false}:null;
}
