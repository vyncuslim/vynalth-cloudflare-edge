/**
 * Authenticated, policy-only Service Binding endpoint for the existing vv Worker.
 * An invalid externally supplied service signature is never a bypass.
 * This code must execute before origin or static asset handlers.
 */
const HEADER_PREFIX="x-vynalth-gps-service-";
const ENC=new TextEncoder();
const ORIGINS=new Set(["vyncuslim.com","www.vyncuslim.com"]);
function hexToBytes(hex){
 if(!/^[a-f0-9]{64}$/.test(hex||""))return null;
 return Uint8Array.from(hex.match(/../g),x=>parseInt(x,16));
}
export function serviceSigningPayload(request,ts,ip,country,regionCode="",region="",version="1"){
 const base=["gps-service-v"+version,ts,request.method.toUpperCase(),request.url,ip,country];
 if(version==="2")base.push(regionCode,region);
 return base.join("\n");
}
export async function verifyGpsServiceCall(request,env,url){
 const entries=["v","ts","sig","ip","country","region-code","region"].map(v=>request.headers.get(HEADER_PREFIX+v));
 if(entries.every(v=>v===null))return null;
 const [version,ts,sig,ip,country,signedCode,signedRegion]=entries;
 const isV2=version==="2";
 const code=isV2?signedCode:null;
 const region=isV2?signedRegion:null;
 const secret=env?.GPS_SERVICE_AUTH_SECRET;
 const now=Math.floor(Date.now()/1000);
 if(!["1","2"].includes(version)||typeof secret!=="string"||secret.length<32||
   !ORIGINS.has(url.hostname.toLowerCase())||url.protocol!=="https:"||
   !/^\d{10}$/.test(ts||"")||Math.abs(Number(ts)-now)>30||
   typeof ip!=="string"||ip.length>64||!/^[a-fA-F0-9:.]+$/.test(ip)||
   !(country===""||/^[A-Z]{2}$/.test(country||""))||
   // The attestation must include *both* region fields in v2 even when
   // unknown. v1 requests cannot carry extra unverified region headers.
   (isV2 ? (typeof code!=="string"||code.length>16||
     !/^[A-Za-z0-9-]*$/.test(code)||typeof region!=="string"||
     region.length>80||!/^[\\p{L}\\p{M} .-]*$/u.test(region)) :
     signedCode!==null||signedRegion!==null))){
  return {authenticated:false};
 }
 const bytes=hexToBytes(sig);
 if(!bytes)return {authenticated:false};
 try{
  const key=await crypto.subtle.importKey("raw",ENC.encode(secret),
   {name:"HMAC",hash:"SHA-256"},false,["verify"]);
  const valid=await crypto.subtle.verify("HMAC",key,bytes,
   ENC.encode(serviceSigningPayload(request,ts,ip,country,
     code??"",region??"",version)));
  if(!valid)return {authenticated:false};
  // Never forward the auth headers to origin or application handlers.
  const headers=new Headers(request.headers);
  for(const name of [...headers.keys()])
   if(name.toLowerCase().startsWith(HEADER_PREFIX))headers.delete(name);
  headers.set("CF-Connecting-IP",ip);
  const clean=new Request(request,{headers});
  return {authenticated:true,request:clean,country,
    regionCode:code,region,version};
 }catch{return {authenticated:false}}
}
