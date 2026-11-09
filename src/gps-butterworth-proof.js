/**
 * Optional, consented browser-location recovery for a Butterworth visitor
 * misclassified by Cloudflare IP city (e.g. Tasek Glugor).
 *
 * Not an official city boundary or proof of identity. A browser-reported GPS
 * reading is spoofable. This reduces unnecessary prompts, never replaces WAF,
 * School IP policy, application auth, or the campus-geofence INSIDE decision.
 */
export const BUTTERWORTH_PROOF_COOKIE="__Host-vynalth-bw-location";
export const BUTTERWORTH_PROOF_TTL=1800; // 30 minutes; always host/IP-bound.
export const BUTTERWORTH_PROOF_KIND="butterworth-approximate";
export const MISLOCATED_OUTSIDE_KIND="verified-outside-ambiguous-ip";
const KINDS=new Set([BUTTERWORTH_PROOF_KIND,MISLOCATED_OUTSIDE_KIND]);
const enc=new TextEncoder();
// Deliberately conservative APPROXIMATE urban region, not all Tasek Glugor.
// Exact accuracy circle must remain at least 250 m inside each box side.
const INNER_REGION=Object.freeze({
  south:5.375,north:5.455,west:100.355,east:100.445
});
function validSourceIp(request){
  const ip=request?.headers?.get("CF-Connecting-IP");
  return typeof ip==="string"&&ip.length>=3&&ip.length<=64&&
    /^[0-9a-f:.]+$/i.test(ip)?ip:null;
}
export function inApproximateButterworth(lat,lon,accuracy){
  if(![lat,lon,accuracy].every(x=>typeof x==="number"&&Number.isFinite(x))||
     accuracy<=0||accuracy>3000)return false;
  const marginMeters=accuracy+250;
  const latMargin=marginMeters/111320;
  const lonMargin=marginMeters/(111320*Math.cos(lat*Math.PI/180));
  return lat>=INNER_REGION.south+latMargin &&
    lat<=INNER_REGION.north-latMargin &&
    lon>=INNER_REGION.west+lonMargin &&
    lon<=INNER_REGION.east-lonMargin;
}
/**
 * Fallback for an explicit, fresh OUTSIDE-campus verification on a request
 * whose original trusted Cloudflare metadata labels the IP as Tasek Glugor.
 * This does NOT assert the visitor is physically in Butterworth; it only
 * extends a user-initiated outside-campus verdict. Do not check browser
 * headers, user-provided city, timezone, or GPS coordinates here.
 *
 * Call ONLY after the independent campus geofence has returned OUTSIDE.
 */
export function isAmbiguousIpRecoveryEligible(request,accuracy){
 const cf=request?.cf;
 const country=String(cf?.country??"").trim().toUpperCase();
 const code=String(cf?.regionCode??"").trim().toUpperCase();
 const name=String(cf?.region??"").trim().toLowerCase();
 const city=String(cf?.city??"").normalize("NFKC").trim().toLowerCase();
 const penang=(code==="07"||code==="MY-07") &&
   (!name||name==="penang"||name==="pulau pinang");
 return country==="MY"&&penang&&city==="tasek glugor"&&
   Number.isFinite(accuracy)&&accuracy>0&&accuracy<=5000;
}
function b64(bytes) {
 let raw="";for(const b of bytes)raw+=String.fromCharCode(b);
 return btoa(raw).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"");
}
function decode(input){
 if(!/^[A-Za-z0-9_-]{43}$/.test(input||""))return null;
 try{
  const s=input.replace(/-/g,"+").replace(/_/g,"/");
  return Uint8Array.from(atob(s+"=".repeat((4-s.length%4)%4)),x=>x.charCodeAt(0));
 }catch{return null}
}
async function key(secret){
 return crypto.subtle.importKey("raw",enc.encode(secret),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
}
function payload(exp,nonce,host,ip,kind=BUTTERWORTH_PROOF_KIND){
 const context=kind===MISLOCATED_OUTSIDE_KIND?"verified-outside-ambiguous-ip-v1":"butterworth-approximate-v1";
 return [context,exp,nonce,host,ip].join("|");
}
export async function mintButterworthProof(request,secret,host,kind=BUTTERWORTH_PROOF_KIND) {
 const ip=validSourceIp(request);
 if(!KINDS.has(kind)||!ip||typeof secret!=="string"||secret.length<32)return null;
 const exp=String(Math.floor(Date.now()/1000)+BUTTERWORTH_PROOF_TTL);
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 const nonce=b64(bytes);
 const sig=b64(new Uint8Array(await crypto.subtle.sign(
  "HMAC",await key(secret),enc.encode(payload(exp,nonce,host,ip,kind)))));
 return BUTTERWORTH_PROOF_COOKIE+"="+exp+"."+nonce+"."+sig+
  "; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age="+BUTTERWORTH_PROOF_TTL;
}
export async function inspectButterworthProof(request,env,host){
 if(env?.GPS_BUTTERWORTH_PROOF_ENABLED!=="true")return {valid:false,status:"feature-disabled"};
 const ip=validSourceIp(request),secret=env?.GPS_GATE_SESSION_SECRET;
 if(!ip)return {valid:false,status:"source-ip-unavailable"};
 if(typeof secret!=="string"||secret.length<32)return {valid:false,status:"signing-unavailable"};
 const pair=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim())
   .find(x=>x.startsWith(BUTTERWORTH_PROOF_COOKIE+"="));
 if(!pair)return {valid:false,status:"missing-cookie"};
 const raw=pair.slice(BUTTERWORTH_PROOF_COOKIE.length+1);
 if(raw.length>190)return {valid:false,status:"malformed-cookie"};
 const [exp,nonce,sig,...extra]=raw.split(".");
 if(extra.length||!/^[0-9]{10,12}$/.test(exp||"")||
  !/^[A-Za-z0-9_-]{22}$/.test(nonce||""))return {valid:false,status:"malformed-cookie"};
 const now=Math.floor(Date.now()/1000),end=Number(exp);
 if(end<=now||end>now+BUTTERWORTH_PROOF_TTL)return {valid:false,status:"expired-cookie"};
 const signature=decode(sig);
 if(!signature||signature.length!==32)return {valid:false,status:"malformed-cookie"};
 try{
  const hmacKey=await key(secret);
  for(const kind of KINDS){
   if(await crypto.subtle.verify("HMAC",hmacKey,signature,
       enc.encode(payload(exp,nonce,host,ip,kind)))){
    return {valid:true,status:"valid",kind};
   }
  }
  return {valid:false,status:"invalid-or-network-changed"};
 }catch{return {valid:false,status:"verification-failed"}}
}
// Coarse status only: never return raw IP, GPS coordinates, cookie, or signature.
export async function hasButterworthProof(request,env,host){
 return (await inspectButterworthProof(request,env,host)).valid;
}
