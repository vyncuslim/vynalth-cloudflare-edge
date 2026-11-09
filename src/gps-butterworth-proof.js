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
     accuracy<=0||accuracy>100)return false;
  const marginMeters=accuracy+250;
  const latMargin=marginMeters/111320;
  const lonMargin=marginMeters/(111320*Math.cos(lat*Math.PI/180));
  return lat>=INNER_REGION.south+latMargin &&
    lat<=INNER_REGION.north-latMargin &&
    lon>=INNER_REGION.west+lonMargin &&
    lon<=INNER_REGION.east-lonMargin;
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
function payload(exp,nonce,host,ip){
 return ["butterworth-approximate-v1",exp,nonce,host,ip].join("|");
}
export async function mintButterworthProof(request,secret,host) {
 const ip=validSourceIp(request);
 if(!ip||typeof secret!=="string"||secret.length<32)return null;
 const exp=String(Math.floor(Date.now()/1000)+BUTTERWORTH_PROOF_TTL);
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 const nonce=b64(bytes);
 const sig=b64(new Uint8Array(await crypto.subtle.sign(
  "HMAC",await key(secret),enc.encode(payload(exp,nonce,host,ip)))));
 return BUTTERWORTH_PROOF_COOKIE+"="+exp+"."+nonce+"."+sig+
  "; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age="+BUTTERWORTH_PROOF_TTL;
}
export async function hasButterworthProof(request,env,host){
 if(env?.GPS_BUTTERWORTH_PROOF_ENABLED!=="true")return false;
 const ip=validSourceIp(request),secret=env?.GPS_GATE_SESSION_SECRET;
 if(!ip||typeof secret!=="string"||secret.length<32)return false;
 const pair=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim())
   .find(x=>x.startsWith(BUTTERWORTH_PROOF_COOKIE+"="));
 if(!pair)return false;
 const raw=pair.slice(BUTTERWORTH_PROOF_COOKIE.length+1);
 if(raw.length>190)return false;
 const [exp,nonce,sig,...extra]=raw.split(".");
 if(extra.length||!/^[0-9]{10,12}$/.test(exp||"")||
  !/^[A-Za-z0-9_-]{22}$/.test(nonce||""))return false;
 const now=Math.floor(Date.now()/1000),end=Number(exp);
 if(end<=now||end>now+BUTTERWORTH_PROOF_TTL)return false;
 const signature=decode(sig);
 if(!signature||signature.length!==32)return false;
 try{
  return await crypto.subtle.verify("HMAC",await key(secret),signature,
    enc.encode(payload(exp,nonce,host,ip)));
 }catch{return false}
}
