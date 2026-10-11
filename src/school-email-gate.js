/* School-account login restriction — server-verified identity only.
 * The existing Vynalth Auth server is authoritative for verified login/email.
 * This edge service cannot derive identity from arbitrary form fields, IP,
 * client headers, the address typed into a login box, or GPS reports.
 * NOTE: this is not a substitute for auth-backend account-state enforcement.
 */
import { signedSSO } from "./universal-consent.js";

const COOKIE="__Host-vynalth-school-restricted";
const TTL_SECONDS=300;
const encoder=new TextEncoder();
const baseHeaders={
 "Cache-Control":"private, no-store, max-age=0",
 "Content-Type":"application/json; charset=utf-8",
 "X-Content-Type-Options":"nosniff",
 "Referrer-Policy":"no-referrer",
 "X-Robots-Tag":"noindex,nofollow",
 "Vary":"Cookie"
};
const deny=(status,error,headers={})=>new Response(JSON.stringify({
 blocked:true,error,reason:"SCHOOL_ACCOUNT_RESTRICTED"
}),{status,headers:{...baseHeaders,...headers}});
const b64=bytes=>{
 let s="";for(const n of bytes)s+=String.fromCharCode(n);
 return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/,"");
};
function getCookie(request,name){
 return (request.headers.get("Cookie")||"").split(";")
  .map(x=>x.trim()).find(x=>x.startsWith(name+"="))?.slice(name.length+1)||null;
}
function restrictedEmail(email){
 if(typeof email!=="string"||email.length>254||email!==email.trim())return false;
 const at=email.lastIndexOf("@");
 if(at<1||email.indexOf("@")!==at)return false;
 const domain=email.slice(at+1).toLowerCase();
 return domain==="powiis.edu.my"||domain==="student.powiis.edu.my";
}
function issuerReady(env){
 return typeof env?.CONSENT_SSO_SIGNING_SECRET==="string"&&
   env.CONSENT_SSO_SIGNING_SECRET.length>=32;
}
function cookieReady(env){
 return typeof env?.SCHOOL_EMAIL_BLOCK_SECRET==="string"&&
   env.SCHOOL_EMAIL_BLOCK_SECRET.length>=32;
}
function publicSafePath(path){
 // Logout must remain usable so a student can sign into another account.
 // Legal/privacy/help, user choice and consent withdrawal must remain usable.
 return path==="/api/auth/logout"||path==="/auth/logout"||
   path==="/api/auth/signout"||path==="/auth/signout"||
   path==="/logout"||path==="/robots.txt"||path==="/favicon.ico"||
   path==="/en/legal/privacy"||path==="/legal/privacy"||
   path==="/__shield/gps/disclaimer"||
   path==="/__shield/gps/verify-info"||
   path==="/__vynalth/consent"||path==="/__vynalth/consent/"||
   path==="/__vynalth/consent/client.js"||
   path==="/__vynalth/consent/session"||
   path==="/__vynalth/consent/state"||
   path==="/__vynalth/consent/history"||
   path==="/__vynalth/consent/preferences"||
   path.startsWith("/.well-known/acme-challenge/")||
   path.startsWith("/.well-known/vercel/");
}
async function mac(secret,message){
 const key=await crypto.subtle.importKey("raw",encoder.encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 return b64(new Uint8Array(await crypto.subtle.sign("HMAC",key,encoder.encode(message))));
}
function safeCompare(a,b){
 if(typeof a!=="string"||typeof b!=="string"||a.length!==b.length)return false;
 let diff=0;for(let i=0;i<a.length;i++)diff|=a.charCodeAt(i)^b.charCodeAt(i);
 return diff===0;
}
async function issuedCookie(secret,hostname){
 const exp=Math.floor(Date.now()/1000)+TTL_SECONDS;
 const nonce=new Uint8Array(16);crypto.getRandomValues(nonce);
 const id=b64(nonce);
 const tag=await mac(secret,["vynalth-school-restricted-v1",hostname,exp,id].join("|"));
 const value=[exp,id,tag].join(".");
 return COOKIE+"="+value+"; Path=/; Max-Age="+TTL_SECONDS+
  "; Secure; HttpOnly; SameSite=Lax";
}
async function hasSignedRestriction(request,env,hostname){
 if(!cookieReady(env))return false;
 const value=getCookie(request,COOKIE);
 if(!value||value.length>240)return false;
 const parts=value.split(".");
 if(parts.length!==3)return false;
 const [exp,id,signature]=parts;
 if(!/^\d{10,12}$/.test(exp)||!/^[A-Za-z0-9_-]{22}$/.test(id)||
    !/^[A-Za-z0-9_-]{43}$/.test(signature))return false;
 const now=Math.floor(Date.now()/1000);
 if(Number(exp)<=now||Number(exp)>now+TTL_SECONDS)return false;
 const expected=await mac(env.SCHOOL_EMAIL_BLOCK_SECRET,
  ["vynalth-school-restricted-v1",hostname,exp,id].join("|"));
 return safeCompare(signature,expected);
}
export async function schoolEmailGate(request,env,url,root){
 if(env?.SCHOOL_EMAIL_GATE_ENABLED!=="true")return null;
 // Never accept email from URL/body/headers. Only from authenticated,
 // host-bound, HMAC-signed canonical SSO, after its issuer verified the email.
 const identity=issuerReady(env)?await signedSSO(request,env,root):null;
 const verifiedSchool=!!identity&&identity.email_verified===true&&
   restrictedEmail(identity.email);
 const previousBlock=await hasSignedRestriction(request,env,url.hostname);
 if(!verifiedSchool&&!previousBlock)return null;
 if(publicSafePath(url.pathname))return null;
 if(verifiedSchool&&!cookieReady(env))
  return deny(503,"SCHOOL_BLOCK_SIGNING_NOT_CONFIGURED");
 const headers={};
 if(verifiedSchool)headers["Set-Cookie"]=await issuedCookie(
  env.SCHOOL_EMAIL_BLOCK_SECRET,url.hostname);
 // Stateless, temporary, host-scoped denial marker: it never grants access.
 // An authenticated school account is denied even if user deletes the marker.
 return deny(403,"SCHOOL_EMAIL_DOMAIN_BLOCKED",headers);
}
export {restrictedEmail};
