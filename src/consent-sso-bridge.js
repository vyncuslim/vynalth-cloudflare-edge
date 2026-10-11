import { signedSSO } from "./universal-consent.js";

/**
 * First-party binding of a canonical, Auth-backend-signed SSO assertion.
 * This Worker has the verifying HMAC secret but NEVER creates an identity.
 * Production remains dormant unless explicitly enabled after review.
 */
const COOKIE="__Secure-vynalth-sso";
const PATH="/__vynalth/sso/session";
const HOST="vynalthai.com";
const ORIGIN="https://vynalthai.com";
const headers={"Cache-Control":"private, no-store","Content-Type":"application/json; charset=utf-8",
 "Referrer-Policy":"no-referrer","X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex,nofollow"};
const output=(status,data,extra={})=>new Response(JSON.stringify(data),{status,
 headers:{...headers,...extra}});
const cookie=(value,age)=>COOKIE+"="+value+"; Domain="+HOST+
 "; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age="+age;
const okayOrigin=(request)=>request.headers.get("Origin")===ORIGIN&&
 (request.headers.get("Sec-Fetch-Site")===null||
  request.headers.get("Sec-Fetch-Site")==="same-origin");
export async function handleConsentSsoBridge(request,env,url){
 if(url.hostname!==HOST||!url.pathname.startsWith(PATH))return null;
 if(url.pathname!==PATH&&url.pathname!==PATH+"/clear"&&
    url.pathname!==PATH+"/status")return null;
 if(env?.CONSENT_SSO_BRIDGE_ENABLED!=="true")return output(503,{error:"SSO_BRIDGE_DISABLED"});
 if(url.pathname===PATH+"/status"){
  if(request.method!=="GET")return output(405,{error:"METHOD_NOT_ALLOWED"});
  const identity=await signedSSO(request,env,HOST);
  return output(200,{authenticated:!!identity},{"Vary":"Cookie"});
 }
 if(request.method!=="POST")return output(405,{error:"METHOD_NOT_ALLOWED"});
 if(!okayOrigin(request))return output(403,{error:"ORIGIN_NOT_ALLOWED"});
 if(url.pathname===PATH+"/clear"){
  return output(200,{cleared:true},{"Set-Cookie":cookie("",0)});
 }
 if(request.headers.get("Content-Type")?.split(";")[0]?.trim().toLowerCase()!=="application/json")
  return output(415,{error:"JSON_REQUIRED"});
 const length=Number(request.headers.get("Content-Length")||0);
 if(!Number.isFinite(length)||length>1600)return output(413,{error:"REQUEST_TOO_LARGE"});
 let data;
 try{const raw=await request.text();if(raw.length>1600)return output(413,{error:"REQUEST_TOO_LARGE"});
  data=JSON.parse(raw);}catch{return output(400,{error:"INVALID_JSON"});}
 const assertion=data?.assertion;
 if(typeof assertion!=="string"||assertion.length>1200||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(assertion))
  return output(403,{error:"SSO_ASSERTION_INVALID"});
 // Signed assertion verifier already checks cryptographic HMAC, sub, sid,
 // claim host, server-attested email and <=600s expiry.
 const test=new Request(ORIGIN+PATH,{headers:{Cookie:COOKIE+"="+assertion}});
 const identity=await signedSSO(test,env,HOST);
 if(!identity||identity.status!=="user"||!identity.email_verified)
  return output(403,{error:"SSO_ASSERTION_NOT_VERIFIED"});
 const age=Math.min(600,identity.exp-Math.floor(Date.now()/1000));
 if(age<=0)return output(403,{error:"SSO_ASSERTION_EXPIRED"});
 return output(200,{bound:true,expiresIn:age},{"Set-Cookie":cookie(assertion,age)});
}
