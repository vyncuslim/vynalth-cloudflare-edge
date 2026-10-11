/* Protected Jingxin photos. Draft only: originals must be removed from
 * any public Vercel/static/CDN origin BEFORE enabling in production.
 * Uses existing Worker and a *private* R2 bucket. Never redirects to
 * an unauthenticated public asset URL or uses JavaScript-only controls.
 */
import { signedSSO, TRUSTED_STATUSES } from "./universal-consent.js";
import { gpsOutsideOrLegacyExempt } from "./guest-gps.js";

const PHOTO_HOST="vyncuslim.com";
const MEDIA_PREFIX="/media/jingxin/";
const PHOTO_KEYS=Object.freeze({
 "shared-memory.jpg":{key:"jingxin/shared-memory.jpg",type:"image/jpeg"},
 "mce-kuala-lumpur-real.webp":{key:"jingxin/mce-kuala-lumpur-real.webp",type:"image/webp"}
});
const common={
 "Cache-Control":"private, no-store, max-age=0",
 "X-Content-Type-Options":"nosniff",
 "Cross-Origin-Resource-Policy":"same-origin",
 "Referrer-Policy":"no-referrer",
 "Vary":"Cookie"
};
function response(status,payload,headers={}){
 return new Response(JSON.stringify(payload),{status,headers:{
  ...common,"Content-Type":"application/json; charset=utf-8",...headers
 }});
}
function recognizedHost(host){
 return host===PHOTO_HOST||host.endsWith("."+PHOTO_HOST);
}
async function photoAuthorized(request,env,root,hostname){
 const identity=await signedSSO(request,env,root);
 if(identity&&TRUSTED_STATUSES.has(identity.status))return true;
 return gpsOutsideOrLegacyExempt(request,env,hostname);
}
export async function handleJingxinMedia(request,env,url,root){
 const isPhoto=url.pathname.startsWith(MEDIA_PREFIX);
 const isStatus=url.pathname==="/jingxin/access-status";
 if(!isPhoto&&!isStatus)return null;
 // Staged rollout: merging the Worker must NOT intercept existing public
 // image routes while private storage migration is incomplete.
 // Once explicitly enabled, missing R2 config fails CLOSED.
 if(env?.JINGXIN_PRIVATE_MEDIA_ENABLED!=="true")return null;
 if(!recognizedHost(url.hostname)||root!==PHOTO_HOST)
  return response(404,{error:"NOT_FOUND"});
 if(request.method!=="GET"&&request.method!=="HEAD")
  return response(405,{error:"METHOD_NOT_ALLOWED"},{Allow:"GET, HEAD"});
 // When explicitly enabled, a missing R2 bucket never exposes origin.
 const configured=typeof env?.JINGXIN_PRIVATE_MEDIA_R2?.get==="function";
 let authorized=false;
 if(configured){
  try{authorized=await photoAuthorized(request,env,root,url.hostname);}
  catch{authorized=false;}
 }
 if(isStatus){
  const state={blocked:!configured||!authorized,
   reason:!configured?"unavailable":authorized?"none":"verification-required",
   source:"vynalth-edge-private-media"};
  return response(200,state);
 }
 const name=url.pathname.slice(MEDIA_PREFIX.length);
 if(!Object.hasOwn(PHOTO_KEYS,name))
  return response(404,{error:"PHOTO_NOT_FOUND"});
 if(!configured)return response(503,{error:"PRIVATE_MEDIA_NOT_CONFIGURED"});
 if(!authorized)return response(403,{error:"PHOTO_VERIFICATION_REQUIRED"});
 // No public origin fallback, even on R2 failures.
 try{
  const item=PHOTO_KEYS[name],obj=await env.JINGXIN_PRIVATE_MEDIA_R2.get(item.key);
  if(!obj)return response(404,{error:"PHOTO_NOT_FOUND"});
  const headers={...common,"Content-Type":item.type,
   "Content-Disposition":"inline",
   "X-Frame-Options":"DENY"};
  // HEAD makes no sensitive content request-body exposure.
  return new Response(request.method==="HEAD"?null:obj.body,{
   status:200,headers
  });
 }catch{
  return response(503,{error:"PRIVATE_MEDIA_TEMPORARILY_UNAVAILABLE"});
 }
}
