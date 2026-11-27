/**
 * Static retired-operations namespace. This is a decoy, not an admin service.
 * No body, Authorization, cookie, credentials or query processing; no origin.
 */
import {recordEvent} from "./vwaf-runtime.js";
const ROOT="/__ops/vwaf";
export function isWafHoneypotPath(url){
 if(url.hostname!=="vynalthai.com")return false;
 let p=url.pathname;
 for(let i=0;i<3;i++){
  const v=p.toLowerCase().replace(/\\/g,"/").replace(/\/{2,}/g,"/");
  if(v===ROOT||v.startsWith(ROOT+"/")||v.startsWith(ROOT+";"))return true;
  if(i===2||p.length>8192)break;
  try{const d=decodeURIComponent(p);if(d===p)break;p=d}catch{break}
 }
 return false;
}
export function handleWafHoneypot(request,env,url,ctx,id,emit=recordEvent){
 if(!isWafHoneypotPath(url))return null;
 // Even with collection off, the former namespace is tombstoned forever.
 if(env?.VYNALTH_WAF_HONEYPOT_ENABLED==="true"){
  try{emit(env,ctx,{host:url.hostname,mode:"observe",action:"honeypot",request_id:id,rule_ids:["VWAF-501"],score:10})}catch{}
 }
 return new Response(request.method==="HEAD"?null:"Resource unavailable.",{status:404,headers:{
  "Content-Type":"text/plain; charset=utf-8","Cache-Control":"private, no-store, max-age=0","X-Robots-Tag":"noindex, nofollow",
  "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY",
  "Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'"
 }});
}
