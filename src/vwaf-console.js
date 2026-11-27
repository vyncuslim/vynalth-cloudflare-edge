/** VWAF Console: read-only, apex-only, dedicated bearer credential. */
import {stateCall} from "./vwaf-runtime.js";
const ROOT="/__ops/vwaf";
export function isWafConsolePath(url){return url.hostname==="vynalthai.com"&&[ROOT,ROOT+"/api/status"].includes(url.pathname)}
const headers={"Cache-Control":"private, no-store, max-age=0","X-Robots-Tag":"noindex, nofollow","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY"};
const json=(x,status=200)=>Response.json(x,{status,headers:{...headers,"Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'"}});
async function authorized(request,env){
 const expected=env?.VWAF_CONSOLE_TOKEN,value=request.headers.get("authorization")||"";
 if(typeof expected!=="string"||expected.length<43||expected.length>128||!/^Bearer [A-Za-z0-9_-]{43,128}$/.test(value))return false;
 const enc=new TextEncoder();const hash=async s=>new Uint8Array(await crypto.subtle.digest("SHA-256",enc.encode(s)));
 const [a,b]=await Promise.all([hash(value.slice(7)),hash(expected)]);let d=0;for(let i=0;i<a.length;i++)d|=a[i]^b[i];return d===0;
}
export async function handleWafConsole(request,env,url){
 if(!isWafConsolePath(url))return null;
 if(env?.VYNALTH_WAF_CONSOLE_ENABLED!=="true"||typeof env?.VWAF_CONSOLE_TOKEN!=="string"||env.VWAF_CONSOLE_TOKEN.length<43)return json({error:"NOT_FOUND"},404);
 if(request.method!=="GET")return json({error:"METHOD_NOT_ALLOWED"},405);
 if(url.search||request.headers.get("sec-fetch-site")==="cross-site")return json({error:"FORBIDDEN"},403);
 if(url.pathname===ROOT){
  const nonce=crypto.randomUUID().replace(/-/g,"");
  const page='<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Vynalth WAF Console</title><style nonce="'+nonce+'">body{font:16px system-ui;background:#111827;color:#e5e7eb;max-width:920px;margin:48px auto;padding:20px}h1{font-size:28px}input,button{padding:12px;border-radius:8px;margin:8px 0}input{width:min(80%,420px)}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1f2937;padding:20px;border-radius:10px}</style><h1>Vynalth WAF</h1><p>Private security decisions · read-only operator console</p><label for="token">Operator token</label><br><input id="token" type="password" autocomplete="off"><button id="load">Load status</button><pre id="out">Authentication required.</pre><script nonce="'+nonce+'">document.getElementById("load").onclick=async()=>{const t=document.getElementById("token");const out=document.getElementById("out");try{const token=t.value;t.value="";const r=await fetch("/__ops/vwaf/api/status",{headers:{Authorization:"Bearer "+token},cache:"no-store",credentials:"same-origin",redirect:"error"});const j=await r.json();out.textContent=JSON.stringify(j,null,2)}catch{out.textContent="Status unavailable."}};</script></html>';
  return new Response(page,{headers:{...headers,"Content-Type":"text/html; charset=utf-8","Content-Security-Policy":"default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"}});
 }
 if(!await authorized(request,env))return json({error:"UNAUTHORIZED"},401);
 try{const status=await stateCall(env,"ledger-v1",{op:"status"});if(!status)return json({error:"STATE_UNAVAILABLE"},503);
  return json({version:"1.1.0",coreMode:env.VYNALTH_WAF_MODE,stateMode:env.VYNALTH_WAF_STATE_MODE,content:env.VYNALTH_WAF_CONTENT_ENABLED==="true",...status});
 }catch{return json({error:"STATE_UNAVAILABLE"},503)}
}
