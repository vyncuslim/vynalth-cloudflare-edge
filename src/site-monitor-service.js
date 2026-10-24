// Signed internal telemetry from the vv apex Worker. This must never proxy to
// vyncuslim.com; the apex belongs to vv, not this Worker.
import { inspectHoneypotRequest, captureAccessTelemetry, honeypotType, passiveProbeType } from "./security-monitor.js";
const PREFIX="x-vynalth-site-monitor-";
const ENCODER=new TextEncoder();
const SIGNED_KEYS=["v","ts","kind","status","duration","sig"];
function response(status,label){
 return new Response(null,{status,headers:{"Cache-Control":"no-store","X-Vynalth-Site-Monitor":label}});
}
function signatureInput(ts,kind,method,url,status,duration){
 return ["site-monitor-v1",ts,kind,method,url,status,duration].join("\n");
}
function hexBytes(s){
 if(!/^[0-9a-f]{64}$/.test(s||""))return null;
 return new Uint8Array(s.match(/../g).map(x=>parseInt(x,16)));
}
async function verified(request,env,url){
 const secret=env?.GPS_SERVICE_AUTH_SECRET;
 if(env?.SITE_MONITOR_SERVICE_ENABLED!=="true"||typeof secret!=="string"||secret.length<32)return false;
 if(!["vyncuslim.com","www.vyncuslim.com"].includes(url.hostname)||url.protocol!=="https:"||
    url.search||url.hash)return false;
 const h=request.headers;
 if(h.get(PREFIX+"v")!=="1")return false;
 const ts=h.get(PREFIX+"ts"),kind=h.get(PREFIX+"kind"),
  status=h.get(PREFIX+"status"),duration=h.get(PREFIX+"duration"),sig=h.get(PREFIX+"sig");
 if(!/^\d{10}$/.test(ts||"")||Math.abs(Math.floor(Date.now()/1000)-Number(ts))>60||
    !["trap","probe","access"].includes(kind)||!/^(?:0|[2-5]\d\d)$/.test(status||"")||
    !/^(?:0|[1-9]\d{0,4})$/.test(duration||"")||Number(duration)>60000)return false;
 if(kind==="trap"&&!honeypotType(url.pathname))return false;
 if(kind==="probe"&&!passiveProbeType(url.pathname))return false;
 if(kind==="access"&&(status==="0"||url.pathname.startsWith("/__vynalth-hp/")))return false;
 if(kind!=="access"&&(status!=="0"||duration!=="0"))return false;
 const signature=hexBytes(sig);
 if(!signature)return false;
 const key=await crypto.subtle.importKey("raw",ENCODER.encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["verify"]);
 return crypto.subtle.verify("HMAC",key,signature,ENCODER.encode(
  signatureInput(ts,kind,request.method,url.origin+url.pathname,status,duration)));
}
export async function handleSignedVvMonitor(request,env,ctx){
 const headers=request.headers;
 const hasMarker=[...headers.keys()].some(x=>x.toLowerCase().startsWith(PREFIX));
 if(!hasMarker)return null;
 const url=new URL(request.url);
 let accepted=false;
 try{accepted=await verified(request,env,url);}catch{accepted=false;}
 if(!accepted)return response(403,"invalid-service-auth");
 const kind=headers.get(PREFIX+"kind");
 // No origin, GPS or browser authentication handling: internal telemetry only.
 const safeHeaders=new Headers();
 const synthetic=new Request(url.origin+url.pathname,{method:request.method,headers:safeHeaders});
 const requestId=crypto.randomUUID(); // Never trust a request ID from the browser.
 if(kind==="trap"||kind==="probe"){
  const trap=await inspectHoneypotRequest(synthetic,env,ctx,requestId);
  if(kind==="trap"){
   // Even without Axiom configured, never expose a decoy at the origin.
   if(trap)return new Response(trap.body,{status:404,headers:{
    ...Object.fromEntries(trap.headers),"X-Vynalth-Site-Monitor":"decoy"}});
   return response(404,"decoy-unlogged");
  }
  return response(204,"observed");
 }
 if(kind==="access"){
  const status=Number(headers.get(PREFIX+"status"));
  const duration=Number(headers.get(PREFIX+"duration"));
  captureAccessTelemetry(synthetic,new Response(null,{status}),{
   ...env,SECURITY_ACCESS_SAMPLE_RATE:"1"
  },ctx,requestId,Date.now()-duration);
  return response(204,"observed");
 }
 return response(403,"invalid-kind");
}
