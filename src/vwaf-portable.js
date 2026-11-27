/** Portable Fetch middleware. No Cloudflare globals, outbound calls or credentials. */
import {applyVynalthWaf,CORE_HOSTS} from "./vynalth-waf-core.js";
import {inspectWafContent,isWafContentCandidate} from "./vwaf-content.js";
import {schemaResponse} from "./vwaf-schema.js";
import {sanitizeEvent} from "./vwaf-policy.js";
export function createPortableWaf({hosts,mode="enforce",schemaMode="enforce",structuredMode="observe",onEvent=()=>{},maxContentInflight=16,allowUnframedContent=false}={}){
 if(!Array.isArray(hosts)||!hosts.length||hosts.some(h=>!CORE_HOSTS.includes(h))||
  !["observe","enforce"].includes(mode)||!["observe","enforce"].includes(schemaMode)||!["observe","enforce"].includes(structuredMode)||
  typeof allowUnframedContent!=="boolean"||!Number.isInteger(maxContentInflight)||maxContentInflight<1||maxContentInflight>64)throw Error("Invalid explicit VWAF configuration");
 const allowed=new Set(hosts),env={VYNALTH_WAF_MODE:mode,VYNALTH_WAF_HOSTS:[...allowed].join(","),VYNALTH_WAF_STRUCTURED_MODE:structuredMode};
 const contentOptions={allowUnframed:allowUnframedContent};
 let inflight=0;
 function emit(event){const safe=sanitizeEvent(event);if(safe)try{onEvent(safe)}catch{}}
 return async function guard(request,next){
  const host=new URL(request.url).hostname,id=crypto.randomUUID();
  if(!allowed.has(host))return new Response("Unrecognized host.",{status:421,headers:{"Cache-Control":"no-store"}});
  const denied=applyVynalthWaf(request,env,id,emit);if(denied)return denied;
  if(inflight<maxContentInflight&&isWafContentCandidate(request,contentOptions)){
   inflight++;
   try{
    const signals=await inspectWafContent(request,contentOptions);
    const reject=schemaResponse(request,signals,mode==="enforce"?schemaMode:"observe");
    if(signals.length)emit({host,mode,action:reject?"block":"observe",request_id:id,
     rule_ids:signals.map(x=>x.id),score:Math.min(100,signals.reduce((n,s)=>n+s.score,0))});
    if(reject)return reject;
   }finally{inflight--}
  }
  // The embedding application owns authentication, authorization, origin
  // validation, network reputation, distributed state and traffic shaping.
  return next(request);
 };
}
