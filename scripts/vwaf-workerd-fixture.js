/** Local-only workerd qualification fixture. Never deploy this module.
 * All inputs and the origin are synthetic; no outbound calls, bindings,
 * user data, or traffic against deployed endpoints.
 */
import {createPortableWaf} from "../src/vwaf-portable.js";
const host="vynalthai.com";
function fixture(n){
 if(n%3===0)return new Request("https://"+host+"/api/health");
 if(n%3===1)return new Request("https://"+host+"/docs/example-"+(n%100));
 const body=JSON.stringify({prompt:"ordinary synthetic example "+(n%100),aspectRatio:"1:1"});
 return new Request("https://"+host+"/api/ai/image",{method:"POST",
  headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
}
const next=async()=>new Response(null,{status:204});
const pct=(a,p)=>a[Math.max(0,Math.ceil(a.length*p)-1)];
async function scenario(guard,concurrency,count){
 let index=0,errors=0;const observations=[];
 async function lane(){
  for(;;){
   const n=index++;if(n>=count)return;
   const request=fixture(n),t=performance.now();
   try{const r=await guard(request,next);if(r.status!==204)errors++;await r.body?.cancel()}catch{errors++}
   observations.push(performance.now()-t);
  }
 }
 await Promise.all(Array.from({length:concurrency},lane));
 observations.sort((a,b)=>a-b);
 return {concurrency,count,completed:observations.length,errors,p50Ms:pct(observations,.5),p95Ms:pct(observations,.95),
  p99Ms:pct(observations,.99),nonzeroSamples:observations.filter(x=>x>0).length};
}
export default {async fetch(request){
 const path=new URL(request.url).pathname;
 if(request.method==="GET"&&path==="/ready")return new Response("vwaf-workerd-local-ready");
 if(request.method!=="GET"||path!=="/benchmark")return new Response(null,{status:404});
 const guard=createPortableWaf({hosts:[host],structuredMode:"enforce",maxContentInflight:16});
 const warmup=await scenario(guard,1,120);
 const scenarios=[];
 for(const concurrency of [1,4,8])scenarios.push(await scenario(guard,concurrency,300));
 const timerUsable=scenarios.every(x=>x.nonzeroSamples>0&&Number.isFinite(x.p95Ms)&&x.p95Ms>0);
 const completed=warmup.errors===0&&warmup.completed===warmup.count&&scenarios.every(x=>x.errors===0&&x.completed===x.count);
 return Response.json({schema:"vwaf-workerd-local-v1",scenarios,timerUsable,completed,
  localTargetMet:timerUsable&&completed&&scenarios.every(x=>x.p95Ms<5),productionQualified:false,
  limitation:"Local workerd wall-clock measurement with synthetic origin; no remote state, deployed profiling, or production traffic."});
}};
