/** Bounded in-process benchmark: no listening socket, no live target, no remote
 * state, no origin fetch, no attack traffic, no environment credentials.
 * Only synthetic ordinary requests to the portable middleware are measured.
 */
import {performance} from "node:perf_hooks";
import {createPortableWaf} from "../src/vwaf-portable.js";
const host="vynalthai.com";
function fixture(n){
 const url="https://"+host;
 if(n%3===0)return new Request(url+"/api/health");
 if(n%3===1)return new Request(url+"/docs/example-"+(n%100));
 const body=JSON.stringify({prompt:"ordinary synthetic example "+(n%100),aspectRatio:"1:1"});
 return new Request(url+"/api/ai/image",{method:"POST",
  headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
}
const guard=createPortableWaf({hosts:[host],structuredMode:"enforce",maxContentInflight:16});
const next=async()=>new Response(null,{status:204});
const pct=(ordered,p)=>ordered[Math.max(0,Math.ceil(ordered.length*p)-1)];
async function run(concurrency,count){
 const observations=[];let index=0,errors=0;
 const start=performance.now();
 async function lane(){
  for(;;){
   const n=index++;if(n>=count)return;
   const request=fixture(n),t=performance.now();
   try{const r=await guard(request,next);if(r.status!==204)errors++;await r.body?.cancel()}
   catch{errors++}
   observations.push(performance.now()-t);
  }
 }
 await Promise.all(Array.from({length:concurrency},lane));
 const elapsedMs=performance.now()-start;
 observations.sort((a,b)=>a-b);
 return {concurrency,count,completed:observations.length,errors,p50Ms:pct(observations,.5),p95Ms:pct(observations,.95),
  p99Ms:pct(observations,.99),elapsedMs,requestsPerSecond:count/(elapsedMs/1000)};
}
const warmup=await run(1,120);
if(warmup.errors||warmup.completed!==120)throw Error("Local benchmark warmup failed");
const scenarios=[];
for(const concurrency of [1,4,8])scenarios.push(await run(concurrency,800));
const report={schema:"vwaf-portable-load-v1",runtime:process.version,scenarios,localTargetMet:scenarios.every(x=>x.p95Ms<5),
 productionQualified:false,limitations:"In-process portable middleware with synthetic origin, excludes Cloudflare isolate scheduling, remote state, origin network and real user traffic."};
console.log("VWAF_PORTABLE_LOAD "+JSON.stringify(report));
if(scenarios.some(x=>x.errors||x.completed!==x.count))process.exitCode=1;
