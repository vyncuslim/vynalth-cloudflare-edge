/** Monotonic client timing of fixed local loopback requests. Not WAF CPU time. */
import {writeFileSync} from "node:fs";
import {performance} from "node:perf_hooks";
const base="http://127.0.0.1:18765",ordinary=["/case/health","/case/docs","/case/image","/case/image-unframed"];
async function request(path,expected){
 const r=await fetch(base+path,{method:"GET",redirect:"error",signal:AbortSignal.timeout(3000)});
 await r.arrayBuffer();
 return r.status===expected;
}
const preflight=await Promise.all([request("/case/image-invalid",400),request("/case/image-unframed-invalid",400),...ordinary.map(p=>request(p,204))]);
const pct=(a,p)=>a[Math.max(0,Math.ceil(a.length*p)-1)];
async function scenario(concurrency,count){
 let index=0,errors=0;const timings=[];
 async function lane(){
  for(;;){
   const n=index++;if(n>=count)return;
   const t=performance.now();
   try{if(!await request(ordinary[n%ordinary.length],204))errors++}catch{errors++}
   timings.push(performance.now()-t);
  }
 }
 await Promise.all(Array.from({length:concurrency},lane));
 timings.sort((a,b)=>a-b);
 return {concurrency,count,completed:timings.length,errors,p50Ms:pct(timings,.5),p95Ms:pct(timings,.95),
  p99Ms:pct(timings,.99),nonzeroSamples:timings.filter(x=>x>0).length};
}
const warmup=await scenario(1,120),scenarios=[];
for(const concurrency of [1,4,8])scenarios.push(await scenario(concurrency,300));
const timerUsable=scenarios.every(x=>x.nonzeroSamples===x.count&&Number.isFinite(x.p95Ms)&&x.p95Ms>0);
const completed=preflight.every(Boolean)&&warmup.errors===0&&warmup.completed===120&&scenarios.every(x=>x.errors===0&&x.completed===x.count);
const report={schema:"vwaf-workerd-loopback-v2",measurement:"client_monotonic_round_trip",preflightPassed:preflight.filter(Boolean).length,preflightTotal:preflight.length,
 scenarios,timerUsable,completed,localRoundTripTargetMet:timerUsable&&completed&&scenarios.every(x=>x.p95Ms<5),productionQualified:false,
 limitation:"Local loopback round trip includes HTTP and scheduling overhead; synthetic origin, no remote state, no deployed CPU profiling."};
writeFileSync(process.argv[2],JSON.stringify(report,null,2)+"\n");
