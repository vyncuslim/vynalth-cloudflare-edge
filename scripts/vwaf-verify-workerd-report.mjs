import {readFileSync} from "node:fs";
const report=JSON.parse(readFileSync(process.argv[2],"utf8"));
if(report.schema!=="vwaf-workerd-local-v1"||report.productionQualified!==false||
 !Array.isArray(report.scenarios)||report.scenarios.length!==3||
 report.completed!==true||report.timerUsable!==true)throw Error("Incomplete local runtime evidence");
for(let i=0;i<3;i++){
 const s=report.scenarios[i];
 if(s.concurrency!==[1,4,8][i]||s.count!==300||s.completed!==300||s.errors!==0||
 !Number.isInteger(s.nonzeroSamples)||s.nonzeroSamples<1||s.nonzeroSamples>300||
 !Number.isFinite(s.p95Ms)||s.p95Ms<=0||!Number.isFinite(s.p50Ms)||s.p50Ms<0||
 !Number.isFinite(s.p99Ms)||s.p50Ms>s.p95Ms||s.p95Ms>s.p99Ms)
  throw Error("Invalid local benchmark observations");
}
if(report.localTargetMet!==report.scenarios.every(x=>x.p95Ms<5))throw Error("Inconsistent local target");
console.log("VWAF_WORKERD_LOCAL "+JSON.stringify(report));
