/**
 * Aggregate external scanner output without publishing actionable finding details
 * in a public CI log. No suppressions, no synthetic result, fail on incomplete input.
 */
import {readdir,readFile} from "node:fs/promises";
import {join} from "node:path";
const mode=process.argv[2],target=process.argv[3];
if(!target||!["codeql","npm"].includes(mode)){console.error("Invalid audit arguments.");process.exit(2)}
try{
 if(mode==="npm"){
  const x=JSON.parse(await readFile(target,"utf8")),v=x.metadata?.vulnerabilities;
  if(x.error||!v||!["info","low","moderate","high","critical","total"].every(k=>Number.isInteger(v[k])&&v[k]>=0))throw Error("Incomplete audit result");
  console.log("VWAF_EXTERNAL_AUDIT "+JSON.stringify({scanner:"npm audit",counts:v,pass:v.high===0&&v.critical===0,scope:"resolved production and development dependency tree"}));
  if(v.high||v.critical)process.exitCode=1;
 }else{
  const files=(await readdir(target,{recursive:true})).filter(p=>p.endsWith(".sarif"));
  if(!files.length)throw Error("Missing SARIF");
  let runs=0,total=0,high=0,critical=0,unclassified=0;
  for(const file of files){
   const x=JSON.parse(await readFile(join(target,file),"utf8"));
   if(!Array.isArray(x.runs)||!x.runs.length)throw Error("Missing runs");
   for(const r of x.runs){
    if(!/CodeQL/i.test(r.tool?.driver?.name||"")||!Array.isArray(r.results))throw Error("Invalid scan output");
    if(r.invocations?.some(i=>i.executionSuccessful===false))throw Error("Unsuccessful scan");
    runs++;
    const rules=r.tool?.driver?.rules||[];
    const byId=new Map(rules.map(q=>[q.id,q]));
    for(const finding of r.results){
     total++;
     const rule=byId.get(finding.ruleId)||rules[finding.ruleIndex];
     const raw=rule?.properties?.["security-severity"];
     const s=typeof raw==="string"&&raw.trim()!==""?Number(raw):typeof raw==="number"?raw:NaN;
     if(Number.isFinite(s)&&s>=0&&s<=10){if(s>=9)critical++;else if(s>=7)high++}
     else if((rule?.properties?.tags||[]).includes("security"))unclassified++;
    }
   }
  }
  if(!runs)throw Error("No completed analysis");
  console.log("VWAF_EXTERNAL_AUDIT "+JSON.stringify({scanner:"GitHub CodeQL",runs,total,high,critical,unclassifiedSecurity:unclassified,pass:high===0&&critical===0&&unclassified===0,scope:"JavaScript/TypeScript static analysis; not human penetration audit"}));
  if(high||critical||unclassified)process.exitCode=1;
 }
}catch{console.error("External scanner output missing, failed or incomplete.");process.exitCode=2}
