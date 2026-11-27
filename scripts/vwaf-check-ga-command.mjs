/** Verify the actual GA CLI agrees with the reported gates; no publish action. */
import {spawnSync} from "node:child_process";
import {fileURLToPath} from "node:url";
const result=spawnSync(process.execPath,[fileURLToPath(new URL("./vwaf-acceptance.mjs",import.meta.url)),"--release"],{encoding:"utf8",timeout:30000,maxBuffer:1024*1024});
if(result.error||result.signal)throw Error("GA command execution incomplete");
const lines=(result.stdout||"").split(/\r?\n/).filter(x=>x.startsWith("VWAF_ACCEPTANCE "));
if(lines.length!==1)throw Error("GA report missing or ambiguous");
const report=JSON.parse(lines[0].slice("VWAF_ACCEPTANCE ".length));
if(report.gaChecklist?.total!==17||typeof report.gaChecklist.allRecordedQualified!=="boolean"||
 !report.goals||!Object.hasOwn(report.goals,"all17RecordedQualified")||
 !Object.hasOwn(report.goals,"productionAvailability")||!Object.hasOwn(report.goals,"independentSecurityAudit"))
 throw Error("GA report missing mandatory conditions");
if(report.regressions!==0||report.benign?.falsePositive!==0||result.status===1)
 throw Error("Acceptance regression; not a valid qualification result");
const expected=Object.values(report.goals).every(x=>x===true)?0:2;
if(result.status!==expected)throw Error("GA command exit status does not match evidence");
console.log("VWAF_GA_GATE_CHECK "+JSON.stringify({exitStatus:result.status,qualified:report.gaChecklist.qualified,total:17,
 publicationAllowedByOfflineCommand:result.status===0,blockedBy:Object.entries(report.goals).filter(([,v])=>v!==true).map(([k])=>k)}));
