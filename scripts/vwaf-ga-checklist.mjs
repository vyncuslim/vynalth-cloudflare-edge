/** GA checklist structural validation. Ledger entries are reviewed records,
 * not independent proof; a source edit cannot replace signed/third-party evidence.
 */
import {readFileSync} from "node:fs";
export const REQUIRED_GATE_IDS=Object.freeze(["engine","network-ipv4-ipv6","owasp-top10","distributed-rate-limit","sqli-xss","api-schema","body-inspection","device-risk","intel-refresh","auto-containment","honeypot","evidence-integrity","real-time-notification","production-performance","independent-human-audit","cross-cloud","production-availability"]);
const statuses=new Set(["implemented","partial","blocked","qualified"]);
const httpsRef=value=>typeof value==="string"&&/^https:\/\/[^\s]+$/.test(value);
export function evaluateGaChecklist(ledger){
 if(ledger?.schema!=="vwaf-ga-checklist-v1"||ledger.release!=="2.0.0"||!Array.isArray(ledger.gates)||ledger.gates.length!==REQUIRED_GATE_IDS.length)
  throw Error("Incomplete GA checklist");
 const remaining=new Set(REQUIRED_GATE_IDS),qualified=[],open=[];
 for(const item of ledger.gates){
  if(!item||!remaining.delete(item.id)||!statuses.has(item.status)||typeof item.requirement!=="string"||!item.requirement.trim()||
   !Array.isArray(item.evidence)||item.evidence.some(x=>!httpsRef(x)))
   throw Error("Invalid or duplicate GA gate");
  if(item.status==="qualified"){
   if(!item.evidence.length||!httpsRef(item.review))throw Error("Qualified gate lacks evidence or review reference");
   qualified.push(item.id);
  }else open.push(item.id);
 }
 if(remaining.size)throw Error("Missing mandatory GA gates");
 return {total:REQUIRED_GATE_IDS.length,qualified:qualified.length,open,allRecordedQualified:open.length===0,
  limitation:"Ledger status is not independently verified evidence or publication authorization."};
}
export function readGaChecklist(){
 return evaluateGaChecklist(JSON.parse(readFileSync(new URL("../docs/vwaf-ga-checklist.json",import.meta.url),"utf8")));
}
