import test from "node:test";
import assert from "node:assert/strict";
import {summarizeAvailability} from "../scripts/vwaf-availability-evidence.mjs";
const start=1800000000000,intervalMs=60000,checks=["main","search"];
const config={start,end:start+3*intervalMs,intervalMs,checks};
test("missing and conflicting probes cannot inflate a sampled SLI",()=>{
 const observations=[{at:start,check:"main",healthy:true},{at:start,check:"search",healthy:true},
  {at:start+intervalMs,check:"main",healthy:true},{at:start+intervalMs,check:"search",healthy:false},
  {at:start+intervalMs+1,check:"search",healthy:true},{at:start+2*intervalMs,check:"main",healthy:true}];
 const r=summarizeAvailability(observations,config);
 assert.equal(r.healthy,1);assert.equal(r.unhealthy,1);assert.equal(r.missing,1);
 assert.equal(r.conservativeSampleRate,1/3);assert.equal(r.sampledTargetMet,false);
 assert.equal(r.productionAvailabilityCertified,false);
});
test("30-day synthetic sample coverage retains exact observation window",()=>{
 const end=start+30*86400000,slots=(end-start)/intervalMs,observations=[];
 for(let i=0;i<slots;i++)for(const check of checks)observations.push({at:start+i*intervalMs,check,healthy:i>=4});
 const r=summarizeAvailability(observations,{...config,end});
 assert.equal(r.slots,43200);assert.equal(r.unhealthy,4);assert.equal(r.sampledTargetMet,true);
 assert.equal(r.productionAvailabilityCertified,false);
 observations.pop();
 assert.equal(summarizeAvailability(observations,{...config,end}).sampledTargetMet,false);
});
test("invalid evidence is rejected",()=>{
 assert.throws(()=>summarizeAvailability([{at:start,check:"unknown",healthy:true}],config));
 assert.throws(()=>summarizeAvailability([],{...config,end:start+1}));
});
