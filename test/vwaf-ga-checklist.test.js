import test from "node:test";
import assert from "node:assert/strict";
import {evaluateGaChecklist,REQUIRED_GATE_IDS,readGaChecklist} from "../scripts/vwaf-ga-checklist.mjs";
const fixture=()=>({schema:"vwaf-ga-checklist-v1",release:"2.0.0",gates:REQUIRED_GATE_IDS.map(id=>({id,status:"implemented",requirement:"synthetic",evidence:[],review:null}))});
test("all 17 mandatory IDs are required; implementation is not qualification",()=>{
 const x=fixture(),r=evaluateGaChecklist(x);
 assert.equal(r.total,17);assert.equal(r.qualified,0);assert.equal(r.allRecordedQualified,false);
 x.gates.pop();assert.throws(()=>evaluateGaChecklist(x));
 const d=fixture();d.gates[1].id=d.gates[0].id;assert.throws(()=>evaluateGaChecklist(d));
});
test("no qualified status without evidence and a review reference",()=>{
 const x=fixture();x.gates[0].status="qualified";
 assert.throws(()=>evaluateGaChecklist(x),/lacks evidence/);
 x.gates[0].evidence=["https://example.invalid/synthetic"];assert.throws(()=>evaluateGaChecklist(x));
 x.gates[0].review="https://example.invalid/synthetic-review";
 assert.equal(evaluateGaChecklist(x).allRecordedQualified,false);
});
test("checked-in ledger is structurally complete",()=>{
 assert.equal(readGaChecklist().total,17);
});
