import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createHash,sign} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {verifyReleaseBundle,readReleaseEvidence} from "../scripts/vwaf-ga-evidence-input.mjs";
import {REQUIRED_GATE_IDS} from "../scripts/vwaf-ga-checklist.mjs";
const hash=b=>createHash("sha256").update(b).digest("hex");
const now=Date.UTC(2026,10,28),candidate="a".repeat(40),day=86400000;
function fixture(t){
 const dir=mkdtempSync(join(tmpdir(),"vwaf-evidence-test-"));t.after(()=>rmSync(dir,{recursive:true,force:true}));
 mkdirSync(join(dir,"artifacts"));
 const {publicKey,privateKey}=generateKeyPairSync("ed25519");
 const trust={schema:"vwaf-release-trust-v1",approved:true,revoked:false,candidate,deployment:"test-deployment",scope:"test-scope",reviewerId:"test-only",publicKeyPem:publicKey.export({type:"spki",format:"pem"}),keySha256:hash(publicKey.export({type:"spki",format:"der"})),validFrom:now-40*day,validUntil:now+day,deployedAt:now-31*day};
 const bytes=Buffer.from("Synthetic test-only evidence, never a real audit.");
 const evidence={url:"https://example.invalid/test-only",sha256:hash(bytes)};
 const artifact=join(dir,"artifacts",evidence.sha256);writeFileSync(artifact,bytes);
 const ledger={schema:"vwaf-ga-checklist-v1",release:"2.0.0",gates:REQUIRED_GATE_IDS.map(id=>({id,status:"qualified",requirement:"test fixture only",evidence:[evidence.url],review:evidence.url}))};
 const ledgerBytes=Buffer.from(JSON.stringify(ledger));writeFileSync(join(dir,"ledger.json"),ledgerBytes);
 const m={schema:"vwaf-independent-evidence-v1",release:"2.0.0",candidate,deployment:trust.deployment,scope:trust.scope,reviewerId:trust.reviewerId,issuedAt:now-1,expiresAt:now+1000,ledgerSha256:hash(ledgerBytes),review:evidence,controls:REQUIRED_GATE_IDS.map(id=>({id,qualified:true,evidence:[evidence]})),attack:{independent:true,representative:true,blocked:990,tested:1000,evidence},benign:{independent:true,representative:true,falsePositive:0,tested:4000,evidence},performance:{deployed:true,samples:1000,p95Ms:4.9,evidence},availability:{independent:true,endToEnd:true,start:now-30*day-1,end:now-1,intervalMs:60000,healthy:43200,unhealthy:0,missing:0,evidence},audit:{independentHuman:true,completed:true,unfixedCritical:0,evidence}};
 const save=()=>{const b=Buffer.from(JSON.stringify(m));writeFileSync(join(dir,"attestation.json"),b);writeFileSync(join(dir,"attestation.sig"),sign(null,b,privateKey))};save();
 return {args:{bundleDir:dir,trust,candidate,now},dir,artifact,m,save};
}
test("test-only signed bundle verifies all recorded thresholds and artifacts",t=>{
 const f=fixture(t),r=verifyReleaseBundle(f.args);
 assert.equal(r.qualification.qualified,17);assert.equal(r.summary.artifactCount,1);assert.equal(r.summary.allAttestedThresholdsMet,true);
});
test("missing or altered evidence artifact is rejected",t=>{
 const f=fixture(t);writeFileSync(f.artifact,"changed");assert.throws(()=>verifyReleaseBundle(f.args),/digest mismatch/);
 rmSync(f.artifact);assert.throws(()=>verifyReleaseBundle(f.args));
});
test("ledger changes cannot pass without signed digest",t=>{
 const f=fixture(t);writeFileSync(join(f.dir,"ledger.json"),"{}");assert.throws(()=>verifyReleaseBundle(f.args),/ledger digest mismatch/);
});
test("revoked, expired or mismatched trust is rejected",t=>{
 const f=fixture(t);for(const patch of [{revoked:true},{validUntil:now},{candidate:"b".repeat(40)},{deployedAt:now-29*day}]){
  assert.throws(()=>verifyReleaseBundle({...f.args,trust:{...f.args.trust,...patch}}));
 }
});
test("absence or partial configuration does not qualify",()=>{
 assert.equal(readReleaseEvidence({env:{}}),null);
 assert.throws(()=>readReleaseEvidence({env:{VWAF_GA_BUNDLE_DIR:"/example"}}),/Incomplete/);
});
