/**
 * RC6: offline, candidate-bound independent qualification evidence preflight.
 * Never fetches URLs, publishes releases, modifies the ledger or grants GA.
 * The trust object MUST be provisioned separately by an approved operator.
 * A signature authenticates an attestation, not the underlying measurements.
 */
import {createHash,createPublicKey,verify} from "node:crypto";
import {REQUIRED_GATE_IDS} from "./vwaf-ga-checklist.mjs";
const DAY=86400000, MAX_BYTES=256*1024;
const sha=v=>typeof v==="string"&&/^[a-f0-9]{40}$/.test(v);
const digest=v=>typeof v==="string"&&/^[a-f0-9]{64}$/.test(v);
const token=v=>typeof v==="string"&&v.length>0&&v.length<=128&&/^[A-Za-z0-9._:-]+$/.test(v);
const integer=v=>Number.isSafeInteger(v)&&v>=0;
const positive=v=>integer(v)&&v>0;
const check=(ok,message)=>{if(!ok)throw Error(message);};
const rate=(n,d)=>{check(integer(n)&&positive(d)&&n<=d,"Invalid count evidence");return n/d;};
function ref(r){
 check(r&&digest(r.sha256)&&typeof r.url==="string"&&r.url.length<=2048,"Invalid evidence reference");
 let u;try{u=new URL(r.url)}catch{throw Error("Invalid evidence reference");}
 check(u.protocol==="https:"&&!u.username&&!u.password&&!u.hash,"Invalid evidence reference");
}
export function verifyIndependentEvidence({payload,signature,trust,expectedCandidate,expectedDeployment,expectedScope,now=Date.now()}={}){
 check(Buffer.isBuffer(payload)&&payload.length>0&&payload.length<=MAX_BYTES,"Invalid evidence payload");
 check(Buffer.isBuffer(signature)&&signature.length===64,"Invalid Ed25519 signature");
 check(sha(expectedCandidate)&&token(expectedDeployment)&&token(expectedScope)&&integer(now),"Missing exact qualification context");
 check(trust&&token(trust.reviewerId)&&digest(trust.keySha256)&&typeof trust.publicKeyPem==="string"&&trust.publicKeyPem.length<=4096,"Approved trust anchor not configured");
 const key=createPublicKey(trust.publicKeyPem);
 check(key.asymmetricKeyType==="ed25519","Trust anchor must be Ed25519");
 const fp=createHash("sha256").update(key.export({type:"spki",format:"der"})).digest("hex");
 check(fp===trust.keySha256,"Trust anchor fingerprint mismatch");
 check(verify(null,payload,key,signature),"Evidence signature invalid");
 const m=JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(payload));
 check(m?.schema==="vwaf-independent-evidence-v1"&&m.release==="2.0.0"&&m.candidate===expectedCandidate&&
  m.deployment===expectedDeployment&&m.scope===expectedScope&&m.reviewerId===trust.reviewerId,"Evidence context mismatch");
 check(integer(m.issuedAt)&&integer(m.expiresAt)&&m.issuedAt<=now&&now<m.expiresAt&&
  m.expiresAt>m.issuedAt&&m.expiresAt-m.issuedAt<=90*DAY,"Evidence expired or invalid validity window");
 check(Array.isArray(m.controls)&&m.controls.length===REQUIRED_GATE_IDS.length,"Incomplete control attestation");
 const remaining=new Set(REQUIRED_GATE_IDS),open=[];
 for(const item of m.controls){
  check(item&&remaining.delete(item.id)&&typeof item.qualified==="boolean"&&Array.isArray(item.evidence)&&item.evidence.length>0&&item.evidence.length<=20,"Invalid control attestation");
  item.evidence.forEach(ref);if(!item.qualified)open.push(item.id);
 }
 check(remaining.size===0,"Missing mandatory control");
 const a=m.attack,b=m.benign,p=m.performance,v=m.availability,h=m.audit;
 check(a?.independent===true&&a.representative===true&&b?.independent===true&&b.representative===true,"Independent representative samples required");
 ref(a.evidence);ref(b.evidence);
 const attackRate=rate(a.blocked,a.tested),benignRate=rate(b.falsePositive,b.tested);
 check(p?.deployed===true&&positive(p.samples)&&typeof p.p95Ms==="number"&&Number.isFinite(p.p95Ms)&&p.p95Ms>=0,"Invalid deployed inspection evidence");
 ref(p.evidence);
 check(v?.independent===true&&v.endToEnd===true&&integer(v.start)&&integer(v.end)&&v.end<=m.issuedAt&&v.end-v.start>=30*DAY&&
  positive(v.intervalMs)&&v.intervalMs<=60000&&(v.end-v.start)%v.intervalMs===0,"Incomplete availability observation window");
 const slots=(v.end-v.start)/v.intervalMs;
 check(positive(slots)&&integer(v.healthy)&&integer(v.unhealthy)&&integer(v.missing)&&v.healthy+v.unhealthy+v.missing===slots,"Invalid availability accounting");
 ref(v.evidence);
 check(h?.independentHuman===true&&typeof h.completed==="boolean"&&integer(h.unfixedCritical),"Invalid independent audit attestation");
 ref(h.evidence);
 const goals={
  independentAttackHoldout:attackRate>=.99,
  representativeBenignFalsePositive:benignRate<.001,
  productionInspectionP95:p.p95Ms<5,
  productionAvailability:v.missing===0&&v.healthy/slots>=.9999,
  independentSecurityAudit:h.completed===true,
  zeroKnownUnfixedCritical:h.completed===true&&h.unfixedCritical===0,
  all17AttestedQualified:open.length===0
 };
 return {schema:"vwaf-independent-evidence-preflight-v1",candidate:m.candidate,deployment:m.deployment,scope:m.scope,
  reviewerId:m.reviewerId,payloadSha256:createHash("sha256").update(payload).digest("hex"),keySha256:fp,
  goals,open,attackRate,benignRate,availabilitySampleRate:v.healthy/slots,
  allAttestedThresholdsMet:Object.values(goals).every(Boolean),releaseAuthorized:false,
  limitation:"Authenticated reviewer attestation only; raw evidence provenance, reviewer independence, protected trust configuration, and actual release-gate integration require separate verification."};
}
