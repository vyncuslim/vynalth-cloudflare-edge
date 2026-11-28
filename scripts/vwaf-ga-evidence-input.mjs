/**
 * Release-only evidence input. The operator approves and protects a trust
 * file outside both checkout and evidence directory. No network or writes.
 */
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {constants,openSync,fstatSync,readSync,closeSync,lstatSync,realpathSync} from "node:fs";
import {join,relative,isAbsolute,sep} from "node:path";
import {fileURLToPath} from "node:url";
import {verifyIndependentEvidence} from "./vwaf-independent-evidence.mjs";
import {evaluateGaChecklist} from "./vwaf-ga-checklist.mjs";
const DAY=86400000, MB=1024*1024;
const hash=b=>createHash("sha256").update(b).digest("hex");
const check=(ok,msg)=>{if(!ok)throw Error(msg);};
const parse=b=>JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(b));
const inside=(root,path)=>{const p=relative(root,path);return p===""||(!isAbsolute(p)&&p!==".."&&!p.startsWith(".."+sep));};
function readBounded(path,max){
 // Open once and validate/read the same descriptor, not a separately checked path.
 // Protected parent directories remain an operator requirement.
 check(typeof constants.O_NOFOLLOW==="number"&&typeof constants.O_NONBLOCK==="number","Required safe file-open flags unavailable");
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const s=fstatSync(fd);
  check(s.isFile()&&s.size>0&&s.size<=max,"Missing, nonregular or oversized evidence file");
  const b=Buffer.alloc(s.size);let offset=0;
  while(offset<b.length){
   const n=readSync(fd,b,offset,b.length-offset,null);
   check(n>0,"Evidence truncated while reading");offset+=n;
  }
  const extra=Buffer.alloc(1);
  check(readSync(fd,extra,0,1,null)===0,"Evidence grew while reading");
  const after=fstatSync(fd);
  check(after.size===s.size&&after.mtimeMs===s.mtimeMs&&after.ctimeMs===s.ctimeMs,"Evidence changed while reading");
  return b;
 }finally{closeSync(fd);}
}
export function verifyReleaseBundle({bundleDir,trust,candidate,now=Date.now()}){
 check(trust?.schema==="vwaf-release-trust-v1"&&trust.approved===true&&trust.revoked===false&&trust.candidate===candidate&&
  Number.isSafeInteger(trust.validFrom)&&Number.isSafeInteger(trust.validUntil)&&trust.validFrom<=now&&now<trust.validUntil&&
  trust.validUntil-trust.validFrom<=90*DAY&&Number.isSafeInteger(trust.deployedAt)&&trust.deployedAt<=now,"Operator trust approval missing, expired or out of scope");
 const payload=readBounded(join(bundleDir,"attestation.json"),256*1024);
 const signature=readBounded(join(bundleDir,"attestation.sig"),64);
 const result=verifyIndependentEvidence({payload,signature,trust,expectedCandidate:candidate,
  expectedDeployment:trust.deployment,expectedScope:trust.scope,now});
 const m=parse(payload);
 check(m.availability.start>=trust.deployedAt&&m.issuedAt>=trust.validFrom,"Observation or attestation predates approved deployment or trust");
 const ledgerBytes=readBounded(join(bundleDir,"ledger.json"),256*1024);
 check(m.ledgerSha256===hash(ledgerBytes),"Signed ledger digest mismatch");
 const ledger=parse(ledgerBytes),qualification=evaluateGaChecklist(ledger);
 const signed=new Map(m.controls.map(x=>[x.id,x]));
 const refs=[m.attack.evidence,m.benign.evidence,m.performance.evidence,m.availability.evidence,m.audit.evidence,m.review];
 for(const item of ledger.gates){
  const a=signed.get(item.id);
  check((item.status==="qualified")===a.qualified,"Recorded qualification differs from signed control");
  const urls=new Set(a.evidence.map(r=>r.url));
  check(item.evidence.length===urls.size&&new Set(item.evidence).size===urls.size&&item.evidence.every(u=>urls.has(u)),"Ledger evidence differs from signed control");
  if(a.qualified)check(item.review===m.review?.url,"Ledger review differs from signed review");
  refs.push(...a.evidence);
 }
 const artifactRoot=join(bundleDir,"artifacts");
 check(lstatSync(artifactRoot).isDirectory()&&!lstatSync(artifactRoot).isSymbolicLink(),"Invalid artifact directory");
 let total=0;const seen=new Set();
 for(const r of refs){
  check(r&&typeof r.sha256==="string"&&/^[a-f0-9]{64}$/.test(r.sha256)&&typeof r.url==="string"&&r.url.length<=2048,"Invalid signed artifact reference");
  const url=new URL(r.url);check(url.protocol==="https:"&&!url.username&&!url.password&&!url.hash,"Invalid evidence URL");
  if(seen.has(r.sha256))continue;
  const bytes=readBounded(join(artifactRoot,r.sha256),16*MB);
  total+=bytes.length;check(total<=128*MB,"Evidence bundle exceeds aggregate limit");
  check(hash(bytes)===r.sha256,"Referenced evidence digest mismatch");seen.add(r.sha256);
 }
 return {qualification,goals:result.goals,summary:{state:"verified-attestation",candidate,reviewerId:result.reviewerId,
  payloadSha256:result.payloadSha256,artifactCount:seen.size,allAttestedThresholdsMet:result.allAttestedThresholdsMet,
  limitation:"Protected operator trust and reviewer assessment remain necessary; matching artifact hashes do not independently prove the measurements."}};
}
export function readReleaseEvidence({env=process.env,now=Date.now(),repoRoot=fileURLToPath(new URL("../",import.meta.url))}={}){
 if(!env.VWAF_GA_BUNDLE_DIR&&!env.VWAF_GA_TRUST_FILE)return null;
 check(env.VWAF_GA_BUNDLE_DIR&&env.VWAF_GA_TRUST_FILE&&isAbsolute(env.VWAF_GA_BUNDLE_DIR)&&isAbsolute(env.VWAF_GA_TRUST_FILE),"Incomplete absolute evidence paths");
 const root=realpathSync(repoRoot),bundleDir=realpathSync(env.VWAF_GA_BUNDLE_DIR),trustFile=realpathSync(env.VWAF_GA_TRUST_FILE);
 check(!inside(root,bundleDir)&&!inside(root,trustFile)&&!inside(bundleDir,trustFile),"Trust and evidence must be external and separate from checkout");
 const candidate=execFileSync("git",["rev-parse","HEAD"],{cwd:root,encoding:"utf8",timeout:5000}).trim();
 const dirty=execFileSync("git",["status","--porcelain","--untracked-files=no"],{cwd:root,encoding:"utf8",timeout:5000}).trim();
 check(!dirty,"Tracked candidate checkout is modified");
 const trust=parse(readBounded(trustFile,16*1024));
 return verifyReleaseBundle({bundleDir,trust,candidate,now});
}
