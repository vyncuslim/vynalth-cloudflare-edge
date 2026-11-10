import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { guestGpsGate, gpsOutsideOrLegacyExempt } from "./guest-gps.js";
import { BUTTERWORTH_PROOF_COOKIE, BUTTERWORTH_PROOF_TTL,
  inApproximateButterworth, isAmbiguousIpRecoveryEligible, hasButterworthProof, inspectButterworthProof, MISLOCATED_OUTSIDE_KIND, BUTTERWORTH_PROOF_KIND } from "./gps-butterworth-proof.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const HOST="vynalthai.com";
const IP="8.8.8.8";
const ENV={
 GPS_GATE_ENABLED:"true",GPS_PENANG_ONLY_ENABLED:"true",
 GPS_BUTTERWORTH_PROOF_ENABLED:"true",GPS_OUTSIDE_SESSION_FASTPASS:"true",
 GPS_GATE_SESSION_SECRET:"gps-butterworth-test-hmac-secret-must-be-32-chars-or-more",
 GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",GPS_CAMPUS_RADIUS_METERS:"120"
};
const cf={country:"MY",region:"Penang",regionCode:"07",city:"Tasek Glugor"};
function request(host=HOST,path="/private",method="GET",headers={},body,clientIp=IP,metadata=cf){
 const url=new URL("https://"+host+path);
 const req=new Request(url,{method,headers:{"CF-Connecting-IP":clientIp,...headers},body});
 Object.defineProperty(req,"cf",{value:metadata});
 return req;
}
const gate=(r,env=ENV)=>guestGpsGate(r,env,new URL(r.url));
async function verify(lat,lon,accuracy=20,headers={},env=ENV,recoveryRequested=false){
 const r=request(HOST,"/__shield/gps/verify","POST",{
  Origin:"https://"+HOST,"Sec-Fetch-Site":"same-origin",
  "Content-Type":"application/json",...headers
 },JSON.stringify({lat,lon,accuracy,recoveryRequested}));
 return gate(r,env);
}
function cookieByName(response,name){
 const setCookies=response.headers.getSetCookie();
 const found=setCookies.find(x=>x.startsWith(name+"="));
 return found?found.split(";")[0]:null;
}

test("before a browser proof Tasek Glugor still requires GPS",async()=>{
 const r=request(HOST,"/__shield/gps/status");
 const response=await gate(r);
 assert.equal(response.status,200);
 const data=await response.json();
 assert.equal(data.regionalPolicy.observedIpCity,"Tasek Glugor");
 assert.equal(data.regionalPolicy.gpsRequired,true);
 assert.equal(data.regionalPolicy.browserProofActive,false);
 assert.equal((await gate(request())).status,403);
});
test("consented precise Butterworth fix outside campus issues IP- and host-bound 30-minute proof",async()=>{
 const res=await verify(5.405,100.382,20);
 assert.equal(res.status,200);
 const parsed=await res.json();
 assert.equal(parsed.classification,"outside");
 assert.deepEqual(parsed.butterworthRecovery,{
  offered:true,reason:"issued",maxDurationSeconds:1800
 });
 const proof=cookieByName(res,BUTTERWORTH_PROOF_COOKIE);
 assert.ok(proof,"missing opt-in recovery cookie");
 assert.match(res.headers.getSetCookie().find(x=>x.startsWith(BUTTERWORTH_PROOF_COOKIE+"=")),/Max-Age=1800/);
 assert.equal(res.headers.getSetCookie().some(x=>x.includes("5.405")||x.includes("100.382")),false);
 assert.equal(await gate(request(HOST,"/private","GET",{Cookie:proof})),null);
 const status=await (await gate(request(HOST,"/__shield/gps/status","GET",{Cookie:proof}))).json();
 assert.equal(status.enforcing,false);
 assert.equal(status.regionalPolicy.gpsRequired,false);
 assert.equal(status.regionalPolicy.selectionReason,"butterworth-browser-proof-exempt");
 assert.equal(status.regionalPolicy.browserProofActive,true);
 assert.equal(status.exempt,true);
 assert.equal(await gpsOutsideOrLegacyExempt(request(HOST,"/media/jingxin/private","GET",{Cookie:proof}),ENV,HOST),true);
});
test("Butterworth approximate bounds never include Tasek Glugor and reject coarse location",()=>{
 assert.equal(BUTTERWORTH_PROOF_TTL,1800);
 assert.equal(inApproximateButterworth(5.405,100.382,20),true);
 assert.equal(inApproximateButterworth(5.48,100.50,20),false);
 assert.equal(inApproximateButterworth(5.405,100.382,400),true);
 assert.equal(inApproximateButterworth(5.405,100.382,2000),true);
 assert.equal(inApproximateButterworth(5.405,100.382,2800),false);
 assert.equal(inApproximateButterworth(5.3751,100.382,20),false);
});
test("reported Tasek Glugor outside campus does not gain Butterworth proof",async()=>{
 const res=await verify(5.48,100.50,15);
 assert.equal(res.status,200);
 assert.equal(cookieByName(res,BUTTERWORTH_PROOF_COOKIE),null);
});
test("proof cannot be replayed from a different IP, hostname, or with flag disabled",async()=>{
 const res=await verify(5.405,100.382);
 const proof=cookieByName(res,BUTTERWORTH_PROOF_COOKIE);
 assert.ok(proof);
 assert.equal(await hasButterworthProof(request(HOST,"/private","GET",{Cookie:proof},undefined,"1.1.1.1"),ENV,HOST),false);
 assert.equal(await hasButterworthProof(request("vyncuslim.com","/private","GET",{Cookie:proof}),ENV,"vyncuslim.com"),false);
 assert.equal(await hasButterworthProof(request(HOST,"/private","GET",{Cookie:proof}),{...ENV,GPS_BUTTERWORTH_PROOF_ENABLED:"false"},HOST),false);
 assert.equal((await gate(request(HOST,"/private","GET",{Cookie:proof},undefined,"1.1.1.1"))).status,403);
 const forged=proof.replace(/.$/,(c)=>c==="A"?"B":"A");
 assert.equal((await gate(request(HOST,"/private","GET",{Cookie:forged}))).status,403);
});
test("campus denial rejects a new proof and revokes a previously signed proof",async()=>{
 const earlier=await verify(5.405,100.382);
 const prior=cookieByName(earlier,BUTTERWORTH_PROOF_COOKIE);
 assert.ok(prior);
 const denied=await verify(5.3677,100.21995,10,{Cookie:prior});
 assert.equal(denied.status,403);
 assert.equal((await denied.json()).error,"CAMPUS_RESTRICTED");
 const expires=denied.headers.getSetCookie().find(x=>x.startsWith(BUTTERWORTH_PROOF_COOKIE+"="));
 assert.match(expires,/Max-Age=0/);
 assert.equal(cookieByName(await verify(5.3677,100.21995),BUTTERWORTH_PROOF_COOKIE),null);
});
test("Tasek Glugor browser proof allows a short-lived hub recheck without new GPS prompt",async()=>{
 const proven=await verify(5.405,100.382);
 const proof=cookieByName(proven,BUTTERWORTH_PROOF_COOKIE);
 const state="Q".repeat(32);
 const p="/__shield/gps/recheck?host=vyncuslim.my&return=%2Fprivate&state="+state;
 const response=await gate(request(HOST,p,"GET",{Cookie:proof}));
 assert.equal(response.status,302);
 assert.match(response.headers.get("Location"),/^https:\/\/vyncuslim\.my\/__shield\/gps\/import\?/);
 const control=await gate(request(HOST,p));
 assert.equal(control.status,403,"without the proof a recheck must ask for geolocation");
});

test("diagnostics distinguish no cookie, invalid network, expiry, and feature disabled without exposing IP",async()=>{
 const empty=await gate(request(HOST,"/__shield/gps/status"));
 const emptyJson=await empty.json();
 assert.deepEqual(emptyJson.regionalPolicy.butterworthRecovery,{
  enabled:true,credentialStatus:"missing-cookie",
  verifyPath:"/__shield/gps/recover",maxDurationSeconds:1800
 });
 assert.doesNotMatch(JSON.stringify(emptyJson),/8\\.8\\.8\\.8/);
 const res=await verify(5.405,100.382);
 const proof=cookieByName(res,BUTTERWORTH_PROOF_COOKIE);
 const good=await inspectButterworthProof(request(HOST,"/private","GET",{Cookie:proof}),ENV,HOST);
 assert.deepEqual(good,{valid:true,status:"valid",kind:BUTTERWORTH_PROOF_KIND});
 const otherIp=await inspectButterworthProof(
  request(HOST,"/private","GET",{Cookie:proof},undefined,"1.1.1.1"),ENV,HOST);
 assert.deepEqual(otherIp,{valid:false,status:"invalid-or-network-changed"});
 const disabled=await inspectButterworthProof(
  request(HOST,"/private","GET",{Cookie:proof}),
  {...ENV,GPS_BUTTERWORTH_PROOF_ENABLED:"false"},HOST);
 assert.deepEqual(disabled,{valid:false,status:"feature-disabled"});
 const malformed=await inspectButterworthProof(
  request(HOST,"/private","GET",{Cookie:BUTTERWORTH_PROOF_COOKIE+"=nonsense"}),ENV,HOST);
 assert.deepEqual(malformed,{valid:false,status:"malformed-cookie"});
 const expiredParts=proof.split("=")[1].split(".");
 const expired=[String(Math.floor(Date.now()/1000)-1),expiredParts[1],expiredParts[2]].join(".");
 const exp=await inspectButterworthProof(request(HOST,"/private","GET",{
  Cookie:BUTTERWORTH_PROOF_COOKIE+"="+expired
 }),ENV,HOST);
 assert.deepEqual(exp,{valid:false,status:"expired-cookie"});
});
test("opt-in recovery page offers explicit browser location consent and does not automatically grant access",async()=>{
 const page=await gate(request(HOST,"/__shield/gps/recover"));
 assert.equal(page.status,403);
 assert.match(await page.text(),/Precise location required/);
 const js=await gate(request(HOST,"/__shield/gps/client.js"));
 assert.equal(js.status,200);
 const body=await js.text();
 assert.ok(body.includes("/__shield/gps/recover"));
 assert.ok(body.includes("const target=new URL(chatTarget||"));
 const otherHost=await gate(request("vyncuslim.my","/__shield/gps/recover"));
 assert.equal(otherHost.status,404);
});

test("standard signed OUTSIDE session permits navigation even when Butterworth proof is absent",async()=>{
 const verified=await verify(5.48,100.50,15);
 assert.equal(verified.status,200);
 const outsideCookie=cookieByName(verified,"__Host-vynalth-geo");
 assert.ok(outsideCookie,"missing standard signed outside session");
 assert.equal(cookieByName(verified,BUTTERWORTH_PROOF_COOKIE),null);
 const statusResponse=await gate(request(HOST,"/__shield/gps/status","GET",{Cookie:outsideCookie}));
 assert.equal(statusResponse.status,200);
 const status=await statusResponse.json();
 assert.equal(status.policyRevision,"gps-chat-reverify-v14");
 assert.equal(status.verified,true);
 assert.equal(status.regionalPolicy.gpsRequired,true,"regional rule still applies");
 assert.equal(status.regionalPolicy.browserProofActive,false);
 assert.equal(status.regionalPolicy.butterworthRecovery.credentialStatus,"missing-cookie");
 assert.deepEqual(status.signedSession,{
  state:"outside",outsideFastpassActive:true,hostBound:true
 });
 assert.equal(status.navigationAssessment.protectedDocumentGpsPromptExpected,false);
 assert.equal(await gate(request(HOST,"/private","GET",{Cookie:outsideCookie})),null);
 const strict=await (await gate(request(HOST,"/__shield/gps/status","GET",
   {Cookie:outsideCookie}),{...ENV,GPS_OUTSIDE_SESSION_FASTPASS:"false",GPS_RECHECK_EVERY_DOCUMENT:"true"})).json();
 assert.equal(strict.signedSession.outsideFastpassActive,false);
 assert.equal(strict.navigationAssessment.protectedDocumentGpsPromptExpected,true);
});

test("regional GPS requirement means a first-time protected visitor needs verification",async()=>{
 const status=await (await gate(request(HOST,"/__shield/gps/status"))).json();
 assert.equal(status.verified,false);
 assert.equal(status.signedSession.state,"none");
 assert.equal(status.signedSession.outsideFastpassActive,false);
 assert.equal(status.navigationAssessment.protectedDocumentGpsPromptExpected,true);
 assert.equal(status.navigationAssessment.previouslyRestricted,false);
});

test("verification distinguishes ordinary outside access from optional 30-minute proof",async()=>{
 const outside=await verify(5.48,100.50,15);
 assert.equal(outside.status,200);
 const response=await outside.json();
 assert.equal(response.verified,true);
 assert.equal(response.classification,"outside");
 assert.deepEqual(response.butterworthRecovery,{
  offered:false,reason:"outside-butterworth-recovery-area",maxDurationSeconds:1800
 });
 assert.equal(cookieByName(outside,BUTTERWORTH_PROOF_COOKIE),null);
 assert.ok(cookieByName(outside,"__Host-vynalth-geo"),
  "normal outside campus 15-minute cookie remains valid");
 const imprecise=await verify(5.405,100.382,6000);
 assert.equal(imprecise.status,200);
 const result=await imprecise.json();
 assert.deepEqual(result.butterworthRecovery,{
  offered:false,reason:"accuracy-over-5000m",maxDurationSeconds:1800
 });
 assert.equal(cookieByName(imprecise,BUTTERWORTH_PROOF_COOKIE),null);
 assert.doesNotMatch(JSON.stringify(result),/5\\.405|100\\.382/,
  "the recovery result must not include the submitted coordinates");
});
test("browser recovery UI stays on page to show proof outcome instead of silently navigating",async()=>{
 const result=await gate(request(HOST,"/__shield/gps/client.js"));
 assert.equal(result.status,200);
 const script=await result.text();
 assert.ok(script.includes('location.pathname==="/__shield/gps/recover"'));
 assert.ok(script.includes("data.butterworthRecovery?.offered"));
 assert.ok(script.includes("outside-butterworth-recovery-area"));
 assert.ok(script.includes("accuracy-over-5000m"));
 assert.ok(script.includes("recoveryRequested:location.pathname"));
 assert.ok(script.includes('statusData?.regionalPolicy?.browserProofActive'));
 assert.ok(script.includes('busy=false;'));
});

test("explicit fresh OUTSIDE verification grants misclassified Tasek Glugor IP a 30-minute recovery without pretending to prove Butterworth",async()=>{
 const response=await verify(5.48,100.50,1200,{},ENV,true);
 assert.equal(response.status,200);
 const payload=await response.json();
 assert.equal(payload.classification,"outside");
 assert.deepEqual(payload.butterworthRecovery,{
  offered:true,reason:"issued-after-fresh-outside-verification",maxDurationSeconds:1800
 });
 const proof=cookieByName(response,BUTTERWORTH_PROOF_COOKIE);
 assert.ok(proof);
 const inspect=await inspectButterworthProof(request(HOST,"/private","GET",{Cookie:proof}),ENV,HOST);
 assert.deepEqual(inspect,{valid:true,status:"valid",kind:MISLOCATED_OUTSIDE_KIND});
 const status=await (await gate(request(HOST,"/__shield/gps/status","GET",{Cookie:proof}))).json();
 assert.equal(status.regionalPolicy.gpsRequired,false);
 assert.equal(status.regionalPolicy.selectionReason,"consented-outside-ambiguous-ip-exempt");
 assert.equal(status.regionalPolicy.browserProofKind,MISLOCATED_OUTSIDE_KIND);
 assert.equal(status.navigationAssessment.protectedDocumentGpsPromptExpected,false);
 assert.equal(await gate(request(HOST,"/private","GET",{Cookie:proof})),null);
 assert.equal((await gate(request(HOST,"/private","GET",{Cookie:proof},undefined,"1.1.1.1"))).status,403);
});

test("no automatic Tasek Glugor exemption: city fallback requires explicit recovery and fresh outside verdict",async()=>{
 const oldWay=await verify(5.48,100.50,1200);
 assert.equal(oldWay.status,200);
 assert.equal(cookieByName(oldWay,BUTTERWORTH_PROOF_COOKIE),null);
 const denied=await verify(5.3677,100.21995,12,{},ENV,true);
 assert.equal(denied.status,403);
 assert.equal(cookieByName(denied,BUTTERWORTH_PROOF_COOKIE),null);
 const noMetadata=request(HOST,"/__shield/gps/verify","POST",{
  Origin:"https://"+HOST,"Sec-Fetch-Site":"same-origin","Content-Type":"application/json",
  "X-City":"Tasek Glugor","CF-City":"Tasek Glugor"
 },JSON.stringify({lat:5.48,lon:100.50,accuracy:1200,recoveryRequested:true}),
 IP,{country:"MY",region:"Penang",regionCode:"07",city:"George Town"});
 const checked=await gate(noMetadata);
 assert.equal(checked.status,200);
 assert.equal((await checked.json()).butterworthRecovery.offered,false);
 assert.equal(cookieByName(checked,BUTTERWORTH_PROOF_COOKIE),null);
 assert.equal(isAmbiguousIpRecoveryEligible(noMetadata,1200),false);
 const unknownRegion=request(HOST,"/private","GET",{},undefined,IP,
  {country:"MY",regionCode:"03",region:"Kelantan",city:"Tasek Glugor"});
 assert.equal(isAmbiguousIpRecoveryEligible(unknownRegion,1200),false);
});
