import test from "node:test";
import assert from "node:assert/strict";
import {createHmac,webcrypto} from "node:crypto";
import {schoolEmailGate,restrictedEmail} from "./school-email-gate.js";
import edge from "./index.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const SSO="test-only-canonical-issuer-secret-111111111111111111";
const BLOCK="test-only-school-block-secret-2222222222222222222";
const env={SCHOOL_EMAIL_GATE_ENABLED:"true",CONSENT_SSO_SIGNING_SECRET:SSO,
 SCHOOL_EMAIL_BLOCK_SECRET:BLOCK};
function signed(host,email,status="normal",verified=true){
 const claim={sub:"user_12345678",sid:"sess_12345678",
  status,host,exp:Math.floor(Date.now()/1000)+180,
  email,email_verified:verified};
 const p=Buffer.from(JSON.stringify(claim)).toString("base64url");
 const tag=createHmac("sha256",SSO).update(p).digest("base64url");
 return "__Secure-vynalth-sso="+p+"."+tag;
}
async function run(host="vynalthai.com",path="/c",cookie="",e=env,extras={}){
 const url=new URL("https://"+host+path);
 return schoolEmailGate(new Request(url,{headers:{Cookie:cookie,...extras}}),e,url,
  host.startsWith("app.")?host.slice(4):host);
}
test("only exact official school email domains match",()=>{
 for(const x of ["x@student.powiis.edu.my","Y@POWIIS.EDU.MY",
  "john+test@powiis.edu.my"])
  assert.equal(restrictedEmail(x),true,x);
 for(const x of ["a@powiis.edu.my.attacker.com","a@sub.student.powiis.edu.my",
  "a@notpowiis.edu.my","a@powiis.edu.my.example","a@gmail.com",
  "@powiis.edu.my","a@powiis.edu.my@evil.test"," a@powiis.edu.my",
  "a@student-powiis.edu.my"])
  assert.equal(restrictedEmail(x),false,x);
});
test("both email domains denied even for trust, contact and status",async()=>{
 for(const email of ["s@student.powiis.edu.my","teacher@powiis.edu.my"]){
  for(const role of ["normal","trust","contact","status"]){
   const res=await run("vynalthai.com","/c",signed("vynalthai.com",email,role));
   assert.equal(res.status,403,email+" "+role);
   assert.equal((await res.json()).reason,"SCHOOL_ACCOUNT_RESTRICTED");
   assert.equal(res.headers.get("Cache-Control").includes("no-store"),true);
   const header=res.headers.get("Set-Cookie");
   assert.match(header,/__Host-vynalth-school-restricted=/);
   assert.match(header,/Secure; HttpOnly; SameSite=Lax/);
   assert.match(header,/Max-Age=300/);
   assert.doesNotMatch(header,/@|powiis/i);
  }
 }
});
test("signed denial marker blocks the next request without retaining email",async()=>{
 const first=await run("vynalthai.com","/c",signed("vynalthai.com","a@student.powiis.edu.my"));
 const marker=first.headers.get("Set-Cookie").split(";")[0];
 const second=await run("vynalthai.com","/c",marker);
 assert.equal(second.status,403);
 assert.equal(second.headers.has("Set-Cookie"),false);
 assert.equal(await run("vyncuslim.com","/c",marker),null);
 const invalid=marker.replace(/.$/,ch=>ch==="A"?"B":"A");
 assert.equal(await run("vynalthai.com","/c",invalid),null);
});
test("unverified or spoofed identity, suffixes, header and body cannot block",async()=>{
 assert.equal(await run("vynalthai.com","/c","",env,
   {"X-User-Email":"s@student.powiis.edu.my"}),null);
 const unverified=signed("vynalthai.com","s@student.powiis.edu.my","normal",false);
 assert.equal(await run("vynalthai.com","/c",unverified),null);
 assert.equal(await run("vynalthai.com","/c",
  signed("vynalthai.com","s@student.powiis.edu.my.evil")),null);
 const wrongHost=signed("vyncuslim.com","s@student.powiis.edu.my");
 assert.equal(await run("vynalthai.com","/c",wrongHost),null);
 const forged=signed("vynalthai.com","s@student.powiis.edu.my")
  .replace(/.$/,ch=>ch==="A"?"B":"A");
 assert.equal(await run("vynalthai.com","/c",forged),null);
 assert.equal(await run("vynalthai.com","/c",
   signed("vynalthai.com","a@gmail.com")),null);
});
test("disabled flag leaves all existing traffic and logins unchanged",async()=>{
 const c=signed("vynalthai.com","a@powiis.edu.my","trust");
 assert.equal(await run("vynalthai.com","/c",c,{
  ...env,SCHOOL_EMAIL_GATE_ENABLED:"false"}),null);
});
test("a school SSO is fail-closed if denial marker secret is not configured",async()=>{
 const r=await run("vynalthai.com","/c",
  signed("vynalthai.com","s@powiis.edu.my"),{
   ...env,SCHOOL_EMAIL_BLOCK_SECRET:""});
 assert.equal(r.status,503);
 assert.doesNotMatch(JSON.stringify(await r.json()),/@|student\.powiis/);
});
test("privacy, consent preferences and logout stay accessible",async()=>{
 const school=signed("vynalthai.com","s@student.powiis.edu.my");
 for(const path of ["/auth/logout","/api/auth/signout",
   "/en/legal/privacy","/__vynalth/consent","/__vynalth/consent/preferences",
   "/.well-known/acme-challenge/test","/__shield/gps/disclaimer"]){
  assert.equal(await run("vynalthai.com",path,school),null,path);
 }
 for(const path of ["/api/auth/callback","/api/ai/chat",
  "/__vynalth/consent/authorize","/media/jingxin/shared-memory.jpg"]){
  assert.equal((await run("vynalthai.com",path,school)).status,403,path);
 }
});
test("Worker denies school SSO prior to GPS and trusted account bypass",async()=>{
 const c=signed("vynalthai.com","s@student.powiis.edu.my","trust");
 const response=await edge.fetch(new Request("https://vynalthai.com/api/ai/chat",{
   headers:{Cookie:c}}),{
   ...env,GPS_GATE_ENABLED:"false",
   SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED:"true",
   CONSENT_CMP_ENABLED:"false",
   JINGXIN_PRIVATE_MEDIA_ENABLED:"false"
 },{});
 assert.equal(response.status,403);
 assert.equal(response.headers.get("x-vynalth-edge"),"cloudflare-worker");
 assert.match(response.headers.get("Set-Cookie"),/school-restricted/);
});
test("seven root hosts can each enforce the same verified-identity issuer",async()=>{
 const roots=["vynalthai.com","vyncuslim.com","vynalthai.si",
 "vyncuslim.si","sleepsomno.com","vitamindai.online","powiismunc.com"];
 for(const host of roots){
  const res=await run(host,"/protected",signed(host,"staff@powiis.edu.my"));
  assert.equal(res.status,403,host);
 }
});
