import test from "node:test";
import assert from "node:assert/strict";
import {createHmac,webcrypto} from "node:crypto";
import {handleJingxinMedia} from "./jingxin-media.js";
import {guestGpsGate} from "./guest-gps.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const COOKIE_SECRET="test-media-consent-signing-key-123456789012345";
const GPS_SECRET="test-gps-photos-signing-key-123456789012345";
const GPS_STATUS_SECRET="test-gps-status-separate-key-123456789012345";
const base={JINGXIN_PRIVATE_MEDIA_ENABLED:"true",CONSENT_SSO_SIGNING_SECRET:COOKIE_SECRET,
 GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:GPS_SECRET,
 GPS_ACCOUNT_STATUS_SECRET:GPS_STATUS_SECRET,
 GPS_CAMPUS_LAT:"5.36770",GPS_CAMPUS_LON:"100.21995",GPS_CAMPUS_RADIUS_METERS:"180"};
const content="private test photo bytes";
function storage(){
 const calls=[];
 return {calls,async get(key){
  calls.push(key);
  return {body:new Response(content).body};
 }};
}
function makeEnv(){const bucket=storage();return {...base,JINGXIN_PRIVATE_MEDIA_R2:bucket};}
function photo(path="/media/jingxin/shared-memory.jpg",cookie="",host="vyncuslim.com",method="GET"){
 const url=new URL("https://"+host+path);
 return new Request(url,{method,headers:{Cookie:cookie}});
}
async function invoke(request,env){
 const url=new URL(request.url);
 return handleJingxinMedia(request,env,url,"vyncuslim.com");
}
function signedUser(status="trust",host="vyncuslim.com"){
 const payload=Buffer.from(JSON.stringify({sub:"person_12345678",sid:"session_12345678",
 status,host,exp:Math.floor(Date.now()/1000)+600})).toString("base64url");
 const tag=createHmac("sha256",COOKIE_SECRET).update(payload).digest("base64url");
 return "__Secure-vynalth-sso="+payload+"."+tag;
}
async function gpsCookie(lat,lon){
 const req=new Request("https://vyncuslim.com/__shield/gps/verify",{
  method:"POST",headers:{Origin:"https://vyncuslim.com",
   "Sec-Fetch-Site":"same-origin","Content-Type":"application/json"},
  body:JSON.stringify({lat,lon,accuracy:10})});
 const res=await guestGpsGate(req,base,new URL(req.url));
 const cookie=res.headers.getSetCookie().find(x=>x.includes("__Host-vynalth-geo"));
 return {status:res.status,cookie:cookie?.split(";")[0]};
}
test("story and unrelated assets are untouched by private media handler",async()=>{
 assert.equal(await invoke(photo("/jingxin"),{}),null);
 assert.equal(await invoke(photo("/assets/logo.svg"),{}),null);
});
test("disabled private-media rollout leaves existing public photos and status routes untouched",async()=>{
 for(const env of [{}, {...makeEnv(),JINGXIN_PRIVATE_MEDIA_ENABLED:"false"}]){
  assert.equal(await invoke(photo(),env),null);
  assert.equal(await invoke(photo("/jingxin/access-status"),env),null);
 }
});
test("enabled private-media rollout without R2 binding fails closed, never reaches public origin",async()=>{
 const env={...base};
 const res=await invoke(photo(),env);
 assert.equal(res.status,503);
 assert.match(res.headers.get("Cache-Control"),/no-store/);
 const status=await invoke(photo("/jingxin/access-status"),env);
 assert.equal(status.status,200);
 const detail=await status.json();
 assert.equal(detail.blocked,true);
 assert.equal(detail.reason,"unavailable");
});
test("signed trusted status unlocks only recognized first-party private R2 paths",async()=>{
 const env=makeEnv();
 for(const status of ["trust","contact","status"]){
  const res=await invoke(photo(undefined,signedUser(status)),env);
  assert.equal(res.status,200,status);
  assert.equal(await res.text(),content);
  assert.match(res.headers.get("Content-Type"),/image\/jpeg/);
  assert.equal(res.headers.get("Cross-Origin-Resource-Policy"),"same-origin");
 }
 assert.deepEqual(env.JINGXIN_PRIVATE_MEDIA_R2.calls,
  Array(3).fill("jingxin/shared-memory.jpg"));
 assert.equal(await invoke(photo("/media/jingxin/../../etc/passwd",signedUser()),env),null);
});
test("forged, ordinary and wrong-host SSO cannot read photos",async()=>{
 const env=makeEnv();
 for(const cookie of ["",signedUser("normal"),signedUser("trust","vynalthai.com"),signedUser().replace(/.$/,x=>x==="A"?"B":"A")]){
  const res=await invoke(photo(undefined,cookie),env);
  assert.equal(res.status,403);
 }
 assert.equal(env.JINGXIN_PRIVATE_MEDIA_R2.calls.length,0);
});
test("signed off-campus GPS cookie unlocks photo, on-campus verdict cannot",async()=>{
 const env=makeEnv();
 const outside=await gpsCookie(5.40,100.25);
 assert.equal(outside.status,200);
 assert.equal((await invoke(photo(undefined,outside.cookie),env)).status,200);
 const inside=await gpsCookie(5.36770,100.21995);
 assert.equal(inside.status,403);
 assert.equal((await invoke(photo(undefined,inside.cookie),env)).status,403);
});
test("photo request errors are closed and never proxy to public source",async()=>{
 const env=makeEnv();
 assert.equal((await invoke(photo("/media/jingxin/other.jpg",signedUser()),env)).status,404);
 assert.equal((await invoke(photo(undefined,signedUser(),"vynalthai.si"),env)).status,404);
 env.JINGXIN_PRIVATE_MEDIA_R2.get=async()=>{throw Error("private object store down")};
 const failed=await invoke(photo(undefined,signedUser()),env);
 assert.equal(failed.status,503);
 assert.match((await failed.json()).error,/UNAVAILABLE/);
});
test("private-photo cutover protects old asset aliases and HQ fragments",async()=>{
 const env=makeEnv();
 for(const alias of ["/assets/jingxin-memory.jpg","/assets/mce-kuala-lumpur-real.webp"]){
  const anonymous=await invoke(photo(alias),env);
  assert.equal(anonymous.status,403,alias);
  assert.match(anonymous.headers.get("Cache-Control"),/no-store/);
  const signed=await invoke(photo(alias,signedUser("trust")),env);
  assert.equal(signed.status,200,alias);
  assert.equal(await signed.text(),content);
 }
 for(const sensitive of ["/assets/jingxin-memory-hq.avif",
  "/assets/.jingxin-hq/part-00.txt","/assets/.jingxin-hq2/part-00.txt"]){
  const denied=await invoke(photo(sensitive,signedUser("trust")),env);
  assert.equal(denied.status,404,sensitive);
 }
 assert.equal(await invoke(photo("/assets/jingxin-memory.jpg"),{
  ...env,JINGXIN_PRIVATE_MEDIA_ENABLED:"false"}),null);
});

test("HEAD responses expose no body and missing object never falls back",async()=>{
 const env=makeEnv(),cookie=signedUser();
 const res=await invoke(photo(undefined,cookie,"vyncuslim.com","HEAD"),env);
 assert.equal(res.status,200);
 assert.equal(res.body,null);
 env.JINGXIN_PRIVATE_MEDIA_R2.get=async()=>null;
 assert.equal((await invoke(photo(undefined,cookie),env)).status,404);
});
