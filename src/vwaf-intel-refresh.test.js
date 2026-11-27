import test from "node:test";
import assert from "node:assert/strict";
import {refreshSignedIntel} from "./vwaf-intel-refresh.js";
const now=1800000000000;
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
async function fixture(){
 const keys=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const publicKey=b64(await crypto.subtle.exportKey("raw",keys.publicKey));
 let current={sequence:0,manifest:null},writes=0,requests=0,envelope;
 async function sign(sequence,overrides={}){
  const bytes=new TextEncoder().encode(JSON.stringify({schema:"vwaf-intel-v1",sequence,issuedAt:now-1000,
   expiresAt:now+60000,indicators:[{host:"vynalthai.com",address:"192.0.2.10",category:"observed_scanning"}],...overrides}));
  return {payload:b64(bytes),signature:b64(await crypto.subtle.sign("Ed25519",keys.privateKey,bytes))};
 }
 const store={load:async()=>current,compareAndSwap:async(seq,next)=>{
  if(seq!==current.sequence)return false;current=next;writes++;return true;
 }};
 const config={feedUrl:"https://intel.example/approved.json",publicKey,store,now:()=>now,
  fetchImpl:async(url,init)=>{requests++;assert.equal(url,"https://intel.example/approved.json");assert.equal(init.redirect,"error");return Response.json(envelope)}};
 return {config,sign,setEnvelope:x=>{envelope=x},stats:()=>({writes,requests,sequence:current.sequence})};
}
test("signed refresh updates atomically, same signed manifest is a no-op, and rollback fails",async()=>{
 const f=await fixture();f.setEnvelope(await f.sign(7));
 assert.equal((await refreshSignedIntel(f.config)).updated,true);
 assert.equal((await refreshSignedIntel(f.config)).updated,false);
 f.setEnvelope(await f.sign(6));await assert.rejects(refreshSignedIntel(f.config),/rollback/);
 f.setEnvelope(await f.sign(7,{expiresAt:now+40000}));await assert.rejects(refreshSignedIntel(f.config),/Conflicting/);
 assert.deepEqual(f.stats(),{writes:1,requests:4,sequence:7});
});
test("untrusted responses, expired manifest and unavailable storage do not update trust state",async()=>{
 const f=await fixture();const signed=await f.sign(1);f.setEnvelope({...signed,payload:b64(new TextEncoder().encode("{}"))});
 await assert.rejects(refreshSignedIntel(f.config),/Untrusted/);
 f.setEnvelope(await f.sign(1,{expiresAt:now-1}));await assert.rejects(refreshSignedIntel(f.config));
 await assert.rejects(refreshSignedIntel({...f.config,fetchImpl:async()=>new Response("x".repeat(100001),{headers:{"content-type":"application/json"}})}),/exceeds/);
 await assert.rejects(refreshSignedIntel({...f.config,fetchImpl:async()=>new Response(null,{status:302,headers:{location:"https://other.example/"}})}));
 await assert.rejects(refreshSignedIntel({...f.config,store:{...f.config.store,load:async()=>null}}),/persisted/);
 f.setEnvelope(await f.sign(1));await assert.rejects(refreshSignedIntel({...f.config,store:{...f.config.store,compareAndSwap:async()=>false}}),/Concurrent/);
 assert.equal(f.stats().writes,0);
});
test("invalid or credential-bearing feed config is rejected before fetch",async()=>{
 const f=await fixture();
 for(const feedUrl of ["http://intel.example/approved.json","https://u:p@intel.example/feed","https://intel.example/feed?key=secret","https://intel.example/feed#fragment"])
  await assert.rejects(refreshSignedIntel({...f.config,feedUrl}),/approved HTTPS/);
 assert.equal(f.stats().requests,0);
});
