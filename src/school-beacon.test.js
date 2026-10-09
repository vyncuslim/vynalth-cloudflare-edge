import {test} from "node:test";
import assert from "node:assert/strict";
import {createHmac} from "node:crypto";
import {handleCampusBeacon, isPublicExactV4} from "./school-beacon.js";

const DEVICE = "00112233445566778899aabbccddeeff";
const SECRET = "b".repeat(64);
const ACCOUNT = "a".repeat(32);
const LIST = "c".repeat(32);
const ADDRESS = "60.51.219.195";
const HOST = "https://vynalthai.com/__shield/campus-beacon";
const sig = payload => createHmac("sha256",Buffer.from(SECRET,"hex"))
  .update(["v1",payload.ts,payload.nonce,payload.deviceId,payload.ssid].join("\n")).digest("hex");
const body = nonce => ({ts:Math.floor(Date.now()/1000),nonce,deviceId:DEVICE,ssid:"POWIIS_Student"});
function request(payload,{ip=ADDRESS, signature=sig(payload)}={}) {
  return new Request(HOST,{
    method:"POST",
    headers:{
      "content-type":"application/json",
      "cf-connecting-ip":ip,
      "x-school-beacon-signature":signature
    },
    body:JSON.stringify(payload)
  });
}
function kv() {
  const store=new Map();
  return {
    store,
    async get(key) {return store.get(key)||null;},
    async put(key,value) {store.set(key,value);},
    async delete(key) {store.delete(key);}
  };
}
function env(kv) {
  return {
    SCHOOL_BEACON_ENABLED:"true",
    SCHOOL_BEACON_KV:kv,
    SCHOOL_BEACON_DEVICE_ID:DEVICE,
    SCHOOL_BEACON_SIGNING_KEY:SECRET,
    SCHOOL_CF_ACCOUNT_ID:ACCOUNT,
    SCHOOL_CF_LIST_ID:LIST,
    SCHOOL_CF_API_TOKEN:"unittest-only"
  };
}
test("single public IPv4 only; no private or CIDR ranges",()=>{
  assert.equal(isPublicExactV4(ADDRESS),true);
  for(const value of ["60.51.219.0/24","60.0.0.0/8","10.0.0.1",
    "192.168.1.1","127.0.0.1","100.64.1.3","198.51.100.4",
    "2606:4700::1111","60.51.219.999"]) {
    assert.equal(isPublicExactV4(value),false,value);
  }
});
test("beacon fails closed without installed Cloudflare secrets or enrollment",async()=>{
  assert.equal((await handleCampusBeacon(request(body("a".repeat(32))),{})).status,503);
  assert.equal((await handleCampusBeacon(request(body("a".repeat(32)),{signature:"0".repeat(64)}),env(kv()))).status,403);
});
test("signed, time-separated owner Wi-Fi observations add EXACT observed IP",async()=>{
  const backing=kv(), e=env(backing);
  const items=[];
  const prev=globalThis.fetch;
  globalThis.fetch=async (url,opt={})=>{
    const u=String(url);
    let result;
    if(u.endsWith("/rules/lists/"+LIST)) result={name:"powiis_verified_egress",kind:"ip"};
    else if(u.includes("/bulk_operations/")) result={status:"completed"};
    else if(u.includes("/items") && opt.method==="POST") {
      items.push(...JSON.parse(opt.body).map((x,i)=>({...x,id:String(i).padStart(32,"0") })));
      result={operation_id:"d".repeat(32)};
    } else if(u.includes("/items?")) result=items;
    else throw new Error("Unexpected provider request "+u);
    return new Response(JSON.stringify({success:true,result}),{
      status:200,headers:{"content-type":"application/json"}
    });
  };
  try {
    const first=await handleCampusBeacon(request(body("1".repeat(32))),e);
    assert.equal(first.status,202);
    assert.equal(items.length,0);
    const key="campus:pending:"+DEVICE+":"+ADDRESS;
    backing.store.set(key,JSON.stringify({first:Math.floor(Date.now()/1000)-360}));
    const second=await handleCampusBeacon(request(body("2".repeat(32))),e);
    assert.equal(second.status,200);
    assert.equal(items.length,1);
    assert.equal(items[0].ip,ADDRESS);
    assert.match(items[0].comment,/^POWIIS\|exp=.*\|ref=campus-beacon-/);
    const third=await handleCampusBeacon(request(body("3".repeat(32))),e);
    assert.equal(third.status,200);
    assert.equal(items.length,1);
  } finally {globalThis.fetch=prev;}
});
