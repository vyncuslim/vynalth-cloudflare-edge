import { test } from "node:test";
import assert from "node:assert/strict";
import { handleSchoolVolunteer, schoolVolunteerTest } from "../src/school-volunteer.js";

test("only public exact IP candidates allowed",()=>{
  assert.equal(schoolVolunteerTest.validIp("60.51.219.225"),true);
  assert.equal(schoolVolunteerTest.validIp("60.51.219.195"),true);
  for(const ip of ["60.51.219.0/24","10.0.0.1","192.168.0.1",
    "198.51.100.2","203.0.113.4","127.0.0.1"]){
    assert.equal(schoolVolunteerTest.validIp(ip),false,ip);
  }
});
test("GET page is public, accessible without any KV or friend login",async()=>{
  const req=new Request("https://vynalthai.com/school-ip-report");
  const res=await handleSchoolVolunteer(req,{},"/school-ip-report");
  const html=await res.text();
  assert.equal(res.status,200);
  assert.match(html,/voluntarily agree/i);
  assert.match(html,/will not automatically block anyone/i);
  assert.equal(res.headers.get("cache-control"),"no-store, max-age=0");
});
test("nonconsenting or malicious origins cannot submit",async()=>{
  let writes=0;
  const env={SCHOOL_EGRESS_REPORTS:{get:async()=>null,put:async()=>writes++}};
  const request=(origin,body)=>new Request("https://vynalthai.com/school-ip-report",{
    method:"POST",headers:{"origin":origin,"content-type":"application/json",
      "CF-Connecting-IP":"60.51.219.225"},body:JSON.stringify(body)
  });
  assert.equal((await handleSchoolVolunteer(request("https://evil.example",{consent:true,schoolWifiConfirmed:true}),env,"/school-ip-report")).status,403);
  assert.equal((await handleSchoolVolunteer(request("https://vynalthai.com",{consent:false,schoolWifiConfirmed:true}),env,"/school-ip-report")).status,400);
  assert.equal(writes,0);
});
test("volunteer report is never a WAF action",async()=>{
  const kv=new Map(); const env={SCHOOL_EGRESS_REPORTS:{
    get:async key=>kv.get(key)||null,
    put:async(key,v,params)=>{assert.equal(params.expirationTtl,72*3600);kv.set(key,v)}
  }};
  const req=new Request("https://vynalthai.com/school-ip-report",{
    method:"POST",headers:{"origin":"https://vynalthai.com",
      "content-type":"application/json","CF-Connecting-IP":"60.51.219.225"},
    body:JSON.stringify({consent:true,schoolWifiConfirmed:true})
  });
  const res=await handleSchoolVolunteer(req,env,"/school-ip-report");
  assert.equal(res.status,200);
  assert.equal((await res.json()).noAutomaticBlock,true);
  assert.equal(kv.size,1);
  const record=JSON.parse([...kv.values()][0]);
  assert.equal(record.ip,"60.51.219.225");
  assert.equal(record.verified,false);
});
test("review endpoint not publicly readable",async()=>{
  const request=new Request("https://vynalthai.com/_shield/school-egress/candidates");
  const result=await handleSchoolVolunteer(request,{},"/_shield/school-egress/candidates");
  assert.equal(result.status,403);
});
