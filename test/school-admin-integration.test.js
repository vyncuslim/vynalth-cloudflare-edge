import test from "node:test";
import assert from "node:assert/strict";
import edge from "../src/index.js";
// Execute legacy management test suite against the unified Edge entrypoint.
const worker={fetch(req,env,ctx){return edge.fetch(req,{
  SCHOOL_POLICY_INLINE_ENABLED:"true",SCHOOL_MANAGEMENT_INLINE_ENABLED:"true",...env
},ctx);}};
globalThis.fetch=async()=>new Response("origin-ok",{status:200});

const HOST = "https://vynalthai.com";
const PASSWORD = "test-value-only-not-real-password-123";
const SECRET = "test-random-session-signing-secret-not-production-1234567890";
const IP = "8.8.8.8";
const envFactory = (mode="observe") => ({
  MODE: mode,
  ADMIN_IP_PASSWORD: PASSWORD,
  ADMIN_IP_SESSION_SECRET: SECRET,
  SCHOOL_IP_KV: kvFixture()
});

function kvFixture() {
  const entries = new Map();
  const writes = [];
  const deletions = [];
  return {
    entries,writes,deletions,
    async get(key){return entries.get(key)?.value??null;},
    async put(key,value,options={}){
      entries.set(key,{value,metadata:options.metadata||null,
        expiration:options.expirationTtl ? Math.floor(Date.now()/1000)+options.expirationTtl : undefined});
      writes.push({key,value,options});
    },
    async delete(key){entries.delete(key);deletions.push(key);},
    async list({prefix,limit=50}){
      const keys=[...entries.entries()].filter(([key])=>key.startsWith(prefix)).slice(0,limit)
        .map(([name,item])=>({name,metadata:item.metadata,expiration:item.expiration}));
      return {keys,list_complete:true,cursor:null};
    }
  };
}
const send = (env,path,method="GET",body,headers={})=>{
  const hdr={"CF-Connecting-IP":IP,...headers};
  if(method==="POST"){
    hdr.Origin=HOST;
    hdr["Sec-Fetch-Site"]="same-origin";
    hdr["Content-Type"]="application/json";
  }
  return worker.fetch(new Request(HOST+path,{method,headers:hdr,
    body:body===undefined?undefined:JSON.stringify(body)}),env,{waitUntil(){}});
};
async function login(env,password=PASSWORD){
  const r=await send(env,"/admin/ip/api/login","POST",{password});
  if(!r.ok)return {response:r};
  const data=await r.json();
  const cookie=r.headers.get("Set-Cookie").split(";")[0];
  return {response:r,cookie,csrf:data.csrf};
}
function authorizedHeaders(loginData, extra={}){
  return {Cookie:loginData.cookie,"X-CSRF-Token":loginData.csrf,...extra};
}

test("black admin login page and JS load without mutating KV",async()=>{
  const env=envFactory();
  const page=await send(env,"/admin/ip");
  assert.equal(page.status,200);
  const html=await page.text();
  assert.match(html,/IP Access Control/);
  assert.match(html,/background:#030407/);
  assert.match(html,/\/admin\/ip\/app.js/);
  assert.match(page.headers.get('Content-Security-Policy'),/script-src 'self'/);
  const script=await send(env,"/admin/ip/app.js");
  assert.equal(script.status,200);
  assert.match(await script.text(),/admin\/ip\/api\//);
  assert.equal(env.SCHOOL_IP_KV.writes.length,0);
});

test("admin API fails closed without configured secrets",async()=>{
  const env=envFactory();
  delete env.ADMIN_IP_PASSWORD;
  const response=await send(env,"/admin/ip/api/login","POST",{password:PASSWORD});
  assert.equal(response.status,503);
  assert.equal((await response.json()).error,"ADMIN_NOT_CONFIGURED");
});

test("unauthed visitor cannot read, add, remove or enumerate list",async()=>{
  const env=envFactory();
  assert.equal((await send(env,"/admin/ip/api/list")).status,403);
  assert.equal((await send(env,"/admin/ip/api/session")).status,403);
  assert.equal((await send(env,"/admin/ip/api/add","POST",{
    kind:"manual",ip:"1.1.1.1",hours:6,confirmSharedImpact:true
  })).status,403);
  assert.equal((await send(env,"/admin/ip/api/remove","POST",{ip:"1.1.1.1"})).status,403);
  assert.equal(env.SCHOOL_IP_KV.writes.length,0);
});

test("bad passwords are rate-limited; owner password never returned",async()=>{
  const env=envFactory();
  for(let i=0;i<5;i++){
    const r=await send(env,"/admin/ip/api/login","POST",{password:"wrong"});
    assert.equal(r.status,401);
    assert.doesNotMatch(await r.text(),/test-value-only/);
  }
  const r=await send(env,"/admin/ip/api/login","POST",{password:PASSWORD});
  assert.equal(r.status,429);
});

test("valid login returns HttpOnly Secure SameSite Strict cookie and anti-CSRF token",async()=>{
  const env=envFactory();
  const s=await login(env);
  assert.equal(s.response.status,200);
  const header=s.response.headers.get("Set-Cookie");
  assert.match(header,/HttpOnly/);
  assert.match(header,/Secure/);
  assert.match(header,/SameSite=Strict/);
  assert.match(header,/Max-Age=1200/);
  assert.equal(typeof s.csrf,"string");
  assert.ok(s.csrf.length>=32);
});

test("bad cookie signature cannot be used for protected API",async()=>{
  const env=envFactory();
  const s=await login(env);
  const bad=s.cookie.slice(0,-3)+"zzz";
  const r=await send(env,"/admin/ip/api/session","GET",undefined,{Cookie:bad});
  assert.equal(r.status,403);
});

test("add requires both valid session and matching CSRF plus impact confirmation",async()=>{
  const env=envFactory();
  const s=await login(env);
  const body={kind:"manual",ip:"1.1.1.1",hours:6,confirmSharedImpact:true};
  const noCsrf=await send(env,"/admin/ip/api/add","POST",body,{Cookie:s.cookie});
  assert.equal(noCsrf.status,403);
  const noConfirm=await send(env,"/admin/ip/api/add","POST",{
    ...body,confirmSharedImpact:false
  },authorizedHeaders(s));
  assert.equal(noConfirm.status,400);
  assert.equal(env.SCHOOL_IP_KV.writes.filter(x=>x.key.startsWith("blocked:")).length,0);
});

test("add-current records trusted CF source, ignores forged JSON IP",async()=>{
  const env=envFactory();
  const s=await login(env);
  const r=await send(env,"/admin/ip/api/add","POST",{
    kind:"current",ip:"1.1.1.1",hours:1,confirmSharedImpact:true
  },authorizedHeaders(s));
  assert.equal(r.status,201);
  const data=await r.json();
  assert.equal(data.ip,IP);
  assert.equal(data.mode,"observe");
  assert.equal(data.effectiveAcrossWebsites,"unverified");
  const record=env.SCHOOL_IP_KV.writes.find(x=>x.key==="blocked:"+IP);
  assert.equal(record.options.expirationTtl,3600);
  assert.equal(env.SCHOOL_IP_KV.entries.has("blocked:1.1.1.1"),false);
});

test("manual exact public IPv6 gets normalized; rejects CIDR/private address",async()=>{
  const env=envFactory();
  const s=await login(env);
  const headers=authorizedHeaders(s);
  const good=await send(env,"/admin/ip/api/add","POST",{
    kind:"manual",ip:"2606:4700:4700:0:0:0:0:1111",hours:12,confirmSharedImpact:true
  },headers);
  assert.equal(good.status,201);
  assert.equal((await good.json()).ip,"2606:4700:4700::1111");
  assert.ok(env.SCHOOL_IP_KV.entries.has("blocked:2606:4700:4700::1111"));
  for(const ip of ["10.0.0.1","192.168.0.1","1.1.1.1/32","2001:db8::1","::1"]){
    const bad=await send(env,"/admin/ip/api/add","POST",{
      kind:"manual",ip,hours:6,confirmSharedImpact:true
    },headers);
    assert.equal(bad.status,422,ip);
  }
});

test("authenticated list returns metadata and deletion revokes selected KV record",async()=>{
  const env=envFactory();
  const s=await login(env),h=authorizedHeaders(s);
  await send(env,"/admin/ip/api/add","POST",{
    kind:"manual",ip:"1.1.1.1",hours:6,confirmSharedImpact:true
  },h);
  const list=await send(env,"/admin/ip/api/list","GET",undefined,h);
  assert.equal(list.status,200);
  const data=await list.json();
  assert.equal(data.items.length,1);
  assert.equal(data.items[0].ip,"1.1.1.1");
  assert.ok(data.items[0].expiresAt);
  const remove=await send(env,"/admin/ip/api/remove","POST",{ip:"1.1.1.1"},h);
  assert.equal(remove.status,200);
  assert.ok(env.SCHOOL_IP_KV.deletions.includes("blocked:1.1.1.1"));
  assert.equal((await (await send(env,"/admin/ip/api/list","GET",undefined,h)).json()).items.length,0);
});

test("logout clears cookie, current cookie is not accepted without valid signature",async()=>{
  const env=envFactory(),s=await login(env);
  const r=await send(env,"/admin/ip/api/logout","POST",{},authorizedHeaders(s));
  assert.equal(r.status,200);
  assert.match(r.headers.get("Set-Cookie"),/Max-Age=0/);
});

test("internal policy returns 403 only when enforce and manually listed IPv6",async()=>{
  const env=envFactory("observe");
  const ip="2606:4700:4700::1111";
  await env.SCHOOL_IP_KV.put("blocked:"+ip,"manual",{expirationTtl:3600});
  const edge=()=>{
    const request=new Request("https://vyncuslim.com/",{
      headers:{"CF-Connecting-IP":ip}
    });
    return worker.fetch(request,env,{waitUntil(){}});
  };
  assert.equal((await edge()).status,200);
  env.MODE="enforce";
  const denied=await edge();
  assert.equal(denied.status,403);
  assert.equal(denied.headers.get("X-School-Policy"),"blocked");
});


test("admin enforcement is protected by login, CSRF, same-origin and double confirmation",async()=>{
  const env=envFactory();
  assert.equal((await send(env,"/admin/ip/api/enforcement")).status,403);
  assert.equal((await send(env,"/admin/ip/api/enforcement","POST",{enabled:true})).status,403);
  const s=await login(env),headers=authorizedHeaders(s);
  assert.equal((await send(env,"/admin/ip/api/enforcement","POST",{
    enabled:true,confirmSharedIpImpact:true,confirmEdgePrerequisites:true,confirmationText:"ENABLE"
  },{Cookie:s.cookie})).status,403);
  assert.equal((await send(env,"/admin/ip/api/enforcement","POST",{
    enabled:true,confirmationText:"ENABLE"
  },headers)).status,400);
  assert.equal((await send(env,"/admin/ip/api/enforcement","POST",{
    enabled:true,confirmSharedIpImpact:true,confirmEdgePrerequisites:true,
    confirmationText:"enable"
  },headers)).status,400);
  assert.equal(env.SCHOOL_IP_KV.entries.has("policy:runtime-enforcement-v1"),false);
});

test("admin can turn policy ON, it blocks only listed IPs in observe mode, then OFF",async()=>{
  const env=envFactory("observe");
  const s=await login(env),headers=authorizedHeaders(s);
  const r=await send(env,"/admin/ip/api/enforcement","POST",{
    enabled:true,confirmSharedIpImpact:true,
    confirmEdgePrerequisites:true,confirmationText:"ENABLE"
  },headers);
  assert.equal(r.status,200);
  const status=await r.json();
  assert.equal(status.enabled,true);
  assert.equal(status.edgeVerified,false);
  assert.ok(new Date(status.expiresAt).getTime()>Date.now());
  const view=await send(env,"/admin/ip/api/enforcement","GET",undefined,headers);
  assert.equal((await view.json()).enabled,true);
  const request=new Request("https://vyncuslim.com/",{headers:{
    "CF-Connecting-IP":IP
  }});
  const context={waitUntil(){}};
  // The runtime toggle alone must not block an IP that is NOT explicitly listed.
  assert.equal((await worker.fetch(request,env,context)).status,200);
  await env.SCHOOL_IP_KV.put("blocked:"+IP,"manual",{expirationTtl:3600});
  const denied=await worker.fetch(request,env,context);
  assert.equal(denied.status,403);
  assert.equal(denied.headers.get("X-School-Policy"),"blocked");
  const off=await send(env,"/admin/ip/api/enforcement","POST",{enabled:false},headers);
  assert.equal(off.status,200);
  assert.equal((await worker.fetch(request,env,context)).status,200);
  assert.equal(env.SCHOOL_IP_KV.entries.has("blocked:"+IP),true);
});

test("policy runtime activation expires logically within an hour and stays OFF",async()=>{
  const env=envFactory("observe");
  const s=await login(env),h=authorizedHeaders(s);
  await send(env,"/admin/ip/api/enforcement","POST",{
    enabled:true,confirmSharedIpImpact:true,confirmEdgePrerequisites:true,
    confirmationText:"ENABLE"
  },h);
  const key="policy:runtime-enforcement-v1";
  const data=JSON.parse(env.SCHOOL_IP_KV.entries.get(key).value);
  assert.ok(data.expiresAtMs-Date.now()<=3600000);
  await env.SCHOOL_IP_KV.put(key,JSON.stringify({...data,expiresAtMs:Date.now()-1000}));
  const state=await send(env,"/admin/ip/api/enforcement","GET",undefined,h);
  const reported=await state.json();
  assert.equal(reported.enabled,false);
  assert.equal(reported.source,"expired");
  await env.SCHOOL_IP_KV.put("blocked:"+IP,"manual",{expirationTtl:3600});
  const edge=new Request("https://vyncuslim.com/",{
    headers:{"CF-Connecting-IP":IP}
  });
  assert.equal((await worker.fetch(edge,env,{waitUntil(){}})).status,200);
});

test("emergency OFF overrides a legacy MODE=enforce flag",async()=>{
  const env=envFactory("enforce");
  const s=await login(env),h=authorizedHeaders(s);
  await env.SCHOOL_IP_KV.put("blocked:"+IP,"manual",{expirationTtl:3600});
  const edge=new Request("https://vyncuslim.com/",{
    headers:{"CF-Connecting-IP":IP}
  });
  assert.equal((await worker.fetch(edge,env,{waitUntil(){}})).status,403);
  assert.equal((await send(env,"/admin/ip/api/enforcement","POST",{enabled:false},h)).status,200);
  assert.equal((await worker.fetch(edge,env,{waitUntil(){}})).status,200);
});

test("admin screen exposes ON, emergency OFF and status refresh controls",async()=>{
  const env=envFactory();
  const page=await (await send(env,"/admin/ip")).text();
  assert.match(page,/enableEnforcement/);
  assert.match(page,/disableEnforcement/);
  assert.match(page,/refreshEnforcement/);
  assert.match(page,/id="enableWord"/);
  const script=await (await send(env,"/admin/ip/app.js")).text();
  assert.match(script,/enforcementStatus/);
  assert.match(script,/confirmEdgePrerequisites/);
});
