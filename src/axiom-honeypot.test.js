import test from "node:test";
import assert from "node:assert/strict";
import {
  buildAxiomSecurityEvent, classifyNetworkAttribution,
  dispatchAxiomSecurityEvent, scheduleAxiomSecurityEvent,
} from "./axiom-honeypot.js";
import { classifyEdgeAlert } from "./edge-telegram-alert.js";
import { formatEdgeSecurityAlert } from "./edge-alert-details.js";

const BASE="https://vynalthai.com";
const KEY="a".repeat(64);
const ENV={AXIOM_HONEYPOT_INGEST_ENABLED:"true",
  AXIOM_INGEST_TOKEN:"b".repeat(64),AXIOM_HONEYPOT_ACTOR_SECRET:KEY};
const stamp=Date.parse("2026-11-10T08:00:00Z");
function req(path="/phpmyadmin/index.php",ip="198.51.100.19",cf=true){
  const r=new Request(BASE+path+"?token=SHOULD_NOT_LEAK",{
    headers:{ "CF-Connecting-IP":ip, "User-Agent":"Twitterbot/1.0",
      "Cookie":"session=SHOULD_NOT_LEAK",
      "Authorization":"Bearer SHOULD_NOT_LEAK",
      "X-Vynalth-Device-Id":"7daa1451-7e83-4cb2-8b14-fcb4beef46fd" }});
  if(cf)Object.defineProperty(r,"cf",{value:{country:"US",regionCode:"WA"}});
  return r;
}
function args(r=req(),kind="database",status=200){
  return {request:r,url:new URL(r.url),requestId:"11111111-2222-3333-4444-555555555555",
    path:"/phpmyadmin/index.php",status,kind,env:ENV,now:stamp};
}

test("network provenance does not confuse Cloudflare's proxy with visitor IP",()=>{
  const cross=req("/phpmyadmin/index.php","2a06:98c0:3600::103");
  assert.equal(classifyNetworkAttribution(cross).attribution,"cloudflare_cross_zone_worker_proxy");
  assert.equal(classifyNetworkAttribution(cross).ip,null);
  assert.equal(classifyNetworkAttribution(req()).attribution,"cloudflare_edge_observed");
  assert.equal(classifyNetworkAttribution(req("/phpmyadmin/index.php","2a03:2880:27ff:43::")).attribution,"cloudflare_edge_observed");
  assert.equal(classifyNetworkAttribution(req("/phpmyadmin/index.php","198.51.100.19",false)).attribution,"unknown");
});

test("event is privacy-bounded, bot label is a claim, hash rotates daily",async()=>{
  const r=req();
  const e=await buildAxiomSecurityEvent(args(r));
  assert.equal(e.event,"HONEYPOT_TRIGGER");
  assert.equal(e.path,"/phpmyadmin/index.php");
  assert.equal(e.host,"vynalthai.com");
  assert.equal(e.status_code,200);
  assert.equal(e.origin_ip_verified,false);
  assert.equal(e.action,"observe_decoy");
  assert.equal(e.bot_claim,"Twitterbot_claimed");
  assert.equal(e.network_actor_id.length,64);
  const next=await buildAxiomSecurityEvent({...args(r),now:stamp+86400000});
  const same=await buildAxiomSecurityEvent(args(r));
  assert.notEqual(next.network_actor_id,e.network_actor_id);
  assert.equal(same.network_actor_id,e.network_actor_id);
  const other=await buildAxiomSecurityEvent(args(req("/phpmyadmin/index.php","198.51.100.20")));
  assert.notEqual(other.network_actor_id,e.network_actor_id);
  const proxy=await buildAxiomSecurityEvent(args(req("/phpmyadmin/index.php","2a06:98c0:3600::103")));
  assert.equal(proxy.network_actor_id,null);
  assert.equal(proxy.country,null);
  const forged=await buildAxiomSecurityEvent(args(req("/phpmyadmin/index.php","198.51.100.19",false)));
  assert.equal(forged.network_actor_id,null);
  const raw=JSON.stringify(e);
  for(const value of ["SHOULD_NOT_LEAK","198.51.100.19","Bearer","session=","7daa1451-7e83-4cb2-8b14-fcb4beef46fd","27ff:43::"]){
    assert.equal(raw.includes(value),false,value);
  }
});

test("Axiom dispatch sends only a bounded JSON event, acknowledges ingest",async()=>{
  const sent=[];
  const fetchImpl=async(url,options)=>{
    sent.push({url,options});
    return new Response(JSON.stringify({ingested:1,failed:0,failures:[]}),{status:200});
  };
  const result=await dispatchAxiomSecurityEvent(args(),fetchImpl);
  assert.equal(result.state,"ingested");
  assert.equal(sent.length,1);
  assert.equal(sent[0].url,"https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-security-logs");
  assert.equal(sent[0].options.redirect,"manual");
  const body=JSON.parse(sent[0].options.body);
  assert.equal(body.length,1);
  assert.equal(body[0].event,"HONEYPOT_TRIGGER");
  assert.equal(body[0].status_code,200);
  for(const secret of ["SHOULD_NOT_LEAK","198.51.100.19",ENV.AXIOM_INGEST_TOKEN])
    assert.equal(sent[0].options.body.includes(secret),false);
});

test("disabled or missing credentials fail closed; Axiom failures do not affect HTTP",async()=>{
  const noConfig={...args(),env:{AXIOM_HONEYPOT_INGEST_ENABLED:"true"}};
  assert.equal((await dispatchAxiomSecurityEvent(noConfig)).state,"not_configured");
  assert.equal((await dispatchAxiomSecurityEvent({...args(),env:{}})).state,"disabled");
  const report=await dispatchAxiomSecurityEvent(args(),async()=>
    new Response(JSON.stringify({ingested:0,failed:1}),{status:200}));
  assert.equal(report.state,"unconfirmed");
  const warn=console.warn;console.warn=()=>{};
  try{
    const failed=await dispatchAxiomSecurityEvent(args(),async()=>{throw Error("network offline")});
    assert.equal(failed.state,"failed");
  }finally{console.warn=warn}
  // Scheduler executes via waitUntil; intercept global fetch in this fixture.
  const oldFetch=globalThis.fetch;
  const tasks=[];
  globalThis.fetch=async()=>new Response(JSON.stringify({ingested:1,failed:0}),{status:200});
  try{
    assert.equal(scheduleAxiomSecurityEvent({...args(),ctx:{waitUntil(p){tasks.push(p)}}}),true);
    await Promise.all(tasks);
    assert.equal(tasks.length,1);
  }finally{globalThis.fetch=oldFetch}
});

test("301 canonical redirect is INFO, never an intrusion claim",()=>{
  const request=new Request("https://www.vynalthai.com/robots.txt");
  const response=new Response(null,{status:301,headers:{
    Location:"https://vynalthai.com/robots.txt"
  }});
  const issue=classifyEdgeAlert(request,response,{EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS:"true"});
  assert.equal(issue.code,"HTTP_REQUEST");
  assert.equal(issue.severity,"Info");
  assert.match(issue.description,/Expected www-to-apex canonical redirect/);
  const msg=formatEdgeSecurityAlert({
    request,url:new URL(request.url),response,issue,requestId:"test-id",responseTimeMs:3,
  });
  assert.match(msg,/Status Code: 301/);
  assert.match(msg,/no intrusion evidence/);
});

test("cross-zone shared IP is not reported as visitor-verified",()=>{
  const request=req("/phpmyadmin/index.php","2a06:98c0:3600::103");
  const response=new Response(null,{status:200});
  const message=formatEdgeSecurityAlert({
    request,url:new URL(request.url),response,
    issue:{code:"SUSPICIOUS_PROBE",severity:"Warning"},
    requestId:"test-id",responseTimeMs:12,
  });
  assert.match(message,/Ip Verified: false/);
  assert.match(message,/Ip Source: cloudflare_cross_zone_worker_ip/);
  assert.match(message,/Visitor Attribution: unknown/);
  assert.match(message,/Country: Unknown/);
});
