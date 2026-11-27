/** Internal Durable Object: actor counters, bounded evidence ledger and alerts. */
import {HOSTS,LIMITS,HARD_IDS,IDS,UUID,RETAIN,uniq,actorTransition,sanitizeEvent,freshLedger,reserveChannel,canonicalRestriction,reserveArchive,nextActorWake,reserveRestrictionDelivery} from "./vwaf-policy.js";
import {configuredChannels,sendDigest} from "./vwaf-alert.js";
import {archiveRestriction} from "./vwaf-archive.js";
const enc=new TextEncoder();
export async function evidenceDigest(value){
 const bytes=await crypto.subtle.digest("SHA-256",enc.encode(JSON.stringify(value)));
 return Array.from(new Uint8Array(bytes),v=>v.toString(16).padStart(2,"0")).join("");
}
const json=(value,status=200)=>Response.json(value,{status,headers:{"Cache-Control":"private, no-store"}});
/** Durable retry to the existing private ledger; same global archive queue and quotas. */
export async function deliverRestriction(env,evidence){
 const record=canonicalRestriction(evidence,Date.now());
 if(!record||!env?.SECURITY_DEVICE_RISK?.idFromName||!env?.VWAF_EVENT_BUDGET?.limit)return false;
 try{
  if((await env.VWAF_EVENT_BUDGET.limit({key:"restriction:"+record.host}))?.success!==true)return false;
  const ns=env.SECURITY_DEVICE_RISK;
  const event={host:record.host,mode:"enforce",action:"restriction",request_id:record.requestIds.at(-1),
   rule_ids:["VWAF-402"],score:100,actor_kind:"device",evidence_sha256:evidence.sha256};
  const r=await ns.get(ns.idFromName("vwaf:v1:ledger-v1")).fetch("https://vwaf.internal/",{
   method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({op:"event",event,evidence:record}),signal:AbortSignal.timeout(1200)});
  return r.ok&&(await r.json()).archiveAccepted===true;
 }catch{return false}
}
export class VynalthWafState{
 constructor(state,env){this.storage=state.storage;this.env=env}
 async wake(at){const existing=await this.storage.getAlarm();if(existing===null||existing>at)await this.storage.setAlarm(at)}
 async fetch(request){
  if(request.method!=="POST")return json({error:"method"},405);
  // Only Worker binding calls reach this object, never a public route.
  let x;try{x=await request.json()}catch{return json({error:"input"},400)}
  const now=Date.now();
  if(x?.op==="actor-status"){
   if(!HOSTS.includes(x.host)||x.kind!=="device")return json({error:"input"},400);
   const s=await this.storage.get("actor");
   return json({blockedUntil:s?.kind==="device"&&(!s.host||s.host===x.host)&&s.blockedUntil>now?s.blockedUntil:0});
  }
  if(x?.op==="actor"){
   if(!HOSTS.includes(x.host)||!UUID.test(x.id||"")||!["device","network"].includes(x.kind)||
     !["observe","enforce"].includes(x.mode)||!(x.category===null||Object.hasOwn(LIMITS,x.category))||
     !Array.isArray(x.rules)||x.rules.length>HARD_IDS.length||x.rules.some(r=>!HARD_IDS.includes(r)))return json({error:"input"},400);
   const out=await this.storage.transaction(async txn=>{
    const old=await txn.get("actor"),r=actorTransition(old,x,now);
    // Persist evidence in the same atomic transaction as restriction state.
    if(r.decision.evidence){
     r.state.evidence={...r.state.evidence,sha256:await evidenceDigest(r.state.evidence)};
     if(r.decision.newRestriction)r.state.delivery={sha256:r.state.evidence.sha256,state:"pending",attempts:0,nextAt:now+60000};
    }
    await txn.put("actor",r.state);
    return {...r.decision,evidence:r.decision.evidence?r.state.evidence:null,expiresAt:nextActorWake(r.state,now)};
   });
   await this.wake(out.expiresAt);
   return json(out);
  }
  if(x?.op==="event"){
   const event=sanitizeEvent(x.event);if(!event)return json({error:"event"},400);
   let archive=null;
   if(event.action==="restriction"&&event.evidence_sha256){
    const record=canonicalRestriction(x.evidence,now);
    if(record&&record.host===event.host&&record.requestIds.includes(event.request_id)&&await evidenceDigest(record)===event.evidence_sha256)
     archive={record,sha256:event.evidence_sha256,tries:0};
   }
   const outcome=await this.storage.transaction(async txn=>{
    const s=freshLedger(await txn.get("ledger"),now);
    const duplicate=s.entries.some(v=>v.event.request_id===event.request_id&&v.event.action===event.action&&v.event.actor_kind===event.actor_kind&&JSON.stringify(v.event.rule_ids)===JSON.stringify(event.rule_ids));
    if(!duplicate){
     const record={seq:++s.seq,at:now,event};
     s.entries.push({...record,sha256:await evidenceDigest(record)});s.entries=s.entries.slice(-128);
     const day=new Date(now).toISOString().slice(0,10);
     const counts=s.daily[day]||{total:0,byAction:{},byRule:{}};
     counts.total++;counts.byAction[event.action]=(counts.byAction[event.action]||0)+1;
     for(const id of event.rule_ids)counts.byRule[id]=(counts.byRule[id]||0)+1;
     s.daily[day]=counts;
    }
    let archiveAccepted=false;
    if(archive){
     const pending=s.archive.pending.some(a=>a.sha256===archive.sha256);
     const completed=s.archive.completed.find(a=>a.sha256===archive.sha256);
     if(pending||completed?.state==="archived")archiveAccepted=true;
     // A terminal failure is not retried through a second queue entry.
     else if(!completed){
      if(s.archive.pending.length<8){s.archive.pending.push(archive);archiveAccepted=true}
      else s.archive.dropped++;
     }
    }
    await txn.put("ledger",s);return{saved:!duplicate,archiveAccepted};
   });
   if(outcome.saved||outcome.archiveAccepted)await this.wake(now+(archive?60000:configuredChannels(this.env).length?900000:86400000));
   return json(outcome);
  }
  if(x?.op==="status"){
   const s=freshLedger(await this.storage.get("ledger"),now);
   // No actor identifiers or raw requests; verify stored evidence on read.
   const events=[];
   for(const e of s.entries.slice(-50).reverse()){
    const {sha256,...record}=e;
    events.push({...record,sha256,integrity:sha256===await evidenceDigest(record)});
   }
   return json({sequence:s.seq,daily:s.daily,retained:s.entries.length,events,
    archive:{pending:s.archive.pending.length,completed:s.archive.completed,dropped:s.archive.dropped,attempts24h:s.archive.attempts.length},
    channels:Object.fromEntries(Object.entries(s.channels).map(([k,v])=>[k,{configured:configuredChannels(this.env).includes(k),last:v.last,pending:Math.max(0,s.seq-v.cursor),attempts24h:v.attempts.length,nextAt:v.nextAt}]))});
  }
  return json({error:"operation"},400);
 }
 async alarm(){
  const now=Date.now(),actor=await this.storage.get("actor");
  if(actor){
   // Reserve before sending, persist attempts across restarts, never extend the ban.
   const plan=await this.storage.transaction(async txn=>{
    const s=await txn.get("actor");if(!s)return {next:0,job:null};
    if(s.expiresAt<=now){await txn.delete("actor");return {next:0,job:null}}
    const job=reserveRestrictionDelivery(s,now);
    if(job)await txn.put("actor",s);
    return {next:nextActorWake(s,now),job};
   });
   let next=plan.next;
   if(plan.job){
    const delivered=await deliverRestriction(this.env,plan.job);
    next=await this.storage.transaction(async txn=>{
     const s=await txn.get("actor");if(!s)return 0;
     if(s.delivery?.sha256===plan.job.sha256){
      s.delivery.state=delivered?"accepted":s.delivery.attempts>=3?"exhausted":"pending";
      await txn.put("actor",s);
     }
     return nextActorWake(s,Date.now());
    });
   }
   if(next>now)await this.wake(next);
   return;
  }
  const channels=configuredChannels(this.env);
  // Reserve attempts durably before I/O; no concurrent delivery or rapid retries.
  const plan=await this.storage.transaction(async txn=>{
   const s=freshLedger(await txn.get("ledger"),now),jobs=[];
   for(const name of channels){
    if(!reserveChannel(s,name,now))continue;
    const c=s.channels[name],recent=s.entries.filter(x=>x.seq>c.cursor);
    if(!recent.length){c.cursor=s.seq;c.last="unconfirmed";continue}
    jobs.push({name,sequence:s.seq,count:s.seq-c.cursor,mode:recent.some(x=>x.event.mode==="enforce")?"enforce":"observe",
     rules:uniq(recent.flatMap(x=>x.event.rule_ids)).slice(0,24)});
   }
   const archive=this.env?.VYNALTH_WAF_ARCHIVE_ENABLED==="true"&&this.env?.VWAF_EVIDENCE?reserveArchive(s,now):null;
   await txn.put("ledger",s);return {jobs,archive};
  });
  if(plan.archive){
   const result=await archiveRestriction(this.env,plan.archive,Date.now());
   await this.storage.transaction(async txn=>{
    const s=freshLedger(await txn.get("ledger"),Date.now()),a=s.archive,j=a.pending.find(v=>v.sha256===plan.archive.sha256);
    if(j&&(result.state==="archived"||result.state==="invalid"||j.tries>=3)){
     a.pending=a.pending.filter(v=>v.sha256!==j.sha256);
     a.completed.push({sha256:j.sha256,at:Date.now(),state:result.state,key:result.key||null});a.completed=a.completed.slice(-24);
    }
    await txn.put("ledger",s);
   });
  }
  for(const job of plan.jobs){
   const result=await sendDigest(job.name,this.env,job);
   await this.storage.transaction(async txn=>{
    const s=freshLedger(await txn.get("ledger"),Date.now()),c=s.channels[job.name];
    c.last=result.state;if(result.state==="sent")c.cursor=Math.max(c.cursor,job.sequence);
    if(Number.isFinite(result.nextAt))c.nextAt=Math.max(c.nextAt,result.nextAt);
    await txn.put("ledger",s);
   });
  }
  const s=freshLedger(await this.storage.get("ledger"),Date.now());
  if(s.entries.length||Object.keys(s.daily).length||s.archive.pending.length||s.archive.completed.length||s.archive.attempts.length){
   let at=Date.now()+86400000;
   for(const name of channels){const c=s.channels[name];if(c.cursor<s.seq&&s.entries.some(x=>x.seq>c.cursor)){
     const quota=c.attempts.length>=8?c.attempts[0]+86400000:0;
     at=Math.min(at,Math.max(Date.now()+900000,c.nextAt,quota));
   }}
   if(s.archive.pending.length&&this.env?.VYNALTH_WAF_ARCHIVE_ENABLED==="true"&&this.env?.VWAF_EVIDENCE){
    const a=s.archive,quota=a.attempts.length>=12?a.attempts[0]+86400000:0;
    at=Math.min(at,Math.max(Date.now()+60000,a.nextAt,quota));
   }
   await this.wake(at);
  }
 }
}
