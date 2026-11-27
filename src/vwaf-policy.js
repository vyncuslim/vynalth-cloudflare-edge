/** VWAF Intelligence, Identity, Rate Shield and Response state transitions. */
import {CORE_HOSTS,STATE_HOSTS} from "./vwaf-scope.js";
export const HOSTS=STATE_HOSTS;
export const LIMITS=Object.freeze({DOC:120,IMAGE:3,SEARCH:15,SIGNUP:3,CHAT:10,LOGIN:5});
export const WINDOW=600000, BAN=259200000, RETAIN=604800000;
export const HARD_IDS=Object.freeze(["VWAF-101","VWAF-102","VWAF-103","VWAF-104","VWAF-105","VWAF-106","VWAF-107","VWAF-108","VWAF-109","VWAF-110","VWAF-111"]);
export const IDS=Object.freeze(["VWAF-001","VWAF-002",...HARD_IDS,"VWAF-201","VWAF-202","VWAF-203","VWAF-204","VWAF-205","VWAF-206","VWAF-207","VWAF-208","VWAF-209","VWAF-210","VWAF-211","VWAF-301","VWAF-302","VWAF-303","VWAF-304","VWAF-305","VWAF-306","VWAF-401","VWAF-402","VWAF-403","VWAF-404","VWAF-501"]);
export const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
export const uniq=a=>[...new Set(a)];
export function actorTransition(prior,input,now){
 const old=prior||{},mode=input.mode,kind=input.kind,host=input.host;
 const s={mode,kind,host,probes:[],buckets:{},blockedUntil:0,evidence:null,expiresAt:now+WINDOW};
 if(old.kind===kind&&(!old.host||old.host===host)){
  if(Number.isFinite(old.blockedUntil)&&old.blockedUntil>now)s.blockedUntil=old.blockedUntil;
  if(old.evidence?.at>now-RETAIN){
   s.evidence=old.evidence;
   if(old.delivery?.sha256===old.evidence.sha256)s.delivery=old.delivery;
  }
  if(old.mode===mode){
   if(Number.isFinite(old.burstAt)&&old.burstAt>now-WINDOW&&old.burstAt<=now)s.burstAt=old.burstAt;
   s.probes=(Array.isArray(old.probes)?old.probes:[]).filter(x=>x.at>now-WINDOW&&x.at<=now&&UUID.test(x.id)&&Array.isArray(x.rules)).slice(-20);
   for(const k of Object.keys(LIMITS)){
    const b=old.buckets?.[k];
    // Old fixed-minute buckets are intentionally not promoted into sliding counters.
    if(Array.isArray(b?.hits))s.buckets[k]={hits:b.hits.filter(t=>Number.isFinite(t)&&t>now-60000&&t<=now).slice(-LIMITS[k]),over:b.over===true};
   }
  }
 }
 let newRestriction=false,candidate=false,burst=false,rateExceeded=false,newRate=false,retryAfterSeconds=0;
 const rules=uniq((input.rules||[]).filter(x=>HARD_IDS.includes(x)));
 if(!s.blockedUntil&&rules.length&&UUID.test(input.id)&&!s.probes.some(x=>x.id===input.id)){
  s.probes.push({id:input.id,at:now,rules});s.probes=s.probes.slice(-20);
  // Each request contributes at most one distinct primary category.
  const categories=uniq(s.probes.map(x=>x.rules[0]));
  if(s.probes.length>=5&&categories.length>=3){
   candidate=true;
   const restricted=kind==="device"&&mode==="enforce";
   if(restricted){s.blockedUntil=now+BAN;newRestriction=true}
   s.evidence={schema:"vwaf-restriction-v1",host,at:now,expiresAt:now+RETAIN,kind,mode,
    requestIds:s.probes.map(x=>x.id),rules:categories,observations:s.probes.map(x=>({id:x.id,at:x.at,rules:x.rules})),
    restricted,blockedUntil:s.blockedUntil};
   s.probes=[];
  }else if(s.probes.length>=10&&!s.burstAt){
   // Sustained same-class probes are useful evidence but not a device-ban trigger.
   s.burstAt=now;burst=true;
  }
 }
 const c=input.category;
 if(Object.hasOwn(LIMITS,c)){
  const b=s.buckets[c]||{hits:[],over:false};
  rateExceeded=b.hits.length>=LIMITS[c];
  newRate=rateExceeded&&!b.over;
  if(rateExceeded)retryAfterSeconds=Math.max(1,Math.ceil((b.hits[0]+60000-now)/1000));
  else b.hits.push(now);
  b.over=rateExceeded;s.buckets[c]=b;
 }
 s.expiresAt=Math.max(now+WINDOW,s.blockedUntil,s.evidence?.expiresAt||0);
 return {state:s,decision:{rateExceeded,newRate,retryAfterSeconds,candidate,burst,newRestriction,blockedUntil:s.blockedUntil,
  evidence:candidate?s.evidence:null}};
}
export function canonicalRestriction(e,now){
 if(!e||e.schema!=="vwaf-restriction-v1"||!HOSTS.includes(e.host)||e.kind!=="device"||e.mode!=="enforce"||e.restricted!==true||
   !Number.isSafeInteger(e.at)||e.at>now+1000||e.at<now-RETAIN||e.expiresAt!==e.at+RETAIN||e.blockedUntil!==e.at+BAN||
   !Array.isArray(e.observations)||e.observations.length<5||e.observations.length>20)return null;
 const observations=[];
 for(const x of e.observations){
  if(!UUID.test(x?.id||"")||!Number.isSafeInteger(x.at)||x.at<=e.at-WINDOW||x.at>e.at||
    !Array.isArray(x.rules)||!x.rules.length||x.rules.length>HARD_IDS.length||x.rules.some(r=>!HARD_IDS.includes(r))||uniq(x.rules).length!==x.rules.length)return null;
  observations.push({id:x.id,at:x.at,rules:x.rules});
 }
 const requestIds=observations.map(x=>x.id),rules=uniq(observations.map(x=>x.rules[0]));
 if(uniq(requestIds).length!==requestIds.length||rules.length<3||
  JSON.stringify(requestIds)!==JSON.stringify(e.requestIds)||JSON.stringify(rules)!==JSON.stringify(e.rules))return null;
 return {schema:"vwaf-restriction-v1",host:e.host,at:e.at,expiresAt:e.expiresAt,kind:"device",mode:"enforce",requestIds,rules,observations,restricted:true,blockedUntil:e.blockedUntil};
}
export function sanitizeEvent(e){
 if(!e||!CORE_HOSTS.includes(e.host)||!UUID.test(e.request_id||"")||!["observe","enforce"].includes(e.mode)||
  !["observe","block","rate_limit","restriction","candidate","honeypot"].includes(e.action))return null;
 const rule_ids=uniq(Array.isArray(e.rule_ids)?e.rule_ids.filter(x=>IDS.includes(x)):[]).slice(0,24);
 if(!rule_ids.length)return null;
 return {event:"VYNALTH_WAF_DECISION",version:"1.4.0",host:e.host,mode:e.mode,action:e.action,
  request_id:e.request_id,rule_ids,score:Math.max(0,Math.min(100,Number.isFinite(e.score)?Math.round(e.score):0)),
  actor_kind:["device","network"].includes(e.actor_kind)?e.actor_kind:"unknown",
  ...(e.action==="restriction"&&/^[a-f0-9]{64}$/.test(e.evidence_sha256||"")?{evidence_sha256:e.evidence_sha256}:{})};
}
export function freshLedger(prior,now){
 const s=prior||{};
 const entries=(Array.isArray(s.entries)?s.entries:[]).filter(x=>x.at>now-RETAIN).slice(-128);
 const channels={};
 for(const name of ["ntfy","telegram","axiom"]){
  const c=s.channels?.[name]||{};
  channels[name]={cursor:Number.isSafeInteger(c.cursor)?c.cursor:0,
   attempts:(Array.isArray(c.attempts)?c.attempts:[]).filter(x=>Number.isFinite(x)&&x>now-86400000&&x<=now).slice(-8),
   nextAt:Number.isFinite(c.nextAt)?c.nextAt:0,last:["sent","failed","rate_limited","unconfirmed","not_configured"].includes(c.last)?c.last:"not_configured"};
 }
 const daily={};for(const [k,v] of Object.entries(s.daily||{})){
  if(/^\d{4}-\d{2}-\d{2}$/.test(k)&&Date.parse(k)>now-RETAIN-86400000&&Date.parse(k)<=now)daily[k]=v;
 }
 // Critical evidence dedup survives eviction from the ordinary 128-event ring.
 const restrictionSeen=(Array.isArray(s.restrictionSeen)?s.restrictionSeen:[])
  .filter(x=>x.at>now-RETAIN&&x.at<=now&&/^[a-f0-9]{64}$/.test(x.sha256||"")).slice(-64);
 const archive=s.archive||{};
 const pending=(Array.isArray(archive.pending)?archive.pending:[]).filter(x=>x?.record?.expiresAt>now&&/^[a-f0-9]{64}$/.test(x.sha256||"")).slice(0,8);
 const attempts=(Array.isArray(archive.attempts)?archive.attempts:[]).filter(x=>Number.isFinite(x)&&x>now-86400000&&x<=now).slice(-12);
 const completed=(Array.isArray(archive.completed)?archive.completed:[]).filter(x=>x.at>now-RETAIN).slice(-24);
 return {seq:Number.isSafeInteger(s.seq)?s.seq:0,entries,channels,daily,restrictionSeen,archive:{pending,attempts,completed,
  dropped:Number.isSafeInteger(archive.dropped)?archive.dropped:0,nextAt:Number.isFinite(archive.nextAt)?archive.nextAt:0}};
}
/** A restriction remains atomically recorded on its actor even if event delivery fails. */
export function nextActorWake(s,now){
 const d=s?.delivery;
 return d?.state==="pending"&&d.attempts<3&&Number.isFinite(d.nextAt)?
  Math.min(s.expiresAt,Math.max(now+1000,d.nextAt)):s.expiresAt;
}
export function reserveRestrictionDelivery(s,now){
 const d=s?.delivery;
 if(!d||d.state!=="pending"||d.attempts>=3||d.nextAt>now||d.sha256!==s.evidence?.sha256||
  !canonicalRestriction(s.evidence,now))return null;
 d.attempts++;d.nextAt=now+900000;
 return structuredClone(s.evidence);
}
export function reserveArchive(s,now){
 const a=s.archive;
 if(a.nextAt>now)return null;
 // If a runtime restart interrupts the final I/O, the durable attempt count
 // still prevents a fourth attempt. Terminal state is explicitly unconfirmed.
 const exhausted=a.pending.filter(j=>j.tries>=3);
 for(const j of exhausted){
  a.completed.push({sha256:j.sha256,at:now,state:"unconfirmed",key:null});
 }
 if(exhausted.length){a.pending=a.pending.filter(j=>!(j.tries>=3));a.completed=a.completed.slice(-24)}
 if(!a.pending.length||a.attempts.length>=12)return null;
 const j=a.pending[0];j.tries=(Number.isInteger(j.tries)?j.tries:0)+1;
 a.attempts.push(now);a.nextAt=now+900000;return structuredClone(j);
}
/** Short-lived internal operation receipts prevent retry-driven counter inflation. */
export function actorReceipts(old,input,now){
 if(old?.host!==input.host||old?.kind!==input.kind||old?.mode!==input.mode)return [];
 return (Array.isArray(old.receipts)?old.receipts:[]).filter(x=>UUID.test(x.id||"")&&Number.isFinite(x.at)&&
  x.at>now-15000&&x.at<=now&&x.decision&&Array.isArray(x.rules)).slice(-128);
}
export function reserveChannel(state,name,now){
 const c=state.channels[name];
 if(!c||c.cursor>=state.seq||c.attempts.length>=8||c.nextAt>now)return false;
 c.attempts.push(now);c.nextAt=now+900000;return true;
}
export function retryDeadline(header,now,fallback=3600000){
 const v=typeof header==="string"?header.trim():"";
 if(/^\d{1,15}$/.test(v)){const n=Number(v)*1000;if(Number.isSafeInteger(n)&&Number.isSafeInteger(now+n))return now+Math.max(900000,n)}
 if(v){const n=Date.parse(v);if(Number.isFinite(n)&&n>now)return Math.max(now+900000,n)}
 return now+fallback;
}
