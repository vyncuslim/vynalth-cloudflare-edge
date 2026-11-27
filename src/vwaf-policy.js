/** VWAF Intelligence, Identity, Rate Shield and Response state transitions. */
export const HOSTS=Object.freeze(["vynalthai.com","search.vynalthai.com"]);
export const LIMITS=Object.freeze({DOC:120,IMAGE:3,SEARCH:15,SIGNUP:3,CHAT:10,LOGIN:5});
export const WINDOW=600000, BAN=259200000, RETAIN=604800000;
export const HARD_IDS=Object.freeze(["VWAF-101","VWAF-102","VWAF-103","VWAF-104","VWAF-105","VWAF-106"]);
export const IDS=Object.freeze(["VWAF-001","VWAF-002",...HARD_IDS,"VWAF-201","VWAF-202","VWAF-203","VWAF-204","VWAF-205","VWAF-206","VWAF-301","VWAF-302","VWAF-303","VWAF-304","VWAF-305","VWAF-306","VWAF-401","VWAF-402","VWAF-403"]);
export const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
export const uniq=a=>[...new Set(a)];
export function actorTransition(prior,input,now){
 const old=prior||{},mode=input.mode,kind=input.kind;
 // Keep active restrictions until expiry but do not enforce them in observe.
 const s={mode,kind,probes:[],buckets:{},blockedUntil:0,evidence:null,expiresAt:now+WINDOW};
 if(old.kind===kind){
  if(Number.isFinite(old.blockedUntil)&&old.blockedUntil>now)s.blockedUntil=old.blockedUntil;
  if(old.evidence?.at>now-RETAIN)s.evidence=old.evidence;
  if(old.mode===mode){
   s.probes=(Array.isArray(old.probes)?old.probes:[]).filter(x=>x.at>now-WINDOW&&x.at<=now&&UUID.test(x.id)&&Array.isArray(x.rules)).slice(-20);
   for(const k of Object.keys(LIMITS)){const b=old.buckets?.[k];if(b?.minute===Math.floor(now/60000)&&Number.isInteger(b.count)&&b.count>=0)s.buckets[k]={...b}}
  }
 }
 let newRestriction=false,candidate=false,rateExceeded=false,newRate=false;
 const rules=uniq((input.rules||[]).filter(x=>HARD_IDS.includes(x)));
 // Only signed host-bound device identities can receive automatic restrictions.
 // Network actors only get endpoint limits and repeat-probe candidates.
 if(!s.blockedUntil&&rules.length&&UUID.test(input.id)&&!s.probes.some(x=>x.id===input.id)){
  s.probes.push({id:input.id,at:now,rules});s.probes=s.probes.slice(-20);
  const categories=uniq(s.probes.flatMap(x=>x.rules));
  if(s.probes.length>=5&&categories.length>=3){
   candidate=true;
   s.evidence={at:now,expiresAt:now+RETAIN,kind,mode,requestIds:s.probes.map(x=>x.id),rules:categories,
    restricted:kind==="device"&&mode==="enforce"};
   if(s.evidence.restricted){s.blockedUntil=now+BAN;newRestriction=true}
   // Do not extend a restriction based on repeated hits. Reset evidence window.
   s.probes=[];
  }
 }
 const c=input.category;
 if(Object.hasOwn(LIMITS,c)){
  const minute=Math.floor(now/60000),b=s.buckets[c]||{minute,count:0};
  const previous=b.count;b.count=Math.min(LIMITS[c]+1,b.count+1);s.buckets[c]=b;
  rateExceeded=b.count>LIMITS[c];newRate=rateExceeded&&previous<=LIMITS[c];
 }
 s.expiresAt=Math.max(now+WINDOW,s.blockedUntil,s.evidence?.expiresAt||0);
 return {state:s,decision:{rateExceeded,newRate,candidate,newRestriction,blockedUntil:s.blockedUntil,
  evidence:candidate?s.evidence:null}};
}
export function sanitizeEvent(e){
 if(!e||!HOSTS.includes(e.host)||!UUID.test(e.request_id||"")||!["observe","enforce"].includes(e.mode)||
  !["observe","block","rate_limit","restriction","candidate"].includes(e.action))return null;
 const rule_ids=uniq(Array.isArray(e.rule_ids)?e.rule_ids.filter(x=>IDS.includes(x)):[]).slice(0,24);
 if(!rule_ids.length)return null;
 return {event:"VYNALTH_WAF_DECISION",version:"1.1.0",host:e.host,mode:e.mode,action:e.action,
  request_id:e.request_id,rule_ids,score:Math.max(0,Math.min(100,Number.isFinite(e.score)?Math.round(e.score):0)),
  actor_kind:["device","network"].includes(e.actor_kind)?e.actor_kind:"unknown"};
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
 return {seq:Number.isSafeInteger(s.seq)?s.seq:0,entries,channels,daily};
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
