import test from "node:test";
import assert from "node:assert/strict";
import { createHmac, randomBytes, webcrypto } from "node:crypto";
import { Script } from "node:vm";
import {
  handleUniversalConsent, consentRoot, signedSSO, shieldAccountExempt,
  CONSENT_DOMAINS, SHARED_NOTICE_VERSION
} from "./universal-consent.js";

if (!globalThis.crypto) globalThis.crypto=webcrypto;
const secretA="demo-cookie-signing-secret-12345678901234567890";
const secretB="demo-sso-issuer-secret-123456789012345678901234";
const policy="/__vynalth/consent";
const defaults={analytics:false,personalization:false,marketing:false};
const approved={analytics:true,personalization:true,marketing:false};
function fakeKV(){
 const contents=new Map();
 return {
  contents,
  async get(key){return contents.get(key)??null;},
  async put(key,data){contents.set(key,data);},
  async delete(key){contents.delete(key);},
  async list({prefix,limit=50,cursor}){
   const all=[...contents.keys()].filter(x=>x.startsWith(prefix)).sort();
   const offset=cursor?Number(cursor):0;
   return {keys:all.slice(offset,offset+limit).map(name=>({name})),
     cursor:offset+limit<all.length?String(offset+limit):"",
     list_complete:offset+limit>=all.length};
  }
 };
}
function env(){return {
 CONSENT_CMP_ENABLED:"true",CONSENT_KV:fakeKV(),
 CONSENT_COOKIE_SECRET:secretA,CONSENT_SSO_SIGNING_SECRET:secretB
}}
function issuer(host,status="normal",sub="user_12345678",email,verified=true){
 const claims={sub,host,status,sid:"session_12345678",
  exp:Math.floor(Date.now()/1000)+600,
  ...(email?{email,email_verified:verified}:{})};
 const payload=Buffer.from(JSON.stringify(claims)).toString("base64url");
 const tag=createHmac("sha256",secretB).update(payload).digest("base64url");
 return "__Secure-vynalth-sso="+payload+"."+tag;
}
function call(e,domain,path=policy+"/state",method="GET",body,cookies="",extra={}){
 const url=new URL("https://"+domain+path);
 const headers={Cookie:cookies};
 if(method!=="GET"){
  headers.Origin=url.origin;headers["Sec-Fetch-Site"]="same-origin";
  headers["Content-Type"]="application/json";
 }
 Object.assign(headers,extra); // tests must be able to override the Origin to simulate attacks
 const req=new Request(url,{method,headers,
  body:body===undefined?undefined:JSON.stringify(body)});
 return handleUniversalConsent(req,e,url,consentRoot(url.hostname));
}
async function begin(e,domain,sso=""){
 const res=await call(e,domain,policy+"/session","GET",undefined,sso);
 assert.equal(res.status,200);
 const json=await res.json();
 const csrfCookie=res.headers.get("Set-Cookie").split(";")[0];
 return {csrf:json.csrf,cookies:sso?[sso,csrfCookie].join("; "):csrfCookie};
}
function body(choices=approved,sharedScope=false,action="save"){
 return {action,choices,sharedScope,
  sharedScopeAcknowledged:sharedScope,noticeVersion:SHARED_NOTICE_VERSION};
}
async function update(e,domain,session,prefs){
 return call(e,domain,policy+"/preferences","POST",prefs,session.cookies,
  {"X-Vynalth-Consent-CSRF":session.csrf});
}
async function status(e,domain,cookie=""){
 const r=await call(e,domain,policy+"/state","GET",undefined,cookie);
 assert.equal(r.status,200);
 return r.json();
}
test("all seven registrable domains and their subdomains share only their own root",()=>{
 assert.deepEqual(CONSENT_DOMAINS,["vynalthai.com","vyncuslim.com","vynalthai.si","vyncuslim.si","sleepsomno.com","powiismunc.com","vitamindai.online"]);
 for(const root of CONSENT_DOMAINS){
  assert.equal(consentRoot(root),root);
  assert.equal(consentRoot("www."+root),root);
  assert.equal(consentRoot("api.admin."+root),root);
 }
 assert.equal(consentRoot("vyncuslim.com.attacker.invalid"),null);
 assert.equal(consentRoot("vitamindai.online"),"vitamindai.online");
});

test("CMP endpoints never handle normal web traffic and configuration defaults OFF",async()=>{
 const e=env();
 assert.equal(await call(e,"vyncuslim.com","/"),null);
 assert.equal((await call({...e,CONSENT_CMP_ENABLED:"false"},"vyncuslim.com")).status,503);
});

test("anonymous GET is opt-out by default and does not generate a tracking ID",async()=>{
 const e=env();
 const r=await call(e,"vyncuslim.com");
 const x=await r.json();
 assert.equal(x.authenticated,false);
 assert.deepEqual(x.choices,{essential:true,...defaults});
 assert.equal(r.headers.get("Set-Cookie"),null);
 assert.equal(e.CONSENT_KV.contents.size,0);
});

test("CSRF and Origin prevent anonymous unauthorized updates",async()=>{
 const e=env();
 const s=await begin(e,"vyncuslim.com");
 assert.equal((await call(e,"vyncuslim.com",policy+"/preferences","POST",body())).status,403);
 assert.equal((await call(e,"vyncuslim.com",policy+"/preferences","POST",body(),s.cookies,
   {"X-Vynalth-Consent-CSRF":"forged"})).status,403);
 const forged=await call(e,"vyncuslim.com",policy+"/preferences","POST",body(),s.cookies,
   {"X-Vynalth-Consent-CSRF":s.csrf,"Origin":"https://attacker.invalid"});
 assert.equal(forged.status,403);
 assert.equal(e.CONSENT_KV.contents.size,0);
});

test("anonymous site-specific consent is stored in KV with its own first-party Cookie",async()=>{
 const e=env(),domain="vyncuslim.com";
 const s=await begin(e,domain);
 const save=await update(e,domain,s,body());
 assert.equal(save.status,200);
 const setCookie=save.headers.get("Set-Cookie");
 assert.match(setCookie,/Domain=vyncuslim.com/);
 assert.match(setCookie,/SameSite=Lax/);
 assert.match(setCookie,/Secure/);
 const siteCookie=setCookie.split(";")[0];
 const a=await status(e,domain,siteCookie);
 assert.equal(a.choices.analytics,true);
 assert.equal(a.sharedAcrossDomains,false);
 const b=await status(e,"vyncuslim.si",siteCookie);
 assert.equal(b.choices.analytics,false);
});

test("a guest cannot opt into cross-domain synchronization",async()=>{
 const e=env();
 const s=await begin(e,"vynalthai.com");
 const r=await update(e,"vynalthai.com",s,body(approved,true));
 assert.equal(r.status,400);
 assert.equal((await r.json()).error,"SHARED_SCOPE_REQUIRES_VERIFIED_SSO_AND_EXPLICIT_NOTICE");
});

test("unsigned or forged SSO status never grants trust/contact/status exemption",async()=>{
 const e=env();
 for(const statusName of ["trust","contact","status"]){
  const c=issuer("vyncuslim.com",statusName);
  const request=new Request("https://vyncuslim.com/",{headers:{Cookie:c}});
  assert.equal(await shieldAccountExempt(request,e,"vyncuslim.com"),true);
  const forged=c.slice(0,-4)+"ABCD";
  const forgedRequest=new Request("https://vyncuslim.com/",{headers:{Cookie:forged}});
  assert.equal(await shieldAccountExempt(forgedRequest,e,"vyncuslim.com"),false);
  assert.equal(await shieldAccountExempt(request,e,"vynalthai.com"),false);
 }
});

test("authenticated and explicitly informed shared consent syncs across all 7 domains",async()=>{
 const e=env(),start="vynalthai.com";
 const s=await begin(e,start,issuer(start));
 const save=await update(e,start,s,body(approved,true));
 assert.equal(save.status,200);
 for(const root of CONSENT_DOMAINS){
  const state=await status(e,root,issuer(root));
  assert.equal(state.authenticated,true);
  assert.equal(state.choices.analytics,true,root);
  assert.equal(state.sharedAcrossDomains,true,root);
  assert.equal(state.choices.marketing,false,root);
 }
 assert.ok([...e.CONSENT_KV.contents.keys()].some(k=>k.includes(":shared:current")));
});

test("a missing shared-scope notice cannot synchronize affirmative consent",async()=>{
 const e=env(),root="vynalthai.com",s=await begin(e,root,issuer(root));
 const reqBody=body(approved,true);
 reqBody.noticeVersion="outdated";
 assert.equal((await update(e,root,s,reqBody)).status,400);
 for(const site of CONSENT_DOMAINS)
  assert.equal((await status(e,site,issuer(site))).choices.analytics,false);
});

test("authenticated site-specific consent does not silently share with siblings",async()=>{
 const e=env(),root="vyncuslim.com",s=await begin(e,root,issuer(root));
 const r=await update(e,root,s,body(approved,false));
 assert.equal(r.status,200);
 assert.equal((await status(e,root,issuer(root))).choices.analytics,true);
 assert.equal((await status(e,"vynalthai.si",issuer("vynalthai.si"))).choices.analytics,false);
});

test("cross-domain withdrawal overrides previous shared grant and creates separate immutable history",async()=>{
 const e=env(),root="vynalthai.com",s=await begin(e,root,issuer(root));
 assert.equal((await update(e,root,s,body(approved,true))).status,200);
 assert.equal((await update(e,root,s,body(defaults,false,"withdraw"))).status,200);
 for(const site of CONSENT_DOMAINS){
  const x=await status(e,site,issuer(site));
  assert.equal(x.choices.analytics,false);
  assert.equal(x.choices.personalization,false);
  assert.ok(x.withdrawnAt);
 }
 const history=await call(e,root,policy+"/history?scope=shared","GET",undefined,issuer(root));
 assert.equal(history.status,200);
 const events=(await history.json()).events;
 assert.equal(events.length,2);
 assert.ok(events.some(x=>x.action==="withdraw"));
 assert.ok(events.some(x=>x.action==="save"));
});

test("turning off prior shared consent revokes other domains but preserves site-only choices",async()=>{
 const e=env(),root="vynalthai.com",s=await begin(e,root,issuer(root));
 assert.equal((await update(e,root,s,body(approved,true))).status,200);
 const localOnly={analytics:true,personalization:false,marketing:false};
 const result=await update(e,root,s,body(localOnly,false));
 assert.equal(result.status,200);
 const home=await status(e,root,issuer(root));
 assert.equal(home.choices.analytics,true);
 assert.equal(home.sharedAcrossDomains,false);
 for(const domain of CONSENT_DOMAINS.filter(x=>x!==root)){
  const x=await status(e,domain,issuer(domain));
  assert.equal(x.choices.analytics,false,domain);
  assert.ok(x.withdrawnAt,domain);
 }
 const history=await call(e,root,policy+"/history?scope=shared","GET",undefined,issuer(root));
 assert.equal((await history.json()).events.filter(x=>x.action==="withdraw").length,1);
 const localChange=await update(e,root,s,body(localOnly,false));
 assert.equal(localChange.status,200);
 const historyAgain=await call(e,root,policy+"/history?scope=shared","GET",undefined,issuer(root));
 assert.equal((await historyAgain.json()).events.filter(x=>x.action==="withdraw").length,1);
});

test("guest withdrawal is confined to same domain and kept in KV history",async()=>{
 const e=env(),root="vyncuslim.si",s=await begin(e,root);
 const initial=await update(e,root,s,body());
 const c=initial.headers.get("Set-Cookie").split(";")[0];
 const session=await begin(e,root,c);
 const revoked=await update(e,root,session,body(defaults,false,"withdraw"));
 assert.equal(revoked.status,200);
 const state=await status(e,root,c);
 assert.equal(state.choices.analytics,false);
 assert.ok(state.withdrawnAt);
 const hist=await call(e,root,policy+"/history","GET",undefined,c);
 assert.equal((await hist.json()).events.length,2);
});

test("Safari and Firefox third-party-cookie blocking does not affect authenticated server-side sync",async()=>{
 const e=env(),root="vynalthai.com",s=await begin(e,root,issuer(root));
 await update(e,root,s,body(approved,true));
 for(const site of ["vyncuslim.com","vynalthai.si","vyncuslim.si"]){
  // No Cookie from vynalthai.com is shared. Each browser presents only its
  // own first-party SSO ticket verified against the same SSO signing key.
  const r=await call(e,site,policy+"/state","GET",undefined,issuer(site),{"Sec-Fetch-Site":"none"});
  assert.equal((await r.json()).choices.analytics,true);
  assert.match(r.headers.get("Set-Cookie"),new RegExp("Domain="+site.replaceAll(".","\\.")));
 }
});

test("consent page is navigable and contains all controls",async()=>{
 const e=env();
 const page=await call(e,"vynalthai.com",policy);
 const html=await page.text();
 assert.equal(page.status,200);
 assert.match(html,/Withdraw consent/);
 assert.match(html,/Cross-site sharing is optional/);
 const script=await call(e,"vynalthai.com",policy+"/client.js");
 assert.equal(script.status,200);
 const javascript=await script.text();
 assert.match(javascript,/X-Vynalth-Consent-CSRF/);
 assert.doesNotThrow(()=>new Script(javascript), "served client must parse as valid JavaScript");
});


async function linkFromPrimarySSO(e,target,role="status",email){
 // The target uses a first-party top-level navigation to vynalthai.com.
 const started=await call(e,target,policy+"/link");
 assert.equal(started.status,302);
 const stateCookie=started.headers.get("Set-Cookie").split(";")[0];
 assert.match(stateCookie,/__Secure-vynalth-consent-link=/);
 const authorize=new URL(started.headers.get("Location"));
 assert.equal(authorize.hostname,"vynalthai.com");
 assert.equal(authorize.pathname,policy+"/authorize");
 const hub=await call(e,"vynalthai.com",authorize.pathname+authorize.search,
   "GET",undefined,issuer("vynalthai.com",role,"user_12345678",email));
 assert.equal(hub.status,302);
 const callback=new URL(hub.headers.get("Location"));
 assert.equal(callback.hostname,target);
 assert.equal(callback.pathname,policy+"/callback");
 const completed=await call(e,target,callback.pathname+callback.search,
   "GET",undefined,stateCookie);
 assert.equal(completed.status,302);
 assert.equal(completed.headers.get("Location"),policy);
 const firstPartyCookie=completed.headers.getSetCookie()
   .find(x=>x.startsWith("__Secure-vynalth-sso=")).split(";")[0];
 assert.ok(firstPartyCookie);
 return {firstPartyCookie,started,hub,completed,callback,stateCookie};
}

test("vynalthai.com is canonical source for seven root-domain linked SSO sessions",async()=>{
 const e=env(),out={};
 for(const root of CONSENT_DOMAINS.slice(1)){
  const linked=await linkFromPrimarySSO(e,root,"contact");
  assert.match(linked.completed.headers.getSetCookie().join("\n"),
    new RegExp("Domain="+root.replaceAll(".","\\.")));
  const result=await call(e,root,policy+"/session","GET",
   undefined,linked.firstPartyCookie);
  const session=await result.json();
  assert.equal(session.authenticated,true,root);
  assert.equal(session.status,"contact",root);
  out[root]=linked.firstPartyCookie;
 }
 assert.equal(Object.keys(out).length,6);
});

test("verified school email claim survives all first-party domain links",async()=>{
 const e=env();
 for(const site of CONSENT_DOMAINS.slice(1)){
  const linked=await linkFromPrimarySSO(e,site,"trust",
   "student@student.powiis.edu.my");
  const req=new Request("https://"+site+"/c",{
   headers:{Cookie:linked.firstPartyCookie}});
  const identity=await signedSSO(req,e,site);
  assert.equal(identity.email,"student@student.powiis.edu.my");
  assert.equal(identity.email_verified,true);
  const raw=linked.firstPartyCookie.split("=")[1].split(".")[0];
  const data=JSON.parse(Buffer.from(raw,"base64url").toString("utf8"));
  assert.equal(data.email_verified,true);
  assert.equal(data.email,"student@student.powiis.edu.my");
 }
});

test("link callback cannot consume arbitrary or already consumed KV tickets",async()=>{
 const e=env(),target="vyncuslim.com";
 const linked=await linkFromPrimarySSO(e,target);
 const again=await call(e,target,linked.callback.pathname+linked.callback.search,
  "GET",undefined,linked.stateCookie);
 assert.equal(again.status,403);
 assert.equal((await again.json()).error,"SSO_CODE_EXPIRED_OR_USED");
 const tampered=await call(e,target,linked.callback.pathname+linked.callback.search,
  "GET",undefined,"__Secure-vynalth-consent-link=forged");
 assert.equal(tampered.status,403);
});

test("anonymous hub visitor is never silently linked to other registrable domains",async()=>{
 const e=env();
 const start=await call(e,"vyncuslim.si",policy+"/link");
 const authUrl=new URL(start.headers.get("Location"));
 const denied=await call(e,"vynalthai.com",authUrl.pathname+authUrl.search);
 assert.equal(denied.status,401);
 assert.equal([...e.CONSENT_KV.contents.keys()]
   .filter(x=>x.includes("sso-link:")).length,0);
});

test("hubs reject destinations outside seven-domain whitelist",async()=>{
 const e=env();
 for(const domain of ["attacker.invalid","powiismunc.com.attacker.invalid","fakevitamindai.online","localhost"]){
  const r=await call(e,"vynalthai.com",policy+"/authorize?client="+
    encodeURIComponent(domain)+"&state=forged","GET",undefined,
    issuer("vynalthai.com"));
  assert.equal(r.status,400);
 }
});

test("real linked SSO sessions synchronize an explicitly shared preference via KV",async()=>{
 const e=env();
 const s=await begin(e,"vynalthai.com",issuer("vynalthai.com","trust"));
 assert.equal((await update(e,"vynalthai.com",s,body(approved,true))).status,200);
 for(const site of CONSENT_DOMAINS.slice(1)){
  const linked=await linkFromPrimarySSO(e,site,"trust");
  const preferences=await status(e,site,linked.firstPartyCookie);
  assert.equal(preferences.choices.analytics,true,site);
  assert.equal(preferences.sharedAcrossDomains,true,site);
  assert.equal(preferences.authenticated,true,site);
 }
});

test("a cross-domain SSO status assertion does not bypass unlinked domain or independent WAF",async()=>{
 const e=env();
 const linked=await linkFromPrimarySSO(e,"vyncuslim.com","status");
 const request=new Request("https://vyncuslim.si/",{
  headers:{Cookie:linked.firstPartyCookie}
 });
 assert.equal(await shieldAccountExempt(request,e,"vyncuslim.si"),false);
});
