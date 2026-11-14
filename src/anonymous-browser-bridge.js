/**
 * Explicit-consent, anonymous browser identity federation.
 *
 * The user voluntarily visits the destination's /bridge endpoint, reviews
 * the central vynalthai.com consent screen, and clicks Approve. Nothing is
 * attached to ordinary anonymous navigation; no tracking redirect, login,
 * fingerprint, third-party cookie or browser/physical-device assertion.
 *
 * Each registrable domain keeps its own HMAC-verified first-party cookie.
 * Central approval signs a host+local-ID+nonce-bound short-lived grant,
 * transmitted only as a URL fragment and then POSTed to the target origin.
 * CONSENT_KV is a revocable pseudonymous association store, never auth.
 */
import {getRootBrowserIdentity,buildRootBrowserCookie} from './global-browser-id.js';

const PATH='/__vynalth/browser/bridge';
const CENTRAL='vynalthai.com';
const CENTRAL_ORIGIN='https://'+CENTRAL;
const TARGETS=new Set(['vynlink.xyz','zokivo.xyz']);
const NONCE_COOKIE='__Host-vyn_browser_bridge_state';
const OPT_OUT_COOKIE='__Secure-vyn_browser_bridge_optout';
const GRANT_TTL=300;
const LINK_TTL=90*86400;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NONCE=/^[A-Za-z0-9_-]{22}$/;
const CODE=/^[A-Za-z0-9_-]{24,900}\.[A-Za-z0-9_-]{43}$/;
const encoder=new TextEncoder();
const HEADERS={
  'Content-Type':'text/html; charset=utf-8',
  'Cache-Control':'private, no-store, max-age=0',
  'Referrer-Policy':'no-referrer',
  'X-Robots-Tag':'noindex, nofollow, noarchive',
  'X-Content-Type-Options':'nosniff',
  'X-Frame-Options':'DENY',
  'Cross-Origin-Resource-Policy':'same-origin',
  'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'",
};

function secret(env){
  if(env?.ANON_BROWSER_BRIDGE_ENABLED!=='true'||env?.ROOT_BROWSER_ID_ENABLED!=='true'
      ||env?.EDGE_DEVICE_ID_ENABLED!=='true')return '';
  const dedicated=String(env?.EDGE_DEVICE_ID_SIGNING_SECRET||'');
  if(dedicated.length>=32)return dedicated;
  if(env?.EDGE_DEVICE_ALLOW_DERIVED_KEY==='true'){
    const shared=String(env?.VISITOR_IP_SIGNING_SECRET||'');
    if(shared.length>=32)return shared;
  }
  return '';
}
function storage(env){
  const k=env?.CONSENT_KV;
  return k&&typeof k.get==='function'&&typeof k.put==='function'&&typeof k.delete==='function'?k:null;
}
function b64(bytes){
  let s='';
  for(const b of bytes)s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
function unpack(value){
  if(typeof value!=='string'||value.length>1800||!/^[A-Za-z0-9_-]+$/.test(value))return null;
  try{
    const bytes=Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')
      +'='.repeat((4-value.length%4)%4)),x=>x.charCodeAt(0));
    return b64(bytes)===value?bytes:null;
  }catch{return null;}
}
function nonce(){return b64(crypto.getRandomValues(new Uint8Array(16)));}
async function key(material){
  const digest=await crypto.subtle.digest('SHA-256',
    encoder.encode('vynalth-anonymous-browser-bridge-signing:v1:'+material));
  return crypto.subtle.importKey('raw',digest,{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
async function signed(payload,material){
  const body=b64(encoder.encode(JSON.stringify(payload)));
  const mac=await crypto.subtle.sign('HMAC',await key(material),encoder.encode(body));
  return body+'.'+b64(new Uint8Array(mac));
}
async function verified(token,material,kind,nowMs=Date.now()){
  if(!CODE.test(String(token||'')))return null;
  const [body,proof]=token.split('.');
  const bytes=unpack(body),mac=unpack(proof);
  if(!bytes||!mac||mac.length!==32)return null;
  const ok=await crypto.subtle.verify('HMAC',await key(material),mac,encoder.encode(body));
  if(!ok)return null;
  let data;
  try{data=JSON.parse(new TextDecoder().decode(bytes));}catch{return null;}
  if(!data||data.kind!==kind||!TARGETS.has(data.host)
    ||!UUID.test(String(data.local||''))||!NONCE.test(String(data.nonce||''))
    ||!Number.isSafeInteger(data.ts)||Math.abs(Math.floor(nowMs/1000)-data.ts)>GRANT_TTL
    ||(kind==='grant'&&!UUID.test(String(data.global||''))))return null;
  return data;
}
function nonceCookie(request){
  const list=String(request.headers.get('cookie')||'').split(';').map(x=>x.trim())
    .filter(x=>x.startsWith(NONCE_COOKIE+'='));
  if(list.length!==1)return '';
  return list[0].slice(NONCE_COOKIE.length+1);
}
function setCookie(response,cookie){
  const h=new Headers(response.headers);h.append('Set-Cookie',cookie);
  return new Response(response.body,{status:response.status,headers:h});
}
function setIdentityCookie(response,state){
  return state.shouldSetCookie?setCookie(response,buildRootBrowserCookie(state.token,state.root)):response;
}
function clearNonce(response){
  return setCookie(response,NONCE_COOKIE+'=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax');
}
function revokeCookie(host){
  return OPT_OUT_COOKIE+'=1; Domain='+host+'; Path=/; Max-Age='+LINK_TTL
    +'; Secure; HttpOnly; SameSite=Lax';
}
function clearRevokeCookie(host){
  return OPT_OUT_COOKIE+'=; Domain='+host+'; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax';
}
function locallyRevoked(request){
  return String(request?.headers?.get('cookie')||'').split(';')
    .some(item=>item.trim()===OPT_OUT_COOKIE+'=1');
}
function allowedPost(request,host){
  return request.method==='POST'
    && request.headers.get('Origin')==='https://'+host
    && request.headers.get('Sec-Fetch-Site')==='same-origin'
    && String(request.headers.get('Content-Type')||'').startsWith('application/x-www-form-urlencoded');
}
async function form(request){
  if(Number(request.headers.get('Content-Length')||0)>4000)return null;
  try{
    const raw=await request.text();
    return raw.length<=4000?new URLSearchParams(raw):null;
  }catch{return null;}
}
function html(title,body,status=200){
  const page='<!doctype html><html lang="zh"><head><meta charset="utf-8">'
    +'<meta name="viewport" content="width=device-width,initial-scale=1">'
    +'<title>'+title+' · Vynalth AI</title>'
    +'<style>body{margin:0;min-height:100vh;display:grid;place-items:center;'
    +'font:16px system-ui,sans-serif;color:#142238;background:linear-gradient(120deg,#9fb6d9,#d9f0e3);padding:20px}'
    +'main{max-width:560px;background:#fffefaed;border:1px solid #ffffff88;border-radius:18px;'
    +'box-shadow:0 18px 55px #14223822;padding:32px}h1{font-size:24px}'
    +'button,.button{display:inline-block;border:0;border-radius:9px;background:#265b9d;color:#fff;'
    +'font:inherit;font-weight:650;padding:13px 18px;cursor:pointer;text-decoration:none}'
    +'p{line-height:1.6}small{color:#465c6d}form{margin-top:22px}</style></head>'
    +'<body><main><h1>'+title+'</h1>'+body+'</main></body></html>';
  return new Response(page,{status,headers:HEADERS});
}
function failure(message,status=400){return html('无法关联浏览器身份','<p>'+message+'</p>',status);}
function redirect(location){
  return new Response(null,{status:303,headers:{
    'Location':location,'Referrer-Policy':'no-referrer',
    'Cache-Control':'private, no-store, max-age=0','X-Robots-Tag':'noindex, nofollow'
  }});
}
function linkKey(host,id){return 'gbid:consented-link:v1:'+host+':'+id;}

/** Only explicit first-party links can override the root-scoped display ID. */
export async function readConsentedBrowserLink(env,root,localId,request){
  // Immediate browser-local opt-out overrides an eventually consistent KV
  // replica. New user consent clears this first-party root-scoped cookie.
  if(locallyRevoked(request))return null;
  if(!secret(env)||!storage(env)||!TARGETS.has(root)||!UUID.test(String(localId||'')))return null;
  try {
    const row=await storage(env).get(linkKey(root,localId),'json');
    return row?.consent===true&&UUID.test(String(row.global||''))?row.global.toLowerCase():null;
  }catch{return null;}
}

/** Route handler called AFTER existing temporary bans/WAF, BEFORE GPS. */
export async function handleAnonymousBrowserBridge(request,env,url){
  if(!url.pathname.startsWith(PATH))return null;
  const central=url.hostname===CENTRAL;
  const target=TARGETS.has(url.hostname);
  if(!central&&!target)return null;
  if(url.pathname===PATH+'/health'){
    if(request.method!=='GET')return new Response(JSON.stringify({error:'METHOD_NOT_ALLOWED'}),{
      status:405,headers:{'Content-Type':'application/json','Cache-Control':'no-store','Allow':'GET'}
    });
    const enabled=Boolean(secret(env)&&storage(env));
    return new Response(JSON.stringify({
      service:'vynalth-anonymous-browser-bridge',
      version:'consent-v1',
      enabled,
      host:url.hostname,
      consentRequired:true,
      crossBrowserLinking:false,
      securityAuthorization:false,
    }),{status:enabled?200:503,headers:{
      'Content-Type':'application/json; charset=utf-8',
      'Cache-Control':'private, no-store, max-age=0',
      'X-Robots-Tag':'noindex, nofollow',
      'X-Content-Type-Options':'nosniff',
      'Access-Control-Allow-Credentials':'false',
    }});
  }
  if(url.pathname!==PATH&&url.pathname!==PATH+'/complete'&&url.pathname!==PATH+'/script.js'
     &&url.pathname!==PATH+'/unlink')return null;
  if(!secret(env)||!storage(env))return failure('服务未配置，关联未启用。',503);
  const material=secret(env);

  if(target&&url.pathname===PATH+'/script.js'){
    if(request.method!=='GET')return failure('不支持此请求。',405);
    const js="(()=>{try{const m=/^#grant=([A-Za-z0-9_-]{24,900}\\.[A-Za-z0-9_-]{43})$/.exec(location.hash);if(!m)return;history.replaceState(null,'',location.pathname+location.search);const f=document.getElementById('bridge-form');if(!f)return;f.elements.namedItem('grant').value=m[1];f.requestSubmit();}catch{}})();";
    return new Response(js,{status:200,headers:{
      'Content-Type':'text/javascript; charset=utf-8','Cache-Control':'public, max-age=3600',
      'X-Content-Type-Options':'nosniff','Cross-Origin-Resource-Policy':'same-origin',
      'X-Robots-Tag':'noindex'
    }});
  }

  if(central&&url.pathname===PATH){
    if(request.method==='GET'){
      const data=await verified(url.searchParams.get('request'),material,'request');
      if(!data)return failure('请求已过期或签名无效，请从原网站重新开始。',403);
      const state=await getRootBrowserIdentity(request,env);
      if(state.state==='disabled')return failure('中央浏览器签名服务不可用。',503);
      const reply=html('授权共享匿名 Browser ID',
        '<p>你正在选择把本浏览器在 <strong>'+data.host
        +'</strong> 的匿名 ID 与 Vynalth AI 中央 Browser ID 关联。</p>'
        +'<p>不需要登录。两个域名各自保留 Cookie；不读取硬件、不读取 IP，'
        +'也不会在其他浏览器中自动识别你。你可在原网站解除关联。</p>'
        +'<form method="post" action="'+PATH+'">'
        +'<input type="hidden" name="request" value="'+url.searchParams.get('request')+'">'
        +'<input type="hidden" name="consent" value="yes">'
        +'<button type="submit">我同意关联这个浏览器</button></form>'
        +'<p><small>不点击则不会关联。授权凭证五分钟内有效。</small></p>');
      return setIdentityCookie(reply,state);
    }
    if(!allowedPost(request,CENTRAL))return failure('来源验证失败。',403);
    const values=await form(request);
    if(values?.get('consent')!=='yes')return failure('未取得同意。',403);
    const stateRequest=await verified(values.get('request'),material,'request');
    if(!stateRequest)return failure('关联请求过期或已被修改。',403);
    const centralId=await getRootBrowserIdentity(request,env);
    if(centralId.state!=='valid'&&centralId.state!=='rotated')
      return failure('请重新打开中央授权页面，保存第一方浏览器 Cookie。',428);
    const grant=await signed({
      kind:'grant',host:stateRequest.host,local:stateRequest.local,
      nonce:stateRequest.nonce,global:centralId.id,ts:Math.floor(Date.now()/1000)
    },material);
    return redirect('https://'+stateRequest.host+PATH+'/complete#grant='+grant);
  }

  if(target&&url.pathname===PATH&&request.method==='GET'){
    const state=await getRootBrowserIdentity(request,env);
    if(state.state==='disabled')return failure('本站匿名浏览器 ID 暂不可用。',503);
    const challenge=nonce();
    const issued=await signed({kind:'request',host:url.hostname,
      local:state.id,nonce:challenge,ts:Math.floor(Date.now()/1000)},material);
    let response=redirect(CENTRAL_ORIGIN+PATH+'?request='+encodeURIComponent(issued));
    response=setIdentityCookie(response,state);
    return setCookie(response,NONCE_COOKIE+'='+challenge
      +'; Path=/; Max-Age=300; Secure; HttpOnly; SameSite=Lax');
  }

  if(target&&url.pathname===PATH+'/complete'){
    if(request.method==='GET')return html('正在完成匿名身份关联',
      '<p>已获中央服务授权。浏览器正在验证本站签名凭证。</p>'
      +'<form id="bridge-form" action="'+PATH+'/complete" method="post">'
      +'<input type="hidden" name="grant" value="">'
      +'<button type="submit">完成关联</button></form>'
      +'<script src="'+PATH+'/script.js" defer></script>');
    if(!allowedPost(request,url.hostname))return failure('来源验证失败。',403);
    const values=await form(request);
    const grant=await verified(values?.get('grant'),material,'grant');
    if(!grant||grant.host!==url.hostname)return failure('授权凭证无效或已过期。',403);
    const state=await getRootBrowserIdentity(request,env);
    if(state.state!=='valid'&&state.state!=='rotated')return failure('本站身份验证失败，请重试。',428);
    if(grant.local!==state.id||grant.nonce!==nonceCookie(request))
      return failure('此授权不属于本浏览器，请重新开始。',403);
    try {
      // KV is eventually consistent. This mapping is deliberately only a
      // revocable display association, never a security or authorization key.
      await storage(env).put(linkKey(url.hostname,state.id),JSON.stringify({
        global:grant.global,host:url.hostname,consent:true,linkedAt:Date.now(),
      }),{expirationTtl:LINK_TTL});
    }catch{return failure('关联储存不可用。',503);}
    return setCookie(clearNonce(html('匿名 Browser ID 已关联',
      '<p>✅ <strong>'+url.hostname+'</strong> 已通过中央授权关联。</p>'
      +'<p>返回本站时，将可查询同一个统一 Browser ID。</p>'
      +'<p><a class="button" href="/">返回网站</a></p>'
      +'<p><small>本关联不是硬件身份验证，也不会改变现有设备封锁策略。</small></p>')),clearRevokeCookie(url.hostname));
  }

  if(target&&url.pathname===PATH+'/unlink'){
    if(request.method==='GET')return html('解除匿名身份关联',
      '<p>此操作会解除本站 Browser ID 与中央 ID 的关联，'
      +'但不会删除其他网站的 Cookie 或账号。</p>'
      +'<form method="post" action="'+PATH+'/unlink">'
      +'<button type="submit">确认解除关联</button></form>');
    if(!allowedPost(request,url.hostname))return failure('来源验证失败。',403);
    const state=await getRootBrowserIdentity(request,env);
    if(state.state!=='valid'&&state.state!=='rotated')return failure('本站身份验证失败。',428);
    try{await storage(env).delete(linkKey(url.hostname,state.id));}
    catch{return failure('解除关联失败，请稍后再试。',503);}
    return setCookie(html('关联已解除','<p>✅ 本站已恢复独立 Browser ID。</p><p><a class="button" href="/">返回网站</a></p>'),revokeCookie(url.hostname));
  }

  return failure('不支持此请求。',405);
}
