import {
  edgeDeviceScope, verifyEdgeDevice, buildEdgeDeviceCookie,
  createGlobalDeviceCookie,
} from './domain-device-id.js';

const PATH='/__vynalth/device/link';
const CENTRAL_ORIGIN='https://vynalthai.com';
const textEncoder=new TextEncoder();
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const CODE=/^[A-Za-z0-9_-]{43}$/;

function enabled(env) {
  return env?.DEVICE_FEDERATION_ENABLED==='true'
    && String(env?.VISITOR_IP_SIGNING_SECRET||'').length>=32;
}
function hex(bytes) {return [...new Uint8Array(bytes)].map(x=>x.toString(16).padStart(2,'0')).join('');}
function b64url(bytes){
  let s='';for(const b of new Uint8Array(bytes))s+=String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}
async function federationKey(secret) {
  const raw=await crypto.subtle.digest('SHA-256',
    textEncoder.encode('vynalth-device-federation-proof:v1:'+secret));
  return crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);
}
async function signature(secret,message) {
  const key=await federationKey(secret);
  return b64url(await crypto.subtle.sign('HMAC',key,textEncoder.encode(message)));
}
export async function signedFederationAssertion(env,host,deviceId,codeOrGlobal,action='claim',nowMs=Date.now()) {
  if(!enabled(env)||!edgeDeviceScope(host)||!UUID.test(deviceId))return null;
  const ts=Math.floor(nowMs/1000);
  const digest=action==='claim'
    ?hex(await crypto.subtle.digest('SHA-256',textEncoder.encode(codeOrGlobal)))
    :String(codeOrGlobal).toLowerCase();
  if(action==='claim'&&!CODE.test(codeOrGlobal))return null;
  if(action==='status'&&!UUID.test(digest))return null;
  const kind=action==='claim'?'f1':'f2';
  const payload=[kind,host.toLowerCase(),deviceId.toLowerCase(),digest,ts].join('|');
  return {ts,proof:await signature(String(env.VISITOR_IP_SIGNING_SECRET),payload)};
}
async function callCentral(env,path,body) {
  const res=await fetch(CENTRAL_ORIGIN+path,{
    method:'POST',redirect:'error',credentials:'omit',
    headers:{'content-type':'application/json','accept':'application/json'},
    body:JSON.stringify(body),
  });
  if(!res.ok)return null;
  const value=await res.json();
  return value && value.success===true?value:null;
}

/** A revoked account link is not shown simply because a cookie has a valid MAC. */
export async function verifyActiveFederation(env,host,localDeviceId,globalDeviceId){
  if(!enabled(env))return false;
  try {
    const a=await signedFederationAssertion(env,host,localDeviceId,globalDeviceId,'status');
    if(!a)return false;
    const value=await callCentral(env,'/api/security/device/federation/status',{
      host,localDeviceId,globalDeviceId,...a,
    });
    return value?.active===true;
  }catch{return false;}
}
const headers={
  'Cache-Control':'private, no-store, max-age=0',
  'Content-Type':'text/html; charset=utf-8',
  'Referrer-Policy':'no-referrer',
  'X-Robots-Tag':'noindex, nofollow, noarchive',
  'X-Content-Type-Options':'nosniff',
  'X-Frame-Options':'DENY',
  'Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
};
function page(host,message='',isError=false) {
  const messageBlock=message?'<p role="status" class="'+(isError?'err':'ok')+'">'+message+'</p>':'';
  const escapedHost=host.replace(/[^a-z0-9.-]/g,'');
  return '<!doctype html><html lang="zh"><head><meta charset="utf-8">'
  +'<meta name="viewport" content="width=device-width,initial-scale=1">'
  +'<title>Vynalth AI · Link Device ID</title>'
  +'<style>*{box-sizing:border-box}body{margin:0;background:#080c18;color:#e7ebf5;'
  +'font:16px system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:24px}'
  +'main{background:#111a30;border:1px solid #334061;border-radius:20px;max-width:520px;padding:30px;width:100%}'
  +'label,input,button{display:block;width:100%}input{margin:10px 0 20px;padding:13px;background:#060b19;'
  +'border:1px solid #64748b;border-radius:8px;color:white}button{background:#5c62e8;color:white;'
  +'border:0;border-radius:9px;padding:14px;font-weight:700;cursor:pointer}'
  +'a{color:#a6b5ff}.small{font-size:13px;color:#abb6ca;line-height:1.6}'
  +'.ok{color:#83e9a2}.err{color:#ffb5b5}</style></head><body><main>'
  +'<h1>🔐 Unified Device ID</h1><p>当前网站：<strong>'+escapedHost+'</strong></p>'
  +'<p>仅在你主动授权后，这个网站的设备身份才会关联到 Vynalth AI 中央 Device ID。</p>'
  +'<p><a href="https://vynalthai.com/cn/security/device-link" rel="noreferrer">'
  +'① 前往 Vynalth AI 登录并生成一次性配对码</a></p>'
  +'<form method="post" action="/__vynalth/device/link" autocomplete="off">'
  +'<label for="code">② 在本网站输入配对码</label><input required id="code" name="code" '
  +'pattern="[A-Za-z0-9_\\-]{43}" minlength="43" maxlength="43" spellcheck="false">'
  +'<button type="submit">授权关联这台浏览器</button></form>'
  +messageBlock
  +'<p class="small">配对码有效期 5 分钟、只能使用一次。不会读取其他域名的 Cookie，'
  +'不会使用 IP、GPS 或浏览器指纹来推测身份。可在中央账户中撤销关联。</p>'
  +'</main></body></html>';
}
function respond(host,message='',status=200,error=false) {
  return new Response(page(host,message,error),{status,headers});
}
function setCookie(response,cookie) {
  const h=new Headers(response.headers);h.append('Set-Cookie',cookie);
  return new Response(response.body,{status:response.status,headers:h});
}
export async function handleDomainDeviceFederation(request,env,url){
  if(url.pathname!==PATH)return null;
  const scope=edgeDeviceScope(url.hostname);
  if(!scope)return null;
  if(!enabled(env))return respond(scope.host,'关联功能尚未启用。',503,true);
  if(request.method!=='GET'&&request.method!=='POST')
    return respond(scope.host,'仅支持 GET / POST',405,true);
  const device=await verifyEdgeDevice(request,env);
  if(device.state==='disabled')return respond(scope.host,'本站设备签名服务不可用。',503,true);
  if(request.method==='GET'){
    let response=respond(scope.host);
    if(device.shouldSetCookie)response=setCookie(response,buildEdgeDeviceCookie(device.token));
    return response;
  }
  if(request.headers.get('Origin')!=='https://'+scope.host
    ||request.headers.get('Sec-Fetch-Site')!=='same-origin'
    ||!String(request.headers.get('Content-Type')||'').startsWith('application/x-www-form-urlencoded'))
    return respond(scope.host,'浏览器来源验证失败。',403,true);
  if(device.state!=='valid'&&device.state!=='rotated')
    return respond(scope.host,'请重新打开本页，让浏览器先保存本站签名设备凭据。',428,true);
  if(Number(request.headers.get('Content-Length')||0)>1500)
    return respond(scope.host,'请求过大。',413,true);
  let code='';
  try{
    const raw=await request.text();
    if(raw.length>1500)return respond(scope.host,'请求过大。',413,true);
    code=new URLSearchParams(raw).get('code')||'';
  }catch{return respond(scope.host,'配对码读取失败。',400,true);}
  if(!CODE.test(code))return respond(scope.host,'无效配对码。',400,true);
  try{
    const proof=await signedFederationAssertion(env,scope.host,device.deviceId,code);
    if(!proof)return respond(scope.host,'服务器签名不可用。',503,true);
    const result=await callCentral(env,'/api/security/device/federation/claim',{
      host:scope.host,localDeviceId:device.deviceId,code,...proof,
    });
    if(!result||!UUID.test(result.globalDeviceId))return respond(scope.host,
      '配对失败：配对码已过期、已经使用，或中央服务暂不可用。',403,true);
    let response=respond(scope.host,'✅ 关联成功！统一 Device ID：'+
      result.globalDeviceId.toLowerCase());
    const cookie=await createGlobalDeviceCookie(
      scope.host,device.deviceId,result.globalDeviceId,env);
    if(!cookie)return respond(scope.host,'关联成功，但本地凭据无法保存，请联系管理员。',503,true);
    response=setCookie(response,cookie);
    if(device.shouldSetCookie)response=setCookie(response,buildEdgeDeviceCookie(device.token));
    return response;
  }catch{return respond(scope.host,'中央关联服务暂时无法连接。',503,true);}
}
