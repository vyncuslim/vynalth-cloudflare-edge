/**
 * Vynalth WAF Core v1. First-party deterministic request inspection.
 * Provider-independent matching; no outbound calls, body reads, fingerprinting,
 * external rule feeds, raw request logging, or implicit authentication bypass.
 */
export const WAF_VERSION = "1.2.0";
export const PILOT_HOSTS = Object.freeze(["vynalthai.com", "search.vynalthai.com"]);
const PATH_LIMIT = 8192;
const QUERY_LIMIT = 4096;
const QUERY_PAIRS = 32;
const VALUE_LIMIT = 512;
const HARD_RULES = Object.freeze([
  { id:"VWAF-101", score:100, category:"private_source_control", re:/(?:^|\/)(?:\.git|\.svn|\.hg|\.ssh)(?:\/|$)/i },
  { id:"VWAF-102", score:100, category:"private_credentials", re:/(?:^|\/)(?:\.env(?:$|[./])|\.git-credentials$|\.netrc$|\.npmrc$|\.pypirc$|\.htpasswd$|\.aws\/(?:credentials|config)(?:\/|$)|\.docker\/config\.json$|\.kube\/config$|\.gnupg\/private-keys-v1\.d(?:\/|$)|private[-_]?key\.(?:key|pem)$|id_(?:rsa|ed25519|ecdsa|dsa)$)/i },
  { id:"VWAF-103", score:100, category:"private_runtime", re:/(?:^|\/)(?:proc\/(?:self|thread-self|[0-9]+)\/environ$|\.bash_history$|\.zsh_history$|terraform\.tfstate(?:\.backup)?$|\.composer\/auth\.json$|\.config\/composer\/auth\.json$|\.htaccess$)/i },
  { id:"VWAF-104", score:100, category:"unexpected_php", re:/\.php(?:\/|$)/i },
  { id:"VWAF-105", score:100, category:"private_development", re:/^\/@fs(?:\/|$)|^\/\.changeset\/config\.json$/i, hosts:["search.vynalthai.com"] },
  { id:"VWAF-106", score:100, category:"private_runtime_diagnostics", re:/(?:^|\/)actuator\/(?:env|heapdump)(?:\/|$)|^\/server-(?:status|info)\/?$/i },
]);
const EXTRA_HARD_RULES = Object.freeze([
  { id:"VWAF-107",score:100,category:"private_backup",re:/(?:^|\/)(?:\.terraform(?:\/|$)|\.git(?:\.zip|\.tar\.gz|\.bak)$|\.env~$)/i },
  { id:"VWAF-108",score:100,category:"private_system_files",re:/^\/(?:etc\/(?:passwd|shadow|gshadow)|proc\/(?:self|thread-self|[0-9]+)\/(?:cmdline|maps))(?:\/|$)/i },
  { id:"VWAF-109",score:100,category:"private_tool_credentials",re:/^\/(?:\.vscode\/sftp\.json|\.idea\/dataSources\.local\.xml|\.gitlab-runner\/config\.toml|\.config\/gcloud\/application_default_credentials\.json|\.config\/gh\/hosts\.yml)$/i },
]);
const QUERY_RULES = Object.freeze([
  { id:"VWAF-201", score:45, category:"sql_injection_signal", re:/\bunion\s+(?:all\s+)?select\b|(?:['"]\s*(?:or|and)\s+[0-9]+\s*=\s*[0-9]+)|\b(?:sleep|benchmark)\s*\(/i },
  { id:"VWAF-202", score:45, category:"script_injection_signal", re:/<\s*script(?:\s|>|\/)|\bon(?:error|load)\s*=|javascript\s*:/i },
  { id:"VWAF-207", score:35, category:"template_expression_signal", re:/\{\{[^{}]{1,128}\}\}|\$\{[^{}]{1,128}\}/ },
  { id:"VWAF-203", score:45, category:"file_inclusion_signal", re:/(?:^|[\\/])\.\.(?:[\\/]|$)|(?:file|php):\/\//i },
]);
const STRUCTURED_PARAMS = new Set(["id","page","limit","offset","sort","order","file","path","redirect","return","next"]);
function signal(id, score, category, blocking=false) {
  return {id,score,category,blocking};
}
function pathVariants(path) {
  const variants = new Set();
  let current=path;
  for(let i=0;i<3;i++) {
    const normalized=current.replace(/\\/g,"/").replace(/\/{2,}/g,"/");
    variants.add(normalized);
    // Some origin routers interpret segment parameters independently of paths.
    // Only fixed sensitive-file rules can turn this normalization into a denial.
    variants.add(normalized.replace(/;[^/]*/g,""));
    if(i===2) break;
    let decoded;
    try { decoded=decodeURIComponent(current); } catch {
      // Preserve malformed and non-ASCII bytes; decode only well-formed ASCII escapes.
      decoded=current.replace(/%([0-9a-f]{2})/gi,(m,h)=>parseInt(h,16)<128?String.fromCharCode(parseInt(h,16)):m);
    }
    if(decoded===current) break;
    current=decoded;
  }
  return [...variants];
}
/** Pure request metadata inspection. Never changes the URL or consumes a body. */
export function inspectWafRequest(request) {
  const url=new URL(request.url);
  const host=url.hostname.toLowerCase();
  const signals=[];
  const push=s=>{if(!signals.some(x=>x.id===s.id))signals.push(s);};
  if(!PILOT_HOSTS.includes(host)) return {score:0,block:false,signals:[]};
  if(["TRACE","TRACK"].includes(request.method.toUpperCase()))
    push(signal("VWAF-001",100,"unsafe_http_method",true));
  // Framing is owned by the trusted HTTP runtime. Ambiguity is an observation,
  // not a claim that a request-smuggling attempt reached an origin parser.
  const length=request.headers?.get("content-length");
  const encoding=request.headers?.get("transfer-encoding");
  if((length!=null&&!/^\d{1,16}$/.test(length))||(length!=null&&encoding))
    push(signal("VWAF-208",35,"http_framing_signal"));
  // Very large inputs are observed, not silently truncated and hard-blocked.
  if(url.pathname.length>PATH_LIMIT) {
    push(signal("VWAF-204",15,"path_inspection_budget"));
  } else {
    const variants=pathVariants(url.pathname);
    if(variants.some(p=>/[\x00\r\n]/.test(p)))
      push(signal("VWAF-002",100,"invalid_path_control",true));
    if(variants.some(p=>/(?:^|\/)\.\.(?:\/|$)/.test(p)))
      push(signal("VWAF-205",60,"path_traversal_signal"));
    for(const rule of [...HARD_RULES,...EXTRA_HARD_RULES]) {
      if(rule.hosts&&!rule.hosts.includes(host))continue;
      if(variants.some(p=>rule.re.test(p)))push(signal(rule.id,rule.score,rule.category,true));
    }
  }
  // Never treat ordinary free-text search, AI prompts, uploaded code, or request
  // bodies as an attack. Structured query fields contribute observation only.
  if(url.search.length>QUERY_LIMIT) {
    push(signal("VWAF-206",15,"query_inspection_budget"));
  } else {
    let count=0;
    for(const [key,value] of url.searchParams) {
      if(++count>QUERY_PAIRS){push(signal("VWAF-206",15,"query_inspection_budget"));break;}
      if(!STRUCTURED_PARAMS.has(key.toLowerCase()))continue;
      if(value.length>VALUE_LIMIT){push(signal("VWAF-206",15,"query_inspection_budget"));continue;}
      for(const rule of QUERY_RULES)
        if(rule.re.test(value))push(signal(rule.id,rule.score,rule.category));
    }
  }
  // Scores express rule evidence, not probability, attribution, or proof of intrusion.
  return {score:Math.min(100,signals.reduce((sum,x)=>sum+x.score,0)),
    block:signals.some(x=>x.blocking),signals};
}
/** Strict allowlisted rollout; unknown config is off. No request-controlled overrides. */
export function applyVynalthWaf(request,env,requestId,emit=event=>console.info("[VYNALTH WAF]",JSON.stringify(event))) {
  const mode=env?.VYNALTH_WAF_MODE;
  if(mode!=="observe"&&mode!=="enforce")return null;
  const host=new URL(request.url).hostname.toLowerCase();
  const enabled=String(env?.VYNALTH_WAF_HOSTS||"").split(",").map(x=>x.trim().toLowerCase());
  if(!PILOT_HOSTS.includes(host)||!enabled.includes(host))return null;
  let result;
  try { result=inspectWafRequest(request); } catch {
    // This is a supplemental control; all existing authorization, device risk,
    // and upstream WAF controls still execute when inspection is unavailable.
    console.warn("[VYNALTH WAF] inspection unavailable");
    return null;
  }
  if(result.signals.length===0)return null;
  const action=result.block&&mode==="enforce"?"block":"observe";
  // Only fixed categories/IDs, host and server-generated correlation ID.
  // No raw path/query/body/header values, IP, cookie, or device identifier.
  const event={event:"VYNALTH_WAF_DECISION",version:WAF_VERSION,host,mode,action,
    would_block:result.block,score:result.score,
    rule_ids:result.signals.map(x=>x.id),categories:result.signals.map(x=>x.category),
    request_id:typeof requestId==="string"&&/^[a-f0-9-]{36}$/i.test(requestId)?requestId:null};
  try{emit(event);}catch{/* Telemetry failure never changes the decision. */}
  if(action!=="block")return null;
  return new Response(request.method==="HEAD"?null:"Request blocked by Vynalth WAF.",{
    status:403,headers:{"Content-Type":"text/plain; charset=utf-8","Cache-Control":"private, no-store",
      "X-Content-Type-Options":"nosniff","X-Robots-Tag":"noindex, nofollow",
      "X-Vynalth-Security-Action":"block-vynalth-waf"}
  });
}
