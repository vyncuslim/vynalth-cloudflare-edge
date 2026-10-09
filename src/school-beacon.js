/**
 * Vynalth Shield: signed campus Wi-Fi reporter endpoint.
 *
 * An owner-controlled Windows laptop on a pre-approved school SSID submits
 * signed observations. Never infer school membership from TM ASN, user-agent,
 * browser claims, or shared IP alone. Only the IP seen by Cloudflare edge
 * can become an exact individual Cloudflare IP List item.
 *
 * Required Worker secrets/bindings are documented separately. This is OFF
 * unless ALL variables and KV namespace have been provisioned.
 */
const BEACON_PATH = "/__shield/campus-beacon";
const BEACON_HOST = "vynalthai.com";
const SSID = "POWIIS_Student";
const CF_API = "https://api.cloudflare.com/client/v4";
const EXPIRE_HOURS = 12;
const MAX_JSON_SIZE = 700;
const MAX_CLOCK_SKEW = 180;
const MIN_TWO_SAMPLE_SECONDS = 300;
const MAX_TWO_SAMPLE_SECONDS = 2400;
const MIN_REFRESH_SECONDS = 3300;

const json = (status, payload) => new Response(JSON.stringify(payload), {
  status,
  headers: {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  }
});

export function isPublicExactV4(ip) {
  if (typeof ip !== "string" || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) return false;
  const octets = ip.split(".").map(Number);
  if (octets.some(x => x > 255)) return false;
  const [a,b,c] = octets;
  if (a === 0 || a === 10 || a === 127 || a >= 224 || a === 169 && b === 254 ||
    a === 100 && b >= 64 && b <= 127 || a === 172 && b >= 16 && b <= 31 ||
    a === 192 && b === 168 || a === 198 && (b === 18 || b === 19) ||
    a === 192 && b === 0 && c === 2 || a === 198 && b === 51 && c === 100 ||
    a === 203 && b === 0 && c === 113) return false;
  return true;
}

function exactManagedComment(value) {
  const match = /^POWIIS\|exp=([^|]+)\|ref=([a-zA-Z0-9_-]{8,64})$/.exec(String(value || ""));
  if (!match) return null;
  const expires = Date.parse(match[1]);
  return Number.isFinite(expires) ? { expires, reference: match[2] } : null;
}
const hexToBytes = (hex) => new Uint8Array((hex.match(/.{2}/g) || []).map(x => parseInt(x,16)));
const bytesToHex = bytes => Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,"0")).join("");

async function validateSignature(env, data, signature) {
  const keyHex = env.SCHOOL_BEACON_SIGNING_KEY || "";
  if (!/^[a-f0-9]{64}$/i.test(keyHex) || !/^[a-f0-9]{64}$/i.test(signature)) return false;
  const key = await crypto.subtle.importKey("raw", hexToBytes(keyHex), {name:"HMAC", hash:"SHA-256"}, false, ["verify"]);
  const message = ["v1", data.ts, data.nonce, data.deviceId, data.ssid].join("\n");
  return crypto.subtle.verify("HMAC", key, hexToBytes(signature), new TextEncoder().encode(message));
}
async function cf(env, path, method="GET", body=undefined) {
  const res=await fetch(CF_API + path, {
    method, headers: {authorization:"Bearer "+env.SCHOOL_CF_API_TOKEN,
      "content-type":"application/json"},
    body: body===undefined?undefined:JSON.stringify(body),
    signal:AbortSignal.timeout(10000)
  });
  const data=await res.json();
  if (!res.ok || data?.success!==true) throw new Error("CLOUDFLARE_REJECTED_"+res.status);
  return data;
}
function paths(env) {
  const account=env.SCHOOL_CF_ACCOUNT_ID;
  const list=env.SCHOOL_CF_LIST_ID;
  return {
    list:"/accounts/"+account+"/rules/lists/"+list,
    op:"/accounts/"+account+"/rules/lists/bulk_operations/"
  };
}
async function getItems(env, path) {
  const results=[];
  let cursor;
  const seen=new Set();
  do {
    const q=new URLSearchParams({per_page:"500"});
    if(cursor)q.set("cursor",cursor);
    const data=await cf(env,path+"/items?"+q);
    if(!Array.isArray(data.result))throw new Error("BAD_LIST_ITEMS");
    results.push(...data.result);
    cursor=data.result_info?.cursors?.after||undefined;
    if(cursor) {
      if(seen.has(cursor)||results.length>10000)throw new Error("PAGINATION_LIMIT");
      seen.add(cursor);
    }
  }while(cursor);
  return results;
}
async function waitForWrite(env, opPath, opId) {
  if(!/^[a-f0-9]{32}$/.test(opId || ""))throw new Error("BAD_OPERATION_ID");
  for(let i=0;i<12;i++) {
    const data=await cf(env,opPath+opId);
    if(data.result?.status==="completed")return;
    if(data.result?.status==="failed")throw new Error("BULK_OPERATION_FAILED");
    if(!["pending","running"].includes(data.result?.status))throw new Error("INVALID_OPERATION_STATUS");
    await new Promise(r=>setTimeout(r,500));
  }
  throw new Error("WRITE_UNCONFIRMED");
}
function isConfigured(env) {
  return Boolean(env.SCHOOL_BEACON_ENABLED==="true" &&
    env.SCHOOL_BEACON_KV && typeof env.SCHOOL_BEACON_KV.get==="function" &&
    /^[a-f0-9]{32}$/.test(env.SCHOOL_CF_ACCOUNT_ID||"") &&
    /^[a-f0-9]{32}$/.test(env.SCHOOL_CF_LIST_ID||"") &&
    env.SCHOOL_CF_API_TOKEN && /^[a-f0-9]{64}$/i.test(env.SCHOOL_BEACON_SIGNING_KEY||"") &&
    /^[a-zA-Z0-9_-]{16,64}$/.test(env.SCHOOL_BEACON_DEVICE_ID||""));
}

export async function handleCampusBeacon(request, env) {
  const url=new URL(request.url);
  if(url.hostname!==BEACON_HOST || url.pathname!==BEACON_PATH ||
    request.method!=="POST")return json(404,{error:"NOT_FOUND"});
  if(!isConfigured(env))return json(503,{error:"SCHOOL_BEACON_DISABLED"});
  if(!request.headers.get("content-type")?.startsWith("application/json"))return json(415,{error:"BAD_TYPE"});
  if(Number(request.headers.get("content-length")||0)>MAX_JSON_SIZE)return json(413,{error:"TOO_LARGE"});
  let raw;
  try {raw=await request.text();if(raw.length>MAX_JSON_SIZE)return json(413,{error:"TOO_LARGE"});}
  catch{return json(400,{error:"INVALID_REQUEST"});}
  let data;try{data=JSON.parse(raw);}catch{return json(400,{error:"BAD_JSON"});}
  const now=Math.floor(Date.now()/1000);
  if(!data || data.ssid!==SSID || data.deviceId!==env.SCHOOL_BEACON_DEVICE_ID ||
     !Number.isSafeInteger(data.ts) || Math.abs(now-data.ts)>MAX_CLOCK_SKEW ||
     !/^[a-f0-9]{32}$/.test(data.nonce||""))return json(403,{error:"UNTRUSTED_REPORT"});
  const signed=await validateSignature(env,data,request.headers.get("x-school-beacon-signature")||"");
  if(!signed)return json(403,{error:"BAD_SIGNATURE"});

  const ip=request.headers.get("cf-connecting-ip") || "";
  if(!isPublicExactV4(ip))return json(403,{error:"UNSUPPORTED_NETWORK_IP"});
  const store=env.SCHOOL_BEACON_KV;
  // Nonce replay detection is best effort: KV is eventually consistent. Signed
  // observations do not grant privileges; the list is still updated only after
  // two time-spaced observations from the same authorized device and IP.
  const nonceKey="campus:nonce:"+data.deviceId+":"+data.nonce;
  if(await store.get(nonceKey))return json(409,{error:"REPLAY"});
  await store.put(nonceKey,"1",{expirationTtl:600});

  try {
    const p=paths(env);
    const meta=(await cf(env,p.list)).result;
    if(meta?.name!=="powiis_verified_egress" || meta?.kind!=="ip") {
      return json(503,{error:"WRONG_IP_LIST"});
    }
    const items=await getItems(env,p.list);
    const current=items.find(x=>x.ip===ip || x.ip===ip+"/32");
    if(current && !exactManagedComment(current.comment))return json(409,{error:"UNMANAGED_IP_PRESENT"});
    const match=current?exactManagedComment(current.comment):null;
    const refresh=(match && match.expires-now*1000>MIN_REFRESH_SECONDS*1000);
    if(refresh)return json(200,{status:"already_protected",renewalRequired:false});

    if(!current) {
      const key="campus:pending:"+data.deviceId+":"+ip;
      const pendingRaw=await store.get(key);
      const pending=pendingRaw?JSON.parse(pendingRaw):null;
      if(!pending || !Number.isSafeInteger(pending.first) ||
         now-pending.first>MAX_TWO_SAMPLE_SECONDS || now<pending.first) {
        await store.put(key,JSON.stringify({first:now}),{expirationTtl:MAX_TWO_SAMPLE_SECONDS});
        return json(202,{status:"awaiting_independent_second_observation"});
      }
      if(now-pending.first<MIN_TWO_SAMPLE_SECONDS) {
        return json(202,{status:"waiting_for_second_observation"});
      }
    }
    const lastKey="campus:lastwrite:"+ip;
    const last=Number(await store.get(lastKey) || 0);
    if(now-last<300)return json(202,{status:"provider_write_cooldown"});
    // Do not misrepresent a queued asynchronous bulk operation as completed.
    const expiry=new Date((now+EXPIRE_HOURS*3600)*1000).toISOString();
    const reference=match?.reference || "campus-beacon-"+data.deviceId.slice(0,24);
    const item={ip,comment:"POWIIS|exp="+expiry+"|ref="+reference};
    const op=(await cf(env,p.list+"/items","POST",[item])).result;
    await waitForWrite(env,p.op,op?.operation_id);
    const readback=await getItems(env,p.list);
    const actual=readback.find(x=>x.ip===ip || x.ip===ip+"/32");
    const verified=exactManagedComment(actual?.comment);
    if(!verified || verified.expires<new Date(expiry).getTime()-1000) {
      throw new Error("READBACK_DID_NOT_MATCH");
    }
    await store.put(lastKey,String(now),{expirationTtl:3600});
    await store.delete("campus:pending:"+data.deviceId+":"+ip);
    return json(200,{status:current?"renewed":"new_exact_ip_protected",lifetimeHours:EXPIRE_HOURS});
  }catch(e) {
    console.error("Campus beacon Cloudflare list update error",String(e instanceof Error?e.message:e));
    return json(503,{error:"SCHOOL_AUTO_UPDATE_FAILED"});
  }
}
