/**
 * Public, consent-based school-egress observation only.
 * A visitor cannot create a blocked:IP record here.
 */
const TTL_SECONDS = 72 * 60 * 60;
const PREFIX = "student-report:";
const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, max-age=0",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow"
};
const json = (status,payload) => new Response(JSON.stringify(payload), {status,headers:JSON_HEADERS});
function isPublicV4(ip) {
  if(typeof ip!=="string")return false;
  const a=ip.split(".");
  if(a.length!==4||a.some(x=>!/^(0|[1-9][0-9]{0,2})$/.test(x)||+x>255))return false;
  const [x,y,z]=a.map(Number);
  return !(x===0||x===10||x===127||x>=224||
    x===169&&y===254||x===100&&y>=64&&y<=127||
    x===172&&y>=16&&y<=31||x===192&&y===168||
    x===192&&y===0&&z===2||x===198&&y===51&&z===100||
    x===203&&y===0&&z===113||x===198&&(y===18||y===19));
}

function isPublicV6(ip) {
  if (typeof ip !== "string" || ip.length > 45 ||
      !/^[0-9a-f:.]+$/i.test(ip) || !ip.includes(":")) return false;
  try {
    // WHATWG URL parsing validates compressed and uncompressed IPv6.
    const host = new URL("https://[" + ip + "]/").hostname;
    const normalized = host.slice(1, -1).toLowerCase();
    // Globally routed unicast allocations lie in 2000::/3.
    if (!/^[23][0-9a-f]{3}:/.test(normalized)) return false;
    if (normalized.startsWith("2001:db8:")) return false; // documentation
    if (normalized === "2a06:98c0:3600::103") return false; // Cloudflare cross-zone Worker identity
    return true;
  } catch {
    return false;
  }
}

function isPseudoV4(ip) {
  if (typeof ip !== "string" || !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip)) return false;
  const octets = ip.split(".").map(Number);
  return octets.every(x => x <= 255) && octets[0] >= 240;
}

// Prefer the real address from Cloudflare's connecting-IP header.
// Under Cloudflare Pseudo IPv4 'Overwrite Headers', the header contains
// a Class E synthetic IPv4. ONLY then use CF-Connecting-IPv6.
// Never trust X-Forwarded-For, form fields, URL params or arbitrary fallbacks.
function observedAddress(request) {
  const source = request.headers.get("CF-Connecting-IP");
  if (isPublicV4(source)) return { ip: source, family: "ipv4" };
  if (isPublicV6(source)) return { ip: source.toLowerCase(), family: "ipv6" };
  if (isPseudoV4(source)) {
    const realV6 = request.headers.get("CF-Connecting-IPv6");
    if (isPublicV6(realV6)) return { ip: realV6.toLowerCase(), family: "ipv6" };
  }
  return { ip: null, family: null, reason: source ? "nonpublic_or_unsupported" : "cf_header_missing" };
}

// Non-sensitive troubleshooting: never display or log a user's IP here.
export function ipStatus(request) {
  if (request.method !== "GET") return json(405, { error: "METHOD_NOT_ALLOWED" });
  const observed = observedAddress(request);
  return json(200, {
    ok: true,
    publicIpAvailable: Boolean(observed.ip),
    family: observed.family,
    reason: observed.reason || null
  });
}

const PAGE = "<!doctype html>\n<html lang=\"en\"><head>\n<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"no-referrer\">\n<title>POWIIS Network Report | Vynalth Shield</title>\n<style>\n:root{color-scheme:dark;font-family:ui-sans-serif,system-ui,sans-serif;background:#080c18;color:#ecf4ff}\n*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse 70% 60% at 8% 0%,#1d3967,transparent 75%),radial-gradient(ellipse 60% 60% at 100% 100%,#152843,transparent 75%),#080c18}\n.shell{width:min(100%,790px);margin:auto;padding:22px 18px 55px}\nheader{display:flex;gap:12px;justify-content:space-between;align-items:center;padding:18px 0 42px}\n.logo{display:flex;align-items:center;gap:11px;font-weight:800;letter-spacing:.025em}\n.mark{width:39px;height:39px;border-radius:13px;background:linear-gradient(135deg,#58b3ff,#8d83ee);display:grid;place-items:center;color:#07152c;font-size:22px}\n.tag{font-size:11px;color:#b3ccf1;border:1px solid #324664;background:#16243c;border-radius:50px;padding:8px 12px}\n.panel{border:1px solid #304564;border-radius:26px;background:linear-gradient(150deg,#172945ed,#0b1529f7);padding:clamp(24px,5vw,47px);box-shadow:0 30px 90px #0005}\n.eyebrow{font-size:12px;font-weight:800;color:#8bd0ff;letter-spacing:.16em}\nh1{font-size:clamp(30px,6vw,46px);letter-spacing:-.05em;line-height:1.1;margin:19px 0 17px}\n.lead{color:#bbcee7;line-height:1.65;font-size:16px}\n.langs{border-top:1px solid #2c4261;margin-top:21px;padding-top:18px;color:#abc0db;font-size:13px;line-height:1.7}\n.steps{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:27px 0}\n.step{border:1px solid #304461;background:#101c31;border-radius:13px;padding:17px 14px;font-size:12px;color:#aec1de}\n.num{font-weight:900;font-size:22px;color:#e1ecff;display:block;margin-bottom:7px}\n.notice{margin:25px 0;padding:20px;background:#11293e;border:1px solid #366b8e;border-radius:16px;color:#cae0f4;line-height:1.65;font-size:14px}\n.notice strong{color:#a5e1ff}\nlabel{display:flex;align-items:flex-start;gap:12px;margin:23px 0;font-size:14px;line-height:1.62;color:#dce9fa;cursor:pointer}\ninput{width:20px;height:20px;flex:none;margin-top:2px;accent-color:#77c2ff}\nbutton{border:0;border-radius:13px;padding:16px 20px;width:100%;background:#87c9ff;color:#08192c;font-size:15px;font-weight:800;cursor:pointer}\nbutton:disabled{opacity:.43;cursor:not-allowed}\n.status{display:none;margin-top:17px;padding:15px;background:#183b3c;border:1px solid #428577;border-radius:12px;color:#d5f8ee;font-size:14px;line-height:1.65}\n.status.show{display:block}.status.error{background:#3d2735;border-color:#945570;color:#ffdeea}\nfooter{font-size:12px;color:#8ca6c8;margin:25px 4px;line-height:1.7}\n@media(max-width:560px){header{padding-bottom:24px}.steps{grid-template-columns:1fr}.step{display:flex;gap:15px;align-items:center}.num{margin:0}}\n</style></head>\n<body><div class=\"shell\"><header>\n<div class=\"logo\"><span class=\"mark\" aria-hidden=\"true\">✦</span> VYNALTH SHIELD</div>\n<span class=\"tag\">VOLUNTARY REPORT</span></header>\n<main class=\"panel\">\n<div class=\"eyebrow\">POWIIS · NETWORK OBSERVATION</div>\n<h1>Help identify the school's network exit.</h1>\n<p class=\"lead\">Connected to authorized school Wi-Fi? You can voluntarily report the public exit IP seen by Cloudflare. No login, app installation or device access is needed.</p>\n<div class=\"langs\">\n<div lang=\"zh-CN\"><b>中文：</b>如果你获准使用学校 Wi-Fi，可以自愿提交当前公网出口 IP，供网站管理员核实。</div>\n<div lang=\"ms\"><b>Bahasa Melayu:</b> Jika anda dibenarkan menggunakan Wi-Fi sekolah, anda boleh menghantar IP awam untuk semakan secara sukarela.</div>\n</div>\n<div class=\"steps\">\n<div class=\"step\"><span class=\"num\">01</span>Use authorized school Wi-Fi</div>\n<div class=\"step\"><span class=\"num\">02</span>Read the notice and consent</div>\n<div class=\"step\"><span class=\"num\">03</span>Submit for manual review</div>\n</div>\n<div class=\"notice\"><strong>Privacy and access notice</strong><p>Your connection's public IP and submission time will be stored for up to <b>72 hours</b>. A public exit IP can be shared by many people. The site owner may later restrict access from that shared IP after verification and separate approval.</p><p>Submitting does <b>not</b> immediately block anyone. This cannot prove school membership. No names, Wi-Fi passwords, logins, device IDs or SSIDs are collected. This is <b>not an official POWIIS school service</b>.</p></div>\n<form id=\"report\"><label><input type=\"checkbox\" id=\"consent\" required><span>I am voluntarily connected to a school network I am permitted to use. I understand that the IP may be shared, and consent to a temporary IP/time record for possible future website-access review.</span></label>\n<button type=\"submit\" id=\"submit\" disabled>Submit my current public IP</button></form>\n<div id=\"status\" class=\"status\" role=\"status\" aria-live=\"polite\"></div>\n</main><footer>Independent Vynalth AI security project · Not affiliated with or endorsed by POWIIS. Submission is optional. Never use unauthorized or confiscated devices.</footer>\n</div><script>\nconst form=document.getElementById('report'), consent=document.getElementById('consent'), button=document.getElementById('submit'), status=document.getElementById('status');\nconsent.addEventListener('change',()=>{button.disabled=!consent.checked});\nform.addEventListener('submit',async event=>{\n event.preventDefault();if(!consent.checked)return;\n button.disabled=true;status.className='status show';status.textContent='Submitting your voluntary report…';\n try{\n  const r=await fetch(location.pathname,{method:'POST',credentials:'omit',redirect:'error',headers:{'Content-Type':'application/json'},body:JSON.stringify({consent:true,schoolWifiConfirmed:true})});\n  const data=await r.json();if(!r.ok)throw new Error(data.error==='PUBLIC_IP_UNAVAILABLE' ? 'Cloudflare could not verify the public IP for this connection. Open /ip-status for diagnostics; the site owner may need to restore the CF-Connecting-IP header.' : (data.error||'Unavailable'));\n  status.className='status show';status.textContent='Report received for manual review. No IP has been blocked. You may close this page.';form.hidden=true;\n }catch(e){status.className='status show error';status.textContent='Could not submit: '+(e.message||'Please retry.');button.disabled=!consent.checked}\n});\n</script></body></html>";

function page() {
  return new Response(PAGE,{
    status:200,
    headers:{
      "Content-Type":"text/html; charset=utf-8",
      "Cache-Control":"private, no-store",
      "X-Robots-Tag":"noindex, nofollow",
      "X-Frame-Options":"DENY",
      "Referrer-Policy":"no-referrer",
      "X-Content-Type-Options":"nosniff",
      "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
    }
  });
}

export async function studentIpReport(request,env,url) {
  if(request.method==="GET")return page();
  if(request.method!=="POST")return json(405,{error:"METHOD_NOT_ALLOWED"});

  const origin=request.headers.get("Origin");
  if(origin!==null&&origin!==url.origin)return json(403,{error:"ORIGIN_NOT_ALLOWED"});
  const fetchSite=request.headers.get("Sec-Fetch-Site");
  if(fetchSite&&fetchSite!=="same-origin"&&fetchSite!=="none")return json(403,{error:"CROSS_SITE_DENIED"});
  if(!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))return json(415,{error:"JSON_REQUIRED"});
  if(Number(request.headers.get("Content-Length")||0)>256)return json(413,{error:"REQUEST_TOO_LARGE"});

  let input;
  try {
    const raw=await request.text();
    if(raw.length>256)return json(413,{error:"REQUEST_TOO_LARGE"});
    input=JSON.parse(raw);
  } catch {return json(400,{error:"INVALID_JSON"});}
  if(input?.consent!==true||input?.schoolWifiConfirmed!==true)return json(400,{error:"CONSENT_REQUIRED"});

  // Cloudflare sets this on incoming requests. Ignore browser-supplied
  // X-Forwarded-For, query-string IP, and body fields purporting to be an IP.
  const source=observedAddress(request);
  if(!source.ip)return json(422,{
    error:"PUBLIC_IP_UNAVAILABLE",
    reason:source.reason,
    help:"See /ip-status (no IP displayed)"
  });
  const ip=source.ip;
  const kv=env?.SCHOOL_IP_KV;
  if(!kv||typeof kv.get!=="function"||typeof kv.put!=="function")return json(503,{error:"REPORTING_UNAVAILABLE"});

  const key=PREFIX+ip;
  try {
    if(await kv.get(key)!==null)return json(200,{received:true,pending:true,alreadyRecorded:true});
    await kv.put(key,JSON.stringify({
      ip,
      ipFamily:source.family,
      firstSeen:new Date().toISOString(),
      source:"public-volunteer-report",
      schoolWifiSelfDeclared:true,
      reviewStatus:"pending-unverified"
    }),{expirationTtl:TTL_SECONDS});
    return json(201,{received:true,pending:true,alreadyRecorded:false});
  }catch {
    console.error("school exit-IP report KV unavailable");
    return json(503,{error:"REPORTING_UNAVAILABLE"});
  }
}
