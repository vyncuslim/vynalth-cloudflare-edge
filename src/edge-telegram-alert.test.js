import test from "node:test";
import assert from "node:assert/strict";
import { classifyEdgeAlert, edgeTelegramStatus, scheduleEdgeTelegramAlert } from "./edge-telegram-alert.js";

const bot = "123456789:" + "A".repeat(35);
function fixture() {
  const sent = [], tasks = [];
  const env = { EDGE_TELEGRAM_ALERTS_ENABLED: "true",
    TELEGRAM_BOT_TOKEN: bot, TELEGRAM_CHAT_ID: "-1001234567890" };
  const request = new Request("https://vynalthai.com/api/ai/chat?token=private", {
    method: "POST", headers: { Cookie: "auth=secret",
      "CF-Connecting-IP": "198.51.100.11" }, body: "secret password" });
  const ctx = { waitUntil: p => tasks.push(p) };
  const fetchImpl = async (url, options) => {
    sent.push({ url, options });
    return new Response(JSON.stringify({ ok: true, result:{message_id:77} }), { status: 200 });
  };
  const args = { env, request, response: new Response(null, { status: 503 }),
    ctx, url: new URL(request.url),
    requestId: "11111111-2222-3333-4444-555555555555", fetchImpl };
  const flush = async () => { while (tasks.length) await Promise.all(tasks.splice(0)); };
  return { env, sent, tasks, args, flush };
}
test("requires valid bot and chat secrets, not client or KV", () => {
  const { env } = fixture();
  assert.deepEqual(edgeTelegramStatus(env), { enabled: true, configured: true });
  assert.deepEqual(edgeTelegramStatus({ ...env, TELEGRAM_BOT_TOKEN: "" }),
    { enabled: true, configured: false });
  assert.deepEqual(edgeTelegramStatus({ ...env, EDGE_TELEGRAM_ALERTS_ENABLED: "false" }),
    { enabled: false, configured: true });
});
test("reports every HTTP 4xx or 5xx including authentication and missing pages", () => {
  const { args } = fixture();
  for (const status of [400, 401, 403, 404, 429, 500, 502, 503, 504]) {
    const issue = classifyEdgeAlert(args.request, new Response(null, { status }));
    assert.ok(issue, String(status) + " must alert");
    assert.equal(issue.status, status);
  }
  for (const status of [200, 204, 301, 307]) {
    assert.equal(classifyEdgeAlert(args.request, new Response(null, { status })), null);
  }
  const probe = new Request("https://vynalthai.com/.env?secret=private");
  assert.equal(classifyEdgeAlert(probe, new Response(null, { status: 404 })).code, "SUSPICIOUS_PROBE");
});
test("reports each individual failure, without cross-event suppression", async () => {
  const { args, sent, flush } = fixture();
  assert.equal(scheduleEdgeTelegramAlert(args), true);
  await flush();
  assert.equal(scheduleEdgeTelegramAlert(args), true);
  await flush();
  assert.equal(sent.length, 2);
  assert.equal(sent[0].options.method, "POST");
  for (const item of sent) {
    const payload = JSON.parse(item.options.body);
    assert.equal(payload.chat_id, "-1001234567890");
    assert.match(payload.text, /🚨 Vynalth AI Security Alert/);
    assert.match(payload.text, /Type: HTTP_5XX/);
    assert.match(payload.text, /Severity: HIGH/);
    assert.match(payload.text, /Status Code: 503/);
    assert.match(payload.text, /Path: \/api\/ai\/chat/);
    assert.match(payload.text, /Request Id:/);
    for (const privateValue of ["198.51.100.11", "private", "auth=secret", "password", bot]) {
      assert.ok(!payload.text.includes(privateValue), "Sensitive data leaked: " + privateValue);
    }
  }
});
test("reports Telegram missing acknowledgment safely and does not modify HTTP status", async () => {
  const { args, flush } = fixture();
  assert.equal(scheduleEdgeTelegramAlert({ ...args, fetchImpl: async () =>
    new Response(JSON.stringify({ ok: false }), { status: 200 }) }), true);
  await flush();
  assert.equal(args.response.status, 503);
});
test("never sends if disabled, missing secrets, or no lifecycle queue", () => {
  const { args } = fixture();
  assert.equal(scheduleEdgeTelegramAlert({ ...args, env: {
    ...args.env, EDGE_TELEGRAM_ALERTS_ENABLED: "false" } }), false);
  assert.equal(scheduleEdgeTelegramAlert({ ...args, env: {
    ...args.env, TELEGRAM_BOT_TOKEN: "" } }), false);
  assert.equal(scheduleEdgeTelegramAlert({ ...args, ctx: undefined }), false);
});

test("INFO notification for each 2xx/3xx after explicit notify-all opt-in",async()=>{
 const {args,sent,flush}=fixture();
 const env={...args.env,EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS:"true"};
 for(const status of [200,201,204,301,307]){
  const response=new Response(null,{status});
  const issue=classifyEdgeAlert(args.request,response,env);
  assert.equal(issue.code,"HTTP_REQUEST");
  assert.equal(issue.severity,"Info");
  assert.equal(scheduleEdgeTelegramAlert({...args,env,response,responseTimeMs:101}),true);
 }
 await flush();
 assert.equal(sent.length,5);
 for(const item of sent){
  const payload=JSON.parse(item.options.body);
  assert.match(payload.text,/Type: HTTP_REQUEST/);
  assert.match(payload.text,/Severity: INFO/);
  assert.match(payload.text,/Response Time Ms: 101/);
 }
 assert.equal(classifyEdgeAlert(args.request,new Response(null,{status:200}),args.env),null);
});

test("full detailed 200 alert identifies Cloudflare-observed IP without claiming verified HMAC, and redacts secrets",async()=>{
 const {args,sent,flush}=fixture();
 const env={...args.env,EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS:"true"};
 const secret="PRIVATE_AUTH_TOKEN_SHOULD_NOT_APPEAR";
 const cookie="sensitive-cookie-secret";
 const device="7daa1451-7e83-4cb2-8b14-fcb4beef46fd";
 const request=new Request("https://vynalthai.com/api/visitor-info?token="+secret+"&lang=en",{
  method:"GET",
  headers:{
   "CF-Connecting-IP":"35.232.80.204",
   "Authorization":"Bearer "+secret,
   "Cookie":"session="+cookie,
   "User-Agent":"ElevenlabsBot/1.0",
   "X-Vynalth-Device-Id":device
  }
 });
 Object.defineProperty(request,"cf",{value:{country:"US",regionCode:"IA"}});
 const response=new Response(null,{status:200});
 assert.equal(scheduleEdgeTelegramAlert({...args,env,request,
  url:new URL(request.url),response,responseTimeMs:106530}),true);
 await flush();
 assert.equal(sent.length,1);
 const m=JSON.parse(sent[0].options.body).text;
 assert.match(m,/^🚨 Vynalth AI Security Alert/);
 assert.match(m,/Type: HTTP_REQUEST/);
 assert.match(m,/Severity: INFO/);
 assert.match(m,/IP: 35\.232\.80\.204 \(Cloudflare edge observed/);
 assert.match(m,/Ip Verified: true \(edge metadata only; not origin HMAC verified\)/);
 assert.match(m,/Path: \/api\/visitor-info/);
 assert.match(m,/Request Id: 11111111-2222-3333-4444-555555555555/);
 assert.match(m,/Response Time Ms: 106530/);
 assert.match(m,/Country: US \(Cloudflare edge; approximate\)/);
 assert.match(m,/Location: US-IA \(Cloudflare edge IP geolocation/);
 assert.match(m,/User Agent: ElevenlabsBot\/1.0/);
 assert.match(m,/Device Id: Unknown \(not authenticated at this edge\)/);
 assert.match(m,/Claimed Device Id: 7daa1451-7e83-4cb2-8b14-fcb4beef46fd \(unverified browser claim\)/);
 assert.match(m,/Query: 2 parameter\(s\) \[REDACTED\]/);
 assert.match(m,/Cookie: Present \[REDACTED\]/);
 assert.match(m,/Token: Present \[REDACTED\]/);
 assert.match(m,/GPS: Not verified or provided/);
 assert.ok(!m.includes(secret));
 assert.ok(!m.includes(cookie));
 assert.ok(!m.includes("token="));
 assert.ok(!m.includes("Bearer"));
 assert.ok(m.length<4096);
});

test("never claims signed IP or authenticated user from browser claims without edge cf metadata",async()=>{
 const {args,sent,flush}=fixture();
 const env={...args.env,EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS:"true"};
 const request=new Request("https://vynalthai.com/api/visitor-info?secret=hidden",{
  headers:{"CF-Connecting-IP":"198.51.100.11",
   "X-Vynalth-Device-Id":"not-an-authenticated-device",
   "User-Agent":"Test-Agent\nInjected-Header"}
 });
 assert.equal(scheduleEdgeTelegramAlert({...args,env,request,url:new URL(request.url),
  response:new Response(null,{status:200})}),true);
 await flush();
 const m=JSON.parse(sent[0].options.body).text;
 assert.match(m,/IP: Unknown \(NOT VERIFIED\)/);
 assert.match(m,/Ip Verified: false/);
 assert.match(m,/Device Id: Unknown/);
 assert.match(m,/Claimed Device Id: Unusable claim \[REDACTED\]/);
 assert.match(m,/Response Time Ms: Unknown \(not instrumented\)/);
 assert.ok(!m.includes("secret=hidden"));
 assert.ok(!m.includes("\nInjected-Header"));
});

test("sensitive path identifiers and content-type parameters are removed from Telegram",async()=>{
 const {args,sent,flush}=fixture();
 const env={...args.env,EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS:"true"};
 const request=new Request("https://vynalthai.com/api/visitor-info/550e8400-e29b-41d4-a716-446655440000?token=private",{
  method:"POST",
  headers:{"Content-Type":"multipart/form-data; boundary=SecretMultipartBoundary",
    "Content-Length":"342",
    "Authorization":"Bearer another-private",
    "User-Agent":"Normal-Agent"}
 });
 scheduleEdgeTelegramAlert({...args,env,request,url:new URL(request.url),
  response:new Response(null,{status:201}),responseTimeMs:3});
 await flush();
 const m=JSON.parse(sent[0].options.body).text;
 assert.match(m,/Path: \/api\/visitor-info\/\[ID\]/);
 assert.match(m,/Body: Present \[REDACTED\] \(Content-Type: multipart\/form-data\)/);
 for(const bad of ["550e8400-e29b-41d4-a716-446655440000",
  "SecretMultipartBoundary","another-private","token=private"]){
  assert.equal(m.includes(bad),false,bad);
 }
});
