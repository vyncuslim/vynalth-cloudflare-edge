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
    return new Response(JSON.stringify({ ok: true }), { status: 200 });
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
    assert.match(payload.text, /HTTP_5XX/);
    assert.match(payload.text, /HTTP status: 503/);
    assert.match(payload.text, /\/api\/ai\/\*/);
    assert.match(payload.text, /Event ID:/);
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
