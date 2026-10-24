import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectHoneypotRequest, captureAccessTelemetry, honeypotType } from '../src/security-monitor.js';

function env(extra = {}) {
  return {
    SECURITY_TELEMETRY_ENABLED: 'true',
    SECURITY_HONEYPOT_ENABLED: 'true',
    SECURITY_ACCESS_MONITOR_ENABLED: 'true',
    SECURITY_ACCESS_SAMPLE_RATE: '0',
    AXIOM_SECURITY_INGEST_TOKEN: 'test-token-with-at-least-twenty-chars',
    ...extra,
  };
}
function context() {
  const jobs = [];
  return { jobs, waitUntil(promise) { jobs.push(promise); }, async done() { await Promise.all(jobs); } };
}
function fakeIngest(events) {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    events.push({ url: String(url), payload: JSON.parse(options.body), headers: options.headers });
    return new Response(JSON.stringify({ ingested: 1, failed: 0 }), {status: 200});
  };
  return () => { globalThis.fetch = original; };
}

test('ten decoy routes exist and never yield a real login or secret', () => {
  const paths = [
    'admin/login', 'phpinfo.php', '.env', '.git/config', 'db-admin',
    'api/internal', 'backup.zip', 'form-submit', 'token-check', 'hidden-link',
  ];
  assert.equal(new Set(paths.map(p => honeypotType('/__vynalth-hp/' + p))).size, 10);
  assert.equal(honeypotType('/api/login'), null);
});

test('active decoy responds 404 and writes a sanitized, attributable security event', async () => {
  const events = [], restore = fakeIngest(events), ctx = context();
  try {
    const req = new Request('https://vynalthai.com/__vynalth-hp/.env?token=should-not-log', {
      headers: { 'CF-Connecting-IP': '203.0.113.50', Authorization: 'Bearer secret-never-log' },
    });
    const res = await inspectHoneypotRequest(req, env(), ctx, 'test-request');
    assert.equal(res.status, 404);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    assert.equal((await res.text()).includes('secret'), false);
    await ctx.done();
    assert.equal(events.length, 1);
    assert.match(events[0].url, /\/v1\/ingest\/vynalth-security-logs$/);
    const row = events[0].payload[0];
    assert.equal(row.host, 'vynalthai.com');
    assert.equal(row.trap, 'environment-file');
    assert.equal(row.event, 'HONEYPOT_TRIGGER');
    assert.equal(row.status_code, 404);
    assert.equal(row.ip_source, 'cloudflare_edge');
    assert.doesNotMatch(JSON.stringify(row), /should-not-log|Bearer secret|203\.0\.113\.50/);
  } finally { restore(); }
});

test('passive probes are observed but never intercepted', async () => {
  const events = [], restore = fakeIngest(events), ctx = context();
  try {
    const result = await inspectHoneypotRequest(
      new Request('https://vynalthai.com/api/phpinfo.php'), env(), ctx, 'probe-1');
    assert.equal(result, null);
    await ctx.done();
    assert.equal(events[0].payload[0].event, 'SENSITIVE_ROUTE_PROBE');
    assert.equal(events[0].payload[0].trap_mode, 'passive-observation');
    assert.equal(events[0].payload[0].status_code, undefined);
  } finally { restore(); }
});

test('disabled or unconfigured decoys do not alter original routes or transmit logs', async () => {
  const events = [], restore = fakeIngest(events), ctx = context();
  try {
    const req = new Request('https://vynalthai.com/__vynalth-hp/backup.zip');
    assert.equal(await inspectHoneypotRequest(req, env({SECURITY_HONEYPOT_ENABLED:'false'}), ctx, 'r'), null);
    assert.equal(await inspectHoneypotRequest(req, env({AXIOM_SECURITY_INGEST_TOKEN:''}), ctx, 'r'), null);
    assert.equal(ctx.jobs.length, 0);
    assert.equal(events.length, 0);
  } finally { restore(); }
});

test('all 5xx responses are captured even if ordinary traffic sampling is zero', async () => {
  const events = [], restore = fakeIngest(events), ctx = context();
  try {
    const req = new Request('https://vynalthai.com/api/private/abcd1234abcdef9876543210?password=nope');
    captureAccessTelemetry(req, new Response('Bad Gateway', { status: 502 }),
      env(), ctx, 'error-r', Date.now() - 123);
    await ctx.done();
    assert.equal(events.length, 1);
    assert.match(events[0].url, /\/v1\/ingest\/vynalth-access-logs$/);
    assert.equal(events[0].payload[0].status_code, 502);
    assert.equal(events[0].payload[0].sample_probability, 1);
    assert.doesNotMatch(JSON.stringify(events[0].payload), /password=nope|abcd1234abcdef9876543210/);
    const ctx2 = context();
    captureAccessTelemetry(req, new Response('ok'), env(), ctx2, 'normal-r', Date.now());
    await ctx2.done();
    assert.equal(events.length, 1);
  } finally { restore(); }
});
