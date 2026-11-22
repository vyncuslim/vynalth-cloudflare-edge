/**
 * Short-lived operator-only TiDB acceptance page. No plaintext password,
 * no additional Cloudflare Secret and no reuse of IP Administration login.
 *
 * Fixed password checked against a salted PBKDF2-SHA256 verifier; only the
 * salt and derived verifier are committed to source. This is a temporary
 * operator-requested convenience, not the recommended permanent credential
 * storage model. The route expires after 25 November 2026, 23:59 MYT.
 */
export const TIDB_ACCEPTANCE_EXPIRES_AT = "2026-11-25T15:59:59Z";
export const TIDB_ACCEPTANCE_CLOSE_KEY = "ops:tidb-acceptance:closed:v1";
const PASSWORD_SALT_HEX = "a3322a4b0f26ff783b94f2729271d864509e38b83da7f175";
const PASSWORD_VERIFIER_HEX = "05b2311343a9987608cbf8bc068bb0e5b2fa1bc168dc070ba1eb125515d92200";
const PASSWORD_ITERATIONS = 25000;
const SESSION_COOKIE = "__Host-vynalth-tidb-acceptance";
const SESSION_PREFIX = "ops:tidb-acceptance:session:v1:";
const FAILURE_PREFIX = "ops:tidb-acceptance:login-fail:v1:";
const SESSION_TTL = 1200;
const FAILURE_TTL = 900;
const MAX_FAILURES = 5;
const TEXT = new TextEncoder();
const HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "private, no-store, max-age=0",
  "X-Robots-Tag": "noindex,nofollow",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
});
const reply = (status, payload, extra = {}) =>
  new Response(JSON.stringify(payload), { status, headers: { ...HEADERS, ...extra } });

export function tidbAcceptanceWithinWindow(now = Date.now()) {
  return Number.isFinite(now) &&
    now < Date.parse(TIDB_ACCEPTANCE_EXPIRES_AT);
}
const configured = (env) =>
  tidbAcceptanceWithinWindow() &&
  typeof env?.SCHOOL_IP_KV?.get === "function" &&
  typeof env.SCHOOL_IP_KV.put === "function" &&
  typeof env.SCHOOL_IP_KV.delete === "function";

export async function tidbAcceptanceClosed(env) {
  // Fail closed when KV cannot confirm the page has not been disabled.
  if (!configured(env)) return true;
  try { return Boolean(await env.SCHOOL_IP_KV.get(TIDB_ACCEPTANCE_CLOSE_KEY)); }
  catch { return true; }
}

function safeOrigin(request, url) {
  const origin = request.headers.get("Origin");
  const site = request.headers.get("Sec-Fetch-Site");
  return origin === url.origin && (!site || site === "same-origin");
}
function base64url(bytes) {
  let raw = "";
  for (const byte of bytes) raw += String.fromCharCode(byte);
  return btoa(raw).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomString(byteCount = 32) {
  const raw = new Uint8Array(byteCount);
  crypto.getRandomValues(raw);
  return base64url(raw);
}
function hex(bytes) {
  return [...bytes].map((x) => x.toString(16).padStart(2, "0")).join("");
}
async function digest(value) {
  const result = await crypto.subtle.digest("SHA-256", TEXT.encode(value));
  return hex(new Uint8Array(result));
}
function fromHex(value) {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
async function fixedPasswordMatches(candidate) {
  if (typeof candidate !== "string" || candidate.length > 256) return false;
  const key = await crypto.subtle.importKey(
    "raw", TEXT.encode(candidate), "PBKDF2", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits({
    name: "PBKDF2", salt: fromHex(PASSWORD_SALT_HEX),
    iterations: PASSWORD_ITERATIONS, hash: "SHA-256",
  }, key, 256);
  const derived = new Uint8Array(bits);
  const expected = fromHex(PASSWORD_VERIFIER_HEX);
  let different = 0;
  for (let i = 0; i < expected.length; i++)
    different |= derived[i] ^ expected[i];
  return different === 0;
}
async function failureKey(env, request) {
  // Hash an observed IP with the dedicated secret; do not persist raw IP.
  const ip = request.headers.get("CF-Connecting-IP");
  if (!ip || ip.length > 60) return null;
  const key = await crypto.subtle.importKey(
    "raw", fromHex(PASSWORD_VERIFIER_HEX),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign(
    "HMAC", key, TEXT.encode("tidb-login-rate-v1|" + ip),
  ));
  return FAILURE_PREFIX + hex(sig.slice(0, 16));
}
async function bodyPassword(request) {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))
    return null;
  const length = Number(request.headers.get("Content-Length") || 0);
  if (!Number.isFinite(length) || length > 512) return null;
  try {
    const body = await request.text();
    if (body.length > 512) return null;
    const obj = JSON.parse(body);
    if (!obj || Array.isArray(obj) || typeof obj !== "object" ||
        typeof obj.password !== "string" || obj.password.length > 256 ||
        Object.keys(obj).length !== 1) return null;
    return obj.password;
  } catch { return null; }
}
function cookie(token, maxAge) {
  return SESSION_COOKIE + "=" + token +
    "; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + maxAge;
}
function sessionToken(request) {
  const part = (request.headers.get("Cookie") || "").split(";")
    .map(s => s.trim()).find(s => s.startsWith(SESSION_COOKIE + "="));
  const token = part?.slice(SESSION_COOKIE.length + 1) || "";
  return /^v1\.[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
}
export function tidbAcceptanceAuthConfigured(env) {
  return configured(env);
}
export async function tidbAcceptanceLogin(request, env, url, matches = fixedPasswordMatches) {
  if (request.method !== "POST") return reply(405, { error: "METHOD_NOT_ALLOWED" });
  if (!tidbAcceptanceWithinWindow()) return reply(410, { error: "TEMPORARY_PAGE_EXPIRED" });
  if (!configured(env)) return reply(503, { error: "ACCEPTANCE_STORAGE_NOT_CONFIGURED" });
  if (!safeOrigin(request, url)) return reply(403, { error: "INVALID_ORIGIN" });
  const key = await failureKey(env, request);
  if (!key) return reply(403, { error: "CLIENT_NETWORK_UNAVAILABLE" });
  try {
    const count = Number(await env.SCHOOL_IP_KV.get(key) || 0);
    if (!Number.isSafeInteger(count) || count < 0 || count >= MAX_FAILURES)
      return reply(429, { error: "TOO_MANY_ATTEMPTS" });
    const supplied = await bodyPassword(request);
    if (supplied === null) return reply(400, { error: "PASSWORD_REQUIRED" });
    if (!await matches(supplied)) {
      await env.SCHOOL_IP_KV.put(key, String(count + 1), { expirationTtl: FAILURE_TTL });
      return reply(401, { error: "INVALID_CREDENTIALS" });
    }
    const token = "v1." + randomString();
    const csrf = randomString(24);
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
    const sessionKey = SESSION_PREFIX + await digest(token);
    // Refuse to authenticate if session persistence is not confirmed.
    await env.SCHOOL_IP_KV.put(sessionKey, JSON.stringify({ csrf, exp }), {
      expirationTtl: SESSION_TTL,
    });
    try { await env.SCHOOL_IP_KV.delete(key); } catch { /* session still secure */ }
    return reply(200, { authenticated: true, expires: exp }, {
      "Set-Cookie": cookie(token, SESSION_TTL),
    });
  } catch {
    return reply(503, { error: "AUTH_STORAGE_UNAVAILABLE" });
  }
}
export async function tidbAcceptanceSession(request, env) {
  if (!configured(env)) return null;
  const token = sessionToken(request);
  if (!token) return null;
  try {
    const record = await env.SCHOOL_IP_KV.get(SESSION_PREFIX + await digest(token));
    if (!record) return null;
    const parsed = JSON.parse(record);
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isInteger(parsed?.exp) || parsed.exp <= now ||
        parsed.exp > now + SESSION_TTL ||
        typeof parsed?.csrf !== "string" ||
        !/^[A-Za-z0-9_-]{32}$/.test(parsed.csrf)) return null;
    return { csrf: parsed.csrf, expiry: parsed.exp };
  } catch { return null; }
}
export async function tidbAcceptanceLogout(request, env) {
  const token = sessionToken(request);
  if (token && typeof env?.SCHOOL_IP_KV?.delete === "function") {
    try { await env.SCHOOL_IP_KV.delete(SESSION_PREFIX + await digest(token)); }
    catch { return reply(503, { error: "LOGOUT_STORAGE_UNAVAILABLE" }); }
  }
  return reply(200, { signedOut: true }, { "Set-Cookie": cookie("", 0) });
}
