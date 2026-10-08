#!/usr/bin/env node
/**
 * School verified-egress expiration reconciler. Run hourly from GH Actions or
 * another trusted scheduler. Never delete unmanaged items, no broad prefixes.
 * DRY-RUN by default; --apply requires explicit confirmation & API token.
 */
import { isIP } from "node:net";

const ACCOUNT = process.env.CLOUDFLARE_ACCOUNT_ID || "";
const LIST = process.env.CLOUDFLARE_IP_LIST_ID || "";
const TOKEN = process.env.CLOUDFLARE_API_TOKEN || "";
const NAME = "powiis_verified_egress";
const apply = process.argv.includes("--apply");
const apiRoot = "https://api.cloudflare.com/client/v4";
const base = "/accounts/" + ACCOUNT + "/rules/lists/" + LIST;
function fail(message) { throw new Error(message); }

export function expiry(item, now = Date.now()) {
  if (!item || typeof item.ip !== "string") return null;
  const match = /^POWIIS\|exp=([^|]+)\|ref=([A-Za-z0-9_-]{8,64})$/.exec(String(item.comment || ""));
  if (!match) return null;
  const [ip, prefix] = item.ip.split("/");
  if (!(isIP(ip) === 4 && (prefix === undefined || prefix === "32") ||
        isIP(ip) === 6 && (prefix === undefined || prefix === "128"))) return null;
  const expires = Date.parse(match[1]);
  if (!Number.isFinite(expires)) return null;
  return { expired: expires <= now, expires, reference: match[2] };
}

async function cf(path, method = "GET", body) {
  const res = await fetch(apiRoot + path, {
    method,
    headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(15000)
  });
  const data = await res.json();
  if (!res.ok || data?.success !== true) fail("Cloudflare request failed " + method + " " + path);
  return data;
}
async function listItems() {
  const items = [];
  let cursor = null;
  const cursors = new Set();
  do {
    const p = new URLSearchParams({ per_page: "500" });
    if (cursor) p.set("cursor", cursor);
    const page = await cf(base + "/items?" + p);
    if (!Array.isArray(page.result)) fail("Invalid list response");
    items.push(...page.result);
    cursor = page.result_info?.cursors?.after || null;
    if (cursor && (cursors.has(cursor) || items.length > 10000)) fail("List pagination limit");
    if (cursor) cursors.add(cursor);
  } while (cursor);
  return items;
}
async function waitForBulk(id) {
  if (!/^[a-f0-9]{32}$/.test(id)) fail("Invalid bulk operation ID");
  for (let n=0;n<24;n++) {
    const data = await cf("/accounts/" + ACCOUNT + "/rules/lists/bulk_operations/" + id);
    const state = data.result?.status;
    if (state === "completed") return;
    if (state === "failed") fail("Bulk list operation failed");
    if (state !== "pending" && state !== "running") fail("Unexpected list operation state");
    await new Promise(resolve => setTimeout(resolve, 750));
  }
  fail("Bulk operation not confirmed");
}
async function main() {
  if (!/^[a-f0-9]{32}$/.test(ACCOUNT) || !/^[a-f0-9]{32}$/.test(LIST) || !TOKEN) {
    if (!apply) {
      console.log("DRY_RUN — set Cloudflare variables to inspect live entries.");
      return;
    }
    fail("Cloudflare account/list/token must be configured");
  }
  if (apply && process.env.VYNALTH_SCHOOL_EXPIRY_CONFIRM !== "DELETE_EXPIRED_VERIFIED_IPS") {
    fail("Explicit expiry cleanup confirmation missing");
  }
  const metadata = await cf(base);
  if (metadata.result?.name !== NAME || metadata.result?.kind !== "ip") {
    fail("Incorrect list identity/type");
  }
  const items = await listItems();
  const expired = items.filter(item => expiry(item)?.expired);
  console.log(JSON.stringify({
    mode: apply ? "APPLY" : "DRY_RUN",
    total: items.length,
    expiredVerifiedItems: expired.map(x => ({ip:x.ip, id:x.id}))
  }));
  if (!apply || expired.length === 0) return;
  if (expired.length > 100) fail("Too many expired items for unattended cleanup; manual review required");
  const result = await cf(base + "/items", "DELETE", {
    items: expired.map(x => ({ id:x.id }))
  });
  await waitForBulk(result.result?.operation_id);
  const after = await listItems();
  if (expired.some(item => after.some(x => x.id === item.id))) {
    fail("Expired entries still present after API success");
  }
  console.log("Confirmed removal of " + expired.length + " expired verified egress entries.");
}
main().catch(err => {
  console.error("SCHOOL_EXPIRY:", err.message);
  process.exitCode = 1;
});
