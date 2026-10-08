#!/usr/bin/env node
/**
 * Vynalth Shield: verified campus egress denial, zone-by-zone Cloudflare WAF.
 * This tool does not obtain IPs or infer school membership.
 * Dry-run by default: no API calls or writes without --apply and extra confirmation.
 * Prerequisite: the dedicated account IP List is already populated by trusted approvals.
 */
import { readFile } from "node:fs/promises";
import { isIP } from "node:net";

const ZONES = Object.freeze([
  "vynalthai.com",
  "vyncuslim.com",
  "sleepsomno.com",
  "powiismunc.com",
  "vitamindai.online"
]);
const RULE_NAME = "VYNALTH_SHIELD_VERIFIED_SCHOOL_EGRESS_DENY_V1";
const LIST_NAME = "powiis_verified_egress";
const EXPRESSION = "ip.src in $powiis_verified_egress";
const PHASE = "http_request_firewall_custom";
const PREFIX = "POWIIS|";
const API = "https://api.cloudflare.com/client/v4";
const apply = process.argv.includes("--apply");
const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const token = process.env.CLOUDFLARE_API_TOKEN;

const zoneMapFile = process.env.VYNALTH_CF_ZONE_MAP_FILE || "security/zone-ids.example.json";

function fail(msg) { throw new Error(msg); }
function requireFullZoneMap(map) {
  if (!map || typeof map !== "object" || Array.isArray(map)) fail("Zone map object required");
  const keys = Object.keys(map).sort();
  if (JSON.stringify(keys) !== JSON.stringify([...ZONES].sort())) {
    fail("All five known zones must be present, and no unknown zones are allowed.");
  }
  for (const domain of ZONES) {
    if (!/^[a-f0-9]{32}$/.test(map[domain])) fail("Invalid zone ID for " + domain);
  }
}
function isVerifiedFreshListItem(item, now) {
  const comment = String(item?.comment || "");
  const match = /^POWIIS\|exp=([^|]+)\|ref=([A-Za-z0-9_-]{8,64})$/.exec(comment);
  if (!match) return false;
  if (typeof item.ip !== "string") return false;
  const [ip, prefix] = item.ip.split("/");
  if (!((isIP(ip) === 4 && (prefix === undefined || prefix === "32")) ||
        (isIP(ip) === 6 && (prefix === undefined || prefix === "128")))) return false;
  const expiry = Date.parse(match[1]);
  return Number.isFinite(expiry) && expiry > now && expiry <= now + 12 * 60 * 60 * 1000;
}
async function api(path, method = "GET", body) {
  const res = await fetch(API + path, {
    method,
    headers: {
      Authorization: "Bearer " + token,
      "Content-Type": "application/json"
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(20_000)
  });
  const data = await res.json().catch(() => null);
  // Missing ruleset is a normal state for the phase GET.
  if (method === "GET" && res.status === 404 &&
      /\/rulesets\/phases\/http_request_firewall_custom\/entrypoint$/.test(path)) return null;
  if (!res.ok || data?.success !== true) {
    fail(method + " " + path + " HTTP " + res.status + " " +
      JSON.stringify(data?.errors || []).slice(0, 240));
  }
  return data.result;
}
async function accountList() {
  const lists = await api("/accounts/" + accountId + "/rules/lists");
  if (!Array.isArray(lists)) fail("Unexpected account lists response");
  const list = lists.find(x => x.name === LIST_NAME);
  if (!list || list.kind !== "ip") fail("Dedicated verified school IP List missing");
  return list;
}
async function listItems(listId) {
  const all = [];
  let cursor = null;
  const seen = new Set();
  do {
    const qs = new URLSearchParams({ per_page: "500" });
    if (cursor) qs.set("cursor", cursor);
    const url = "/accounts/" + accountId + "/rules/lists/" + listId + "/items?" + qs;
    const res = await fetch(API + url, {
      headers: { Authorization: "Bearer " + token },
      signal: AbortSignal.timeout(20_000)
    });
    const data = await res.json();
    if (!res.ok || !data.success || !Array.isArray(data.result)) fail("List fetch failed");
    all.push(...data.result);
    const next = data.result_info?.cursors?.after || null;
    if (next && seen.has(next)) fail("Repeated list cursor");
    if (next) seen.add(next);
    cursor = next;
  } while (cursor);
  return all;
}
function desiredRule() {
  return { description: RULE_NAME, expression: EXPRESSION, action: "block", enabled: true };
}
async function applyZone(domain, zoneId) {
  const zone = await api("/zones/" + zoneId);
  if (zone.name !== domain || zone.status !== "active") {
    fail("Wrong or inactive zone: " + domain);
  }
  const ruleset = await api("/zones/" + zoneId + "/rulesets/phases/" + PHASE + "/entrypoint");
  if (ruleset) {
    if (ruleset.kind !== "zone" || ruleset.phase !== PHASE || !Array.isArray(ruleset.rules)) {
      fail("Unexpected ruleset for " + domain);
    }
    const match = ruleset.rules.filter(x => x.description === RULE_NAME);
    if (match.length > 1) fail("Duplicate school deny rules at " + domain);
    if (match.length === 1) {
      const r = match[0];
      if (r.expression !== EXPRESSION || r.action !== "block" || r.enabled === false) {
        fail("Existing school deny rule differs on " + domain + " – manual review required");
      }
      console.log("Already configured: " + domain);
      return;
    }
    await api("/zones/" + zoneId + "/rulesets/" + ruleset.id + "/rules",
      "POST", desiredRule());
  } else {
    await api("/zones/" + zoneId + "/rulesets", "POST", {
      name: "Vynalth Shield zone WAF",
      kind: "zone",
      phase: PHASE,
      rules: [desiredRule()]
    });
  }
  console.log("Created: " + domain);
}
async function main() {
  if (!apply) {
    console.log(JSON.stringify({
      mode: "DRY_RUN",
      list: LIST_NAME,
      expression: EXPRESSION,
      action: "block",
      zones: ZONES,
      note: "No API calls. Real zone IDs and fresh verified IP list needed before --apply."
    }, null, 2));
    return;
  }
  const zoneMap = JSON.parse(await readFile(zoneMapFile, "utf8"));
  requireFullZoneMap(zoneMap);
  if (!/^[a-f0-9]{32}$/.test(accountId || "") || !token) {
    fail("Valid CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN required");
  }
  if (process.env.VYNALTH_WAF_CONFIRM !== "ENABLE_VERIFIED_SCHOOL_BLOCK") {
    fail("Explicit VYNALTH_WAF_CONFIRM required");
  }
  const list = await accountList();
  const items = await listItems(list.id);
  if (items.length === 0 || items.some(x => !isVerifiedFreshListItem(x, Date.now()))) {
    fail("Refusing to enable: list empty or contains unknown/expired entries");
  }
  console.log("Validated " + items.length + " currently approved exact addresses.");
  for (const domain of ZONES) {
    await applyZone(domain, zoneMap[domain]);
  }
  console.log("Zone WAF rules created/verified. Validate proxied DNS and real HTTP responses.");
}
main().catch(error => { console.error("WAF setup:", error.message); process.exitCode = 1; });
