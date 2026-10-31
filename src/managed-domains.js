// This is an explicit inventory of Vynalth-operated root domains that were
// assigned to this edge Worker in the operator's Cloudflare Dashboard.
// An entry does not create a DNS record, Worker route, or WAF exception.
export const MANAGED_ROOT_DOMAINS = Object.freeze([
  "vynalthai.com",
  "vynalthai.si",
  "vyncuslim.com",
  "vyncuslim.si",
  "vyncuslim.my",
  "sleepsomno.com",
  "vitamindai.online",
  "powiismunc.com",
  "vynli.xyz",
  "vynlink.xyz",
  "zokivo.xyz",
]);

export function getRootDomain(hostname) {
  if (typeof hostname !== "string" || hostname.length > 253) return null;
  const host = hostname.toLowerCase();
  if (!/^[a-z0-9.-]+$/.test(host) || host.includes("..") ||
      host.startsWith(".") || host.endsWith(".")) return null;
  return MANAGED_ROOT_DOMAINS.find(root => host === root || host.endsWith("." + root)) || null;
}
