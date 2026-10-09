# Vynalth Cloudflare Edge

Unified Cloudflare edge Worker for Vynalth-managed web properties.

## Managed zones

The Worker is configured for the apex and all HTTP/HTTPS subdomains of:

- `vynalthai.com`
- `vyncuslim.com`
- `sleepsomno.com`
- `powiismunc.com`
- `vitamindai.online`
- `vynalthai.si`
- `vyncuslim.si`

Mail transport hostnames that are used for SMTP/IMAP/POP should remain DNS-only and are not expected to use HTTP response headers.

## Architecture

```text
Browser / API client
  -> Cloudflare edge
     -> DDoS protection
     -> WAF / custom rules
     -> bot and rate-limit controls
     -> zone security policy
  -> Vynalth Cloudflare Edge Worker
     -> preserves the original public hostname / Host header
     -> adds x-vynalth-* tracing headers
  -> the hostname's configured Cloudflare DNS origin
  -> application origin (Vercel or another backend)
```

The Worker does not hard-code a single Vercel hostname. Each domain and subdomain keeps its own DNS origin, so multiple sites can safely share the same edge Worker.

## Response tracing headers

HTTP/HTTPS responses traversing the Worker receive:

```text
x-vynalth-edge: cloudflare-worker
x-vynalth-edge-host: <public hostname>
x-vynalth-zone: <root zone>
x-vynalth-request-id: <unique UUID>
x-vynalth-ray-id: <Cloudflare Ray ID when available>
x-vynalth-origin: vercel | fastly | dns-origin
```

`x-vynalth-request-id` is generated at the edge for every request.

## Canonical redirect

Only `www.vynalthai.com` is canonicalized by this Worker:

```text
https://www.vynalthai.com/*
  -> 301
https://vynalthai.com/*
```

Certificate and Vercel ownership validation paths are exempt from this redirect:

```text
/.well-known/acme-challenge/*
/.well-known/vercel/*
```

## Worker routes

`wrangler.toml` attaches this Worker to both the apex and wildcard route for every managed zone:

```text
vynalthai.com/*
*.vynalthai.com/*

vyncuslim.com/*
*.vyncuslim.com/*

sleepsomno.com/*
*.sleepsomno.com/*

powiismunc.com/*
*.powiismunc.com/*

vitamindai.online/*
*.vitamindai.online/*
```

A hostname must still have a valid Cloudflare DNS record and its HTTP/HTTPS traffic must actually enter Cloudflare for the Worker route to execute.

## vynalthai.com partial DNS setup

`vynalthai.com` currently uses a Cloudflare Partial/CNAME setup with Dynadot remaining authoritative.

External authoritative DNS should send proxied web hostnames to Cloudflare's partial hostname. Examples:

```text
@            ANAME -> vynalthai.com.cdn.cloudflare.net
www          CNAME -> www.vynalthai.com.cdn.cloudflare.net
partner      CNAME -> partner.vynalthai.com.cdn.cloudflare.net
status       CNAME -> status.vynalthai.com.cdn.cloudflare.net
```

Inside the Cloudflare zone, each hostname keeps its real application origin, for example a Vercel CNAME.

Do not point public authoritative DNS directly at Vercel if the hostname is intended to traverse Vynalth Edge.

## Other managed zones

For zones using Cloudflare as authoritative DNS, web-facing A/AAAA/CNAME records should normally be proxied (orange cloud) when they are intended to use Vynalth Edge.

Do not proxy ordinary mail transport records such as MX targets used for SMTP/IMAP/POP.

## Files

- `src/index.js` — multi-zone edge Worker and tracing logic.
- `wrangler.toml` — Worker configuration and multi-zone routes.
- `.github/workflows/deploy.yml` — GitHub Actions deployment workflow.

## GitHub repository secrets

Automatic deployment requires:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

The Cloudflare API token must be allowed to deploy Workers and manage Worker routes for all managed zones.

## Verification

Examples:

```powershell
curl.exe -I https://vynalthai.com
curl.exe -I https://vyncuslim.com
curl.exe -I https://sleepsomno.com
curl.exe -I https://powiismunc.com
curl.exe -I https://vitamindai.online
curl.exe -I https://partner.vynalthai.com
```

Expected Cloudflare/Vynalth indicators include:

```text
server: cloudflare
cf-ray: ...
x-vynalth-edge: cloudflare-worker
x-vynalth-edge-host: ...
x-vynalth-zone: ...
x-vynalth-request-id: ...
x-vynalth-ray-id: ...
x-vynalth-origin: ...
```

## Local commands

```bash
npm install
npm run dev
npm run deploy
npm run tail
```

## POWIIS candidate IP policy integration (observe only)

This Worker owns all **seven** configured zone Routes. It calls the separate `website-block-by-school-powiis` policy Worker through an internal **SCHOOL_POLICY** Service Binding, rather than assigning the policy Worker a Custom Domain over an existing website.

1. The policy Worker has the `SCHOOL_IP_KV` binding to namespace `website-block-by-school-powiis-school-ip-kv`.
2. The edge Worker passes only the Cloudflare-observed source IP, the hostname, path and HTTP method; URL query parameters, cookies and request bodies are not forwarded.
3. The policy Worker records only unverified candidate IPs on root GET requests and reports an allowed response (204). It can return a tagged 403 only if `MODE=enforce` **and** a `blocked:IP` key is manually created.
4. The edge Worker retains the existing origin proxy, tracing headers, redirects, validation-path exceptions and all upstream Cloudflare WAF controls. Unknown policy failures fail open to avoid taking down the website.
5. The added `.si` routes activate only on hosts with Cloudflare-proxied web DNS records and correct zone permissions. Never point SMTP/IMAP/MX transport hostnames to Workers.
6. Review Cloudflare deployment / GitHub Actions logs to confirm routes actually deployed. Updating a GitHub config does not alone prove the live Cloudflare routes changed.

The service binding and routes are declared in `wrangler.toml`. Test before deployment with `npm test`.
