# Vynalth Cloudflare Edge

Cloudflare edge proxy for the production Vynalth AI site.

## Architecture

```text
Browser
  -> https://vynalthai.com
  -> Cloudflare edge
     -> DDoS protection
     -> WAF / custom rules
     -> IP and country controls
     -> rate limiting
  -> Cloudflare Worker
  -> https://somno-ai-digital-sleep-lab.vercel.app
  -> Vercel production application
```

The public domain remains `vynalthai.com`. The Worker deliberately uses the stable Vercel production alias as its origin. Do **not** change `ORIGIN_HOST` to `vynalthai.com`, because once the apex is proxied through this Worker that would create a proxy loop.

## Files

- `src/index.js` — reverse proxy Worker.
- `wrangler.toml` — Worker and `vynalthai.com/*` route configuration.
- `.github/workflows/deploy.yml` — GitHub Actions deployment.

## GitHub repository secrets

Configure these repository secrets before automatic deployment:

```text
CLOUDFLARE_API_TOKEN
CLOUDFLARE_ACCOUNT_ID
```

The API token must be able to deploy Workers and manage the Worker route for the `vynalthai.com` zone.

If the secrets are not configured, the GitHub Action exits successfully and skips deployment instead of failing.

## Cloudflare zone

The Cloudflare zone must contain a proxied record for the apex hostname. For the current Vercel origin configuration:

```text
Type: A
Name: @
Target: 216.198.79.1
Proxy status: Proxied
```

The Worker route is defined as:

```text
vynalthai.com/*
```

Cloudflare WAF and other edge security controls are evaluated before requests are sent to the Worker.

## Partial DNS setup

Because the authoritative nameservers currently remain outside Cloudflare, the authoritative DNS provider must send the apex hostname into Cloudflare's partial/CNAME setup before the Worker route can receive production traffic.

For a provider that supports apex ANAME/ALIAS flattening, the intended target is:

```text
vynalthai.com.cdn.cloudflare.net
```

Do not remove the currently working Vercel apex record until the Cloudflare partial hostname is verified and the replacement apex record can be tested immediately. If the authoritative DNS returns NODATA after the switch, restore the working Vercel apex A record.

## Verification

After Cloudflare is in the traffic path:

```powershell
ipconfig /flushdns
curl.exe -I https://vynalthai.com
curl.exe https://vynalthai.com/cdn-cgi/trace
```

Expected indicators include:

```text
server: cloudflare
cf-ray: ...
x-vynalth-edge: cloudflare-worker
x-vynalth-origin: vercel
```

The `x-vynalth-edge` and `x-vynalth-origin` headers are added by this Worker to make routing verification easy.

## Local commands

```bash
npm install
npm run dev
npm run deploy
npm run tail
```
