# Incident: Cloudflare Workers Builds route conflict (code 10020)

## Definitive evidence (2026-10-22 build 9b10dd46)

The uploaded Cloudflare build log records:

- Dependency install succeeded; Wrangler 4.151.3 bundled and uploaded 135.91 KiB.
- Cloudflare reported `Uploaded vynalth-cloudflare-edge` and `Deployed vynalth-cloudflare-edge triggers` including the workers.dev URL.
- The final failure was in applying **routes**: `Trigger configuration ... only partially updated`, `A route with the same pattern already exists ... [code: 10020]`.
- Cloudflare explicitly warned that successful trigger changes were **not rolled back**.
- The local vs remote config diff showed reordered/changed route entries, `preview_urls` and a service binding `environment`. That comparison is not itself the 10020 root cause, and the log does not name the conflicting pattern's owning Worker.

Do **not** delete routes merely because Cloudflare reports duplicate patterns. Removing an existing route could reroute traffic away from GPS/access/security checks or another legitimate Worker.

## Low-risk solution: deploy versions without rewriting triggers

The new default npm deploy command is:

```sh
npm run deploy
```

Implemented in `scripts/deploy-preserve-routes.mjs`:

1. Require an exact full Git commit SHA from the build environment or `git rev-parse HEAD`.
2. Upload a tagged Worker version using `wrangler versions upload --tag git-<SHA-prefix> --keep-vars`; this uploads code/bindings while preserving existing dashboard-defined vars and does **not** synchronize route triggers.
3. Promote the precise tag to 100% of current Worker traffic using `wrangler versions deploy --version-tag <tag> --percentage 100 --yes`.
4. Report failures if either stage fails. Never automatically call `wrangler triggers deploy` or `wrangler deploy` from this safe path.

This prevents the repeated create-route operation that caused 10020 while preserving currently assigned routes. It **does not reconcile missing/wrong routes**; that still requires a separate audited trigger change.

## Required Cloudflare dashboard configuration

Open Cloudflare > Workers & Pages > `vynalth-cloudflare-edge` > Settings > Builds, and update the native Cloudflare **Deploy command** from:

```sh
npx wrangler deploy
```

to:

```sh
npm run deploy
```

Keep Git repository `vyncuslim/vynalth-cloudflare-edge`, production branch `main`, and root directory `/`. Build command `None` is acceptable for the current simple JS Worker. Do not change `wrangler.toml` routes blindly.

The above UI setting **must be saved**, and this PR **must be merged to main** before the native Cloudflare build can use the new script. If the Cloudflare build runs a commit without this script, `npm run deploy` will fail, so use a coordinated change or temporarily disable automatic production builds until both are ready.

After updating, retry the newest `main` build. Verify the Cloudflare **Builds** check is green, the expected new Worker version is deployed, the 8 intended domain routes are present, and the GPS/access/security flows still behave normally. Do not call a successful version upload a successful production deploy.

## Important separate blocker: GitHub Actions

`.github/workflows/deploy.yml` also uses the safe command but still **requires** its own `CLOUDFLARE_API_TOKEN` Actions secret. The latest `main` GitHub deployment failed at the explicit missing-secret guard. Either configure that secret with least privilege and plan to use the GitHub deployment path, or designate Cloudflare native Builds as the sole authoritative deploy path. Do not permit competing deployments to race.

## Route conflict ownership audit

For each zone represented in `wrangler.toml`, inspect the zone's Workers Routes in Cloudflare Dashboard. Identify which Worker owns each exact pattern. Record before changing anything:

```text
*.sleepsomno.com/*
*.vyncuslim.com/*
*.vynalthai.com/*
*.vynalthai.si/*
*.powiismunc.com/*
*.vyncuslim.si/*
vynalthai.com/*
*.vitamindai.online/*
```

If a route is assigned to a different legitimate Worker, do not overwrite it. If one is missing, create it only after comparing live routing, exact domain/zone and origin behavior. Keep Vynova CDN's separate Worker route ownership intact.

## Evidence and references

- Uploaded production log `vynalth-cloudflare-edge.production.9b10dd46...build.log` lines 95-108
- Official Cloudflare Worker versions and deployments: https://developers.cloudflare.com/workers/versions-and-deployments/
- Official Wrangler commands (versions upload/deploy/triggers deploy): https://developers.cloudflare.com/workers/wrangler/commands/workers/
- Deployment management: https://developers.cloudflare.com/workers/versions-and-deployments/deployment-management/
