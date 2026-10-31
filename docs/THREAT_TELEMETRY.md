# Vynalth AI Shield — Worker threat telemetry forwarder

This feature is **off by default**. It is an optional addition to the EXISTING
\`vynalth-cloudflare-edge\` Worker; it does not change GPS, consent, School
Policy, bot protection, domain routing or origin behavior.

## Scope

Only requests that **reach this Worker** and match known security-probe
categories (\`/.env\`, \`/api/.env\`, \`/api/config.json\`, \`/.git/*\`,
\`/wp-login.php\`, \`/cgi-bin/*\`, etc.) may be reported. The module sends a
fixed path template, observation time, first-party host, method, and Cloudflare
Ray ID where present. It does **not** send IP, headers/cookies, user-agent,
query strings, body, location, private chat, or any credential. Observations
are **UNVERIFIED**: a scan attempt does not mean a breach occurred.

The sender cannot see requests blocked before the Worker by Cloudflare WAF;
a separate approved WAF-log ingestion mechanism would be needed for that.

## Dependencies before enabling

1. Main **website GitHub** PR #122:
   https://github.com/vyncuslim/SomnoAI-Digital-Sleep-Lab/pull/122
   must be reviewed and deployed to the **correct**
   \`somno-ai-digital-sleep-lab\` Vercel project.
2. Production \`/api/security/ingest\` must accept a server-to-server
   request and return **202** after persistent writes to the correct
   Supabase project \`ojcvvtyaebdodmegwqan\` with its private RLS table.
   A 403 Cloudflare challenge or 503 from an unconfigured endpoint is NOT
   successful collection.
3. Both the correct Vercel project and this Cloudflare Worker must have
   the exact same high-entropy Secret named \`THREAT_INTEL_INGEST_TOKEN\`
   (at least 32 characters). Never commit or paste the secret publicly.
4. Existing database schema has already been updated to recognize
   provenance \`cloudflare_worker\`; the website GitHub PR includes the
   matching SQL migration.
5. \`THREAT_INTEL_COLLECT_ENABLED\` currently defaults to **false** in
   \`wrangler.toml\`. Only switch it to **true** after approved end-to-end
   verification of the receiving route, auth, retention, and no loops.
   This switch is NOT an instruction to disable any WAF policies.

## Behavior

- Uses \`ctx.waitUntil()\` so telemetry cannot delay or change a visitor
  response. Delivery failures only log an HTTP status or generic failure.
- Posts to \`https://vynalthai.com/api/security/ingest\`, no redirects
  accepted, requiring HTTP **202** for success.
- If Cloudflare's same-zone routing or security challenge prevents the
  subrequest, do not bypass or relax the general WAF. Prefer a reviewed,
  properly authenticated origin/service route instead.
- Run \`npm test\` and check full Workers Builds logs before changing the flag.

## Proof of real collection

Use an authorized synthetic request to a test probe path that does not
contain sensitive data. Confirm the Worker saw it, the authorized sender
received 202, one RLS-protected \`cloudflare_worker\` event exists in
Supabase, deduplication works and the retention job removes stale events.
Do not claim traffic ingestion based only on a published Worker version.
