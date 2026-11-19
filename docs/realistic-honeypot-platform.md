# Vynalth realistic, isolated honeypot roadmap

## Scope and current implementation

### Web deception console — proposed in this branch

The fixed PHP decoy paths now show a working-looking **browser-only** console.
The login, mock shell, SQL editor, virtual file editor, services and backup
controls are interactive, but they **never touch the real origin**, production
files, databases, credentials or OS.

- The sign-in form has no input \`name\` attributes and no \`action\`; JavaScript
  intercepts submit and immediately clears input. The Worker returns **405**
  to POST/PUT/PATCH/DELETE on all decoy PHP paths.
- The browser-side script uses no \`fetch\`, \`XMLHttpRequest\`, \`sendBeacon\`,
  cookies, storage or arbitrary code execution. All arbitrary typed commands
  and SQL are interpreted as **text**, against a fixed fictional fixture.
- The CSP permits one fixed same-origin JS asset; it still blocks inline
  scripts, all outbound connections, form submissions and framing.
- In-browser activity history is *not* server-side full session replay.
  No usernames, passwords or typed command strings are sent to TiDB.
- The initial GET/HEAD HTTP probes keep the existing sanitized event pipeline,
  subject to the existing 10% TiDB sampling and service availability.
- The file editor's "save" state lasts in that browser tab only. No real file
  writes. The shell and database are deterministic, not remotely exploitable.
- No other root domain or PHP path outside the existing allowlist is changed.

This deception-first approach avoids exposing a genuinely vulnerable
application or letting an adversary use the honeypot as a pivot.

### True SSH/Telnet honeypot — NOT deployed

Use [Cowrie](https://docs.cowrie.org/) on a **dedicated, disposable sensor**
with no access to the user's production VPN, voice server, DNS, TiDB admin,
Vercel credentials or private networks.

Cowrie logs:
- SSH and Telnet connection and authentication events
- Emulated shell commands, filesystem access and client activity
- Terminal session tapes for **real replay** using its documented \`playlog\`
- Potential transferred-file samples, kept isolated and offline

Local-only smoke test (does **not** expose anything publicly):

\`\`\`sh
docker run --rm --name vynalth-cowrie-lab \
  -p 127.0.0.1:2222:2222 \
  cowrie/cowrie:latest

ssh -p 2222 root@127.0.0.1
\`\`\`

Review resource use, logging, container security, published port mappings,
internet egress and network firewall on a **separate** host before moving to
a public honeypot. Pin the image digest before any production deployment.
Do not install this on the active Oracle VPN or voice node.

### Multi-protocol network services — NOT deployed

Use [OpenCanary](https://www.opencanary.org/en/latest/) in an isolated
network namespace/container on a separate host. It can simulate multiple
TCP services, including MySQL and FTP, with configurable banners and events.
Its protocol-level decoys do not imply that the real TiDB database becomes
an attacker-facing fake MySQL server.

A normal website/Cloudflare HTTP Worker cannot accept raw internet SSH/Telnet
or arbitrary TCP protocol listeners on ports 22, 23 or 3306. Dedicated
compute, network firewall and controlled egress are prerequisites.

### Malware sample handling — NOT deployed

- First collect only *indicators* (file names or hashes/metadata from a
  dedicated sensor), not binaries from production websites.
- If sample capture is approved later, isolate it on a separate disposable
  machine with limited privileges, retention, access control, disk quotas,
  outbound restrictions, and malware scanning.
- **Never execute samples or allow arbitrary download/execution from a
  honeypot event.** Do not publish binaries, secret strings or personal data.
- Use hashes of quarantined files and linked event IDs for subsequent offline
  review; mark all findings unverified until evidence supports them.

### Global map and rankings — NOT live

Use *verified incoming* security observations from deployed sensors, aggregate
by country and AS number, mark source+last updated time, and clearly label
sampled/partial traffic. A single visit to a decoy is not evidence of
compromise. Don't display a \"world's most malicious IP\" ranking unless
independent reporting sources, provenance and deduplication are established.

## Infrastructure and cost constraints

- Existing TiDB Cloud Starter: **US$0 monthly spending cap**; must remain
  unchanged. Existing table: \`vynalth_honeypot.honeypot_events\`.
- Existing Cloudflare Worker only: no Vercel changes, new zone routes,
  upgrades or additional production deployments until user approval.
- The proposed enriched metadata in PR #96 is **still staged**, and requires
  separate SQL migration/approval. This UI PR does not alter TiDB schema.
- No new SSH/Telnet compute resources have been provisioned; do not claim
  Cowrie/OpenCanary/T-Pot or malware handling are active.

## Rollout and acceptance gates

1. GitHub tests, security regression and Wrangler dry-run must pass.
2. Confirm the browser UI has no credential capture, cross-origin calls, or
   access to true filesystem/services; verify responsive desktop and mobile.
3. Keep this PR unmerged until live Worker -> TiDB delivery is verified and
   a single safe deployment is authorized.
4. For a future independent Cowrie/OpenCanary node, start on localhost;
   validate the network isolation and firewall before public exposure.
5. Test actual *real* Cowrie command logs and replay separately from the
   in-browser simulator. Only after that may the feature be marked Live.
6. Implement the public map only after collecting actual event records,
   with uncertainty labels and privacy-safe aggregation.

No additional Vercel or Cloudflare production deployment is required merely
to review this documentation and GitHub PR.
