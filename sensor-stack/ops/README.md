# Dedicated Honeypot Collector Operations — STAGED (NOT DEPLOYED)

These four systemd template units are installation templates, NOT live services.
This repository does not authorize new Oracle/cloud resources, public ports,
production TiDB DDL or timers on the existing VPN/Voice hosts.

## Topology and privacy boundaries

On a separately reviewed, isolated sensor host:
- Cowrie and OpenCanary must be unable to reach production credentials, VPN,
  voice instances, Cloudflare secrets or unrestricted internet egress.
- An independent unprivileged collector reads restricted raw JSONL copies
  from /var/lib/vynalth-honeypot/raw/cowrie and .../opencanary. The log
  transfer/mount is NOT configured by this change and requires separate
  review. OpenCanary commonly logs to stdout, not necessarily to JSONL.
- Only sanitized metadata and HMAC-signed health state go in
  /var/lib/vynalth-honeypot/private with 0700/0600 permissions.
- Raw IPs, usernames, passwords, shell commands, malware bytes and terminal
  tapes must not be copied to GitHub, TiDB, Axiom or shared feeds.

## Prerequisites for actual installation

1. Approved isolated host and public ingress, strict verified no-egress,
   provider costs/quotas, boot disk and retention/compliance sign-off.
2. An unprivileged vynalth-collector account with read-only access to raw
   log copies and 0700 ownership of the private spool directory.
3. Reviewed Python scripts installed at /opt/vynalth-honeypot/sensor-stack.
4. A durable confidential HMAC key (32+ chars) stored OUTSIDE GitHub at
   /etc/vynalth-honeypot/evidence.key (root-owned 0600). systemd
   LoadCredential securely makes it available to the collector only.
   Preserve the key for later evidence verification; rotation requires
   a documented key-epoch procedure.
5. Raw archive retention: preserve all source.json.1, source.json.2,
   source.json.YYYY-MM-DD files until their offsets are acknowledged.
   Compressed, deleted or unknown archives cause release NO-GO.
6. Validate a hard restart, retained archive drain and independent recovery
   before activating any service timer.

## Service templates and monitoring

For Cowrie:
- vynalth-honeypot-collector@cowrie.timer — bounded local collection
  approximately every 60 seconds
- vynalth-honeypot-health@cowrie.timer — signed heartbeat validation
  approximately every 90 seconds; fails if older than 180 seconds

For OpenCanary, use the corresponding @opencanary templates ONLY after
its actual JSONL logging path has been configured and validated.

The service sandbox denies network access with
RestrictAddressFamilies=AF_UNIX and IPAddressDeny=any. It has no permission
to run Docker, execute untrusted commands or upload evidence. All journal
output is fixed-field status metadata, never raw event payloads.

Failures are observable through systemd and journald, but NO external
SOC notification destination has been connected yet. An operator must
separately monitor for stale heartbeat, backlog, disk pressure and key
integrity errors. Never suppress alerts to make readiness tests pass.

## Health and emergency stop

On the isolated host after operator installation, inspect the timer units,
their status and journal records. A missing archive, HMAC failure, stale
heartbeat or exhausted queue must stop the public decoy ingress until
triaged. Preserve existing evidence, do not erase logs, and do not disable
unrelated production VPN/Voice/Cloudflare/TiDB services.

Default limits: 32 recognized source files, 64MiB each, 10,000 SQLite rows,
512 lines maximum per batch, private storage with a disk-free guard.
Reaching a cap blocks the collector; it never silently overwrites evidence.

## Scope and unavoidable limits

GitHub CI validates retained archive rotation, restart/resume, HMAC and
heartbeat using synthetic fixtures and isolated, authentic Cowrie protocol
events. This is not a live 24/7 service, independent timestamp attestation,
zero-loss guarantee, or evidence of actual malicious internet attackers.

Writes made after the most recent observation and then deleted before the
next polling cycle are unrecoverable. Changing the source log in place
while preserving its first bytes may bypass generation detection. Both
require writer-side archive retention and operational controls, not merely
a clever parser. Production TiDB inserts and lawful external sharing remain
separate release gates.
