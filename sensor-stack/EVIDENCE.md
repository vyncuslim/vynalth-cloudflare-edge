# Vynalth Honeypot Evidence Chain v1 — Professional Forensic Intake

**Status:** Implemented offline, not a public 24/7 sensor. Never represent
synthetic CI traffic as actual malicious attacker evidence. Live Cloudflare
Web honeypot observations and Cowrie/OpenCanary protocol recordings have
different provenances and MUST NOT be conflated.

## What the collector preserves

The evidence_capture.py script reads actual local Cowrie/OpenCanary JSONL and
generates a private, integrity-protected metadata index. It recognizes:

- Cowrie: session.connect / session.closed, login.failed / login.success,
  command.input / command.failed, log.closed, session.file_download /
  session.file_upload.
- OpenCanary: FTP, MySQL and Redis destination ports with typed log events.

For every recognized source event it indexes source, protocol, event class,
source-provided UTC timestamp (never fabricated), HMAC-pseudonymized daily
network source, HMAC-pseudonymized Cowrie session, and coarse command behavior
class. Categories include download, persistence, reconnaissance, destructive
process, privilege/access changes, and other. It never exports the command
text, username, password, domain, URL, raw source IP or raw session ID.

For Cowrie TTY recordings: optional local SHA-256 and file-size verification,
with Cowrie's separate *attacker input-only* SHA-256. This is NOT verification
that the replay was opened or read by an investigator.

For Cowrie file uploads/downloads: optional local SHA-256, file size, magic
type and comparison with Cowrie's reported file digest. File content remains
in secure quarantine and is never executed.

All evidence is initially marked verified_intrusion=false,
share_authorized=false, indicator_status=observation_only. A honeypot trigger
is not proof of legal identity or compromise of a production host.

## Integrity and chain of custody

The index hashes the source JSONL file with SHA-256 and independently chains
the SHA-256 of each sanitized event. A final manifest HMAC-SHA256 uses the
protected VYNALTH_EVIDENCE_HMAC_KEY (32+ characters) held outside GitHub.

This detects unauthorized changes only while the key remains secret. It does
NOT provide independent timestamping, proof of legal authorship or third-party
attestation. Use organizational identity controls and an append-only audit
store for stronger chain of custody.

The output file mode is 0600 and never overwrites existing data. Raw input
is limited to 64 MiB / 10,000 lines; individual artifacts to 20 MiB, and
index output to 16 MiB. Reads reject symlinks and nonregular files. No network
calls or binary execution occur.

## Run only on a separately approved cloud evidence node

No user laptop or Docker installation is required. The process MUST NOT be
run on the existing production VPN or Voice instance. This PR does not
provision a cloud VM or open public TCP ports.

On a dedicated restricted host, securely set VYNALTH_EVIDENCE_HMAC_KEY
and invoke:

    python sensor-stack/evidence_capture.py --source cowrie --input /restricted/raw/cowrie.jsonl --tty-dir /restricted/tty --download-dir /restricted/downloads --output /restricted/manifests/cowrie-index.json

To verify the HMAC and event chain:

    python sensor-stack/evidence_capture.py --source cowrie --input /restricted/manifests/cowrie-index.json --verify

For OpenCanary:

    python sensor-stack/evidence_capture.py --source opencanary --input /restricted/raw/opencanary.jsonl --output /restricted/manifests/opencanary-index.json

GitHub CI indexes genuine, disposable Cowrie connection events, plus
strictly synthetic TTY and file fixtures. This does not demonstrate
production attacker sessions, real attacker malware or replay acceptance.

## Enterprise release gates still outstanding

1. Dedicated public sensor VM with real firewall egress-denial proof,
   no access to production environments and enforced rate/volume limits.
2. Real interactive Cowrie session, isolated TTY playback and custody records.
3. Secure sample quarantine, strict storage/retention, offline inspection.
4. Durable local log spool, restart checkpoint and rotation recovery. The
   current offline one-shot tool is not a 24/7 log processor.
5. Actual Worker and signed sensor summaries inserted in real TiDB, with
   database verification and separate telemetry of failed writes.
6. Human review of false positives and TLP before STIX/MISP partner sharing.
7. Sensor uptime, timestamp drift, drop rates, disk pressure, source image
   versions and abuse complaints monitored with operational response.

## Official documentation

- Cowrie event fields: https://docs.cowrie.org/en/stable/OUTPUT.html
- Cowrie filesystem/recording docs: https://docs.cowrie.org/en/stable/README.html
- FIRST TLP: https://www.first.org/tlp/
