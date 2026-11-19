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

For Cowrie TTY recordings: optional local SHA-256 of the **actual tape** and
the physical file size. Cowrie's own `shasum` is an *attacker input-only*
digest; the event `size` is kept as a separate source-reported value and
is NOT assumed identical to the physical recording size. This avoids false
custody mismatches due to serialized terminal framing. Neither the hash nor
the existence of a TTY file proves it has been replayed by an investigator.

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

GitHub CI indexes genuine, disposable Cowrie sessions, including an
authenticated fake-shell session and a harmless command, and also verifies
real TTY frame parsing and output reconstruction in a digest-only sink.
The tests do not print raw terminal output or execute uploaded binaries.
This demonstrates replayable forensic structure in disposable CI, not a
public attacker session or a forensic operator having watched a recording.

## Restart-safe long-running event queue (staged, not deployed)

The durable_spool.py CLI continuously *supports incremental invocations* on
an append-only Cowrie/OpenCanary JSONL file. It stores a protected SQLite
spool with only the sanitized event fields and a durable byte offset.

- SQLite WAL + FULL synchronous mode; transactional write of events and
  checkpoint. A crash before COMMIT causes safe reprocessing on the next run.
- The next invocation resumes from the last committed byte, and cannot
  acknowledge an unfinished JSONL line. Oversized lines are bounded.
- File inode replacement and truncation are detected. WARNING: an unread
  rotated-away file is not automatically recovered; save and drain rotated
  files before deleting them. Do not claim guaranteed zero data loss.
- The restricted local database and parent folder must be 0600 / 0700.
  Rows are signed with an HMAC key, and verify mode detects record tampering.
- Bounded 512 lines per invocation and an operator-selected row cap. If
  capacity is reached, the entire pending batch and checkpoint roll back.
  Such a sensor must stop and alert rather than silently discard evidence.
- No attacker usernames, passwords, raw IPs, commands or original TTY bytes
  enter this database. The original raw JSONL and binary TTY tapes remain
  separately restricted. No network or cloud dependencies.

On an approved isolated server, set a signing key securely *outside GitHub*
then invoke (e.g., with a supervised timer after deployment):

    python sensor-stack/durable_spool.py --source cowrie --sensor-id cloud-ssh-01 --input /restricted/raw/cowrie.jsonl --db /restricted/spool/cowrie.db

Check independent HMAC integrity:

    python sensor-stack/durable_spool.py --db /restricted/spool/cowrie.db --verify

These are examples; no 24/7 timer, VM, public ports, or network sender was
activated by this PR. A real production collector must additionally monitor
spool growth, disk pressure, raw input rotation, clock synchronization and
backlog drain; failed capacity checks must alert an operator.

## Safe TTY format replay

The safe_tty_replay.py tool independently validates Cowrie's UML-style
binary frame format, length bounds and stream directions; it reconstructs
the output bytes into a one-way hash sink without displaying any untrusted
terminal content or executing commands. The CI uses genuine Cowrie TTY
generated by a fake-shell test.

    python sensor-stack/safe_tty_replay.py --tty /restricted/tty/approved-recording

This is not identical to running Cowrie's official playlog executable:
the official CLI was not available in the disposable Cowrie image and
its execution was not confirmed. Both the local file SHA-256 and the
reconstructed stream SHA-256 are available for verification.

The tests also use synthetic TTY and sample data to exercise malformed
frame, symlink, oversized content and tampering protection.

## Enterprise release gates still outstanding

1. Dedicated public sensor VM with real firewall egress-denial proof,
   no access to production environments and enforced rate/volume limits.
2. Real interactive Cowrie session, isolated TTY playback and custody records.
3. Secure sample quarantine, strict storage/retention, offline inspection.
4. Durable local spool now supports transactional checkpoints and re-entry;
   it is not yet running in a supervised 24/7 deployment. Rotated-away files
   and power-loss restoration still require independent host acceptance.
5. Actual Worker and signed sensor summaries inserted in real TiDB, with
   database verification and separate telemetry of failed writes.
6. Human review of false positives and TLP before STIX/MISP partner sharing.
7. Sensor uptime, timestamp drift, drop rates, disk pressure, source image
   versions and abuse complaints monitored with operational response.

## Official documentation

- Cowrie event fields: https://docs.cowrie.org/en/stable/OUTPUT.html
- Cowrie filesystem/recording docs: https://docs.cowrie.org/en/stable/README.html
- FIRST TLP: https://www.first.org/tlp/
