# Vynalth Protocol Honeypot Sensor Stack — Local Lab

## Status
This is a deployable **local-only laboratory**, not a deployed internet sensor.
It uses official Cowrie and OpenCanary Docker images. No cloud VM has been
provisioned. No Cloudflare or Vercel deployment is performed. No TiDB data
is automatically ingested by running these containers.

## Capabilities and exact boundaries
| Capability | Local lab |
|---|---|
| SSH on localhost:2222 | Cowrie, real SSH listener, fake shell |
| Telnet on localhost:2223 | Cowrie, real Telnet listener |
| Fake FTP on localhost:2121 | OpenCanary |
| Fake MySQL on localhost:13306 | OpenCanary (**not TiDB port 4000**) |
| Fake Redis on localhost:16379 | OpenCanary |
| True session tapes | Cowrie TTY log; playlog must be invoked on actual recorded files |
| Suspicious-file indicators | Cowrie downloads; local hashing only; no execution |
| Cloudflare/TiDB | sanitized JSONL export only until gateway configured |

References:
- https://docs.cowrie.org/en/stable/docker/README.html
- https://docs.cowrie.org/en/stable/OUTPUT.html
- https://docs.cowrie.org/en/stable/
- https://www.opencanary.org/en/latest/starting/configuration.html

## Local-only smoke test (disposable laptop or isolated VM)

From the repository root with Docker Desktop / Docker Compose v2 installed:

```sh
docker compose -f sensor-stack/compose.lab.yaml config
docker compose -f sensor-stack/compose.lab.yaml up -d
docker compose -f sensor-stack/compose.lab.yaml ps
```

Cowrie connection (deliberately use a **throwaway fake password**; its raw local
logs can capture attempted credentials):

```sh
ssh -o StrictHostKeyChecking=accept-new -p 2222 demo@127.0.0.1
```

Telnet: connect to `127.0.0.1:2223` with a local Telnet client.

OpenCanary FTP: `127.0.0.1:2121`; MySQL: `127.0.0.1:13306`;
Redis: `127.0.0.1:16379`. All are fake services. **No real credentials**.

```sh
docker logs --tail=100 vynalth-lab-cowrie
docker logs --tail=100 vynalth-lab-opencanary
```

Raw container logs may include attempted usernames/passwords, commands and
network addresses; keep them private. **Never paste raw logs into GitHub,
ChatGPT or public dashboards.**

## Session replay with genuine Cowrie TTY files

Cowrie stores session recordings under
`/cowrie/cowrie-git/var/lib/cowrie/tty/`. After a successful interactive
session (not merely a failed login), list TTY files by using:

```sh
docker exec vynalth-lab-cowrie /cowrie/cowrie-env/bin/python3 -c "from pathlib import Path; p=Path('/cowrie/cowrie-git/var/lib/cowrie/tty'); print('\n'.join(x.name for x in p.glob('*.log')))"
```

Use Cowrie's bundled `playlog` with an **actual TTY log path**. Its
behavior depends on the installed image/version; do not claim session replay
passed until the rendered recording is inspected:

```sh
docker exec -it vynalth-lab-cowrie /cowrie/cowrie-env/bin/python3 /cowrie/cowrie-git/bin/playlog /cowrie/cowrie-git/var/lib/cowrie/tty/YOUR_SESSION.log
```

A login failure alone does **not** produce a full shell recording.

## Sanitize collected events before TiDB

Raw Cowrie/OpenCanary logs can contain sensitive attempted passwords.
Copy them to a secured local directory for offline processing:

```sh
mkdir -p sensor-stack/runtime
docker cp vynalth-lab-cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json sensor-stack/runtime/raw-cowrie.jsonl
docker logs vynalth-lab-opencanary > sensor-stack/runtime/raw-opencanary.jsonl
python sensor-stack/event_sanitizer.py --source cowrie --input sensor-stack/runtime/raw-cowrie.jsonl --output sensor-stack/runtime/cowrie.safe.jsonl
python sensor-stack/event_sanitizer.py --source opencanary --input sensor-stack/runtime/raw-opencanary.jsonl --output sensor-stack/runtime/opencanary.safe.jsonl
```

No network requests are made by the sanitizer. Only seven allowlisted fields
are exported (matching TiDB `honeypot_events`). It drops raw IP, username,
password, typed commands, file paths, URL/query, device identifiers, and
raw replay content. Optional `HONEY_SENSOR_NETWORK_HMAC_KEY` (32+ chars)
enables a **daily pseudonymous** IP hash; this is not anonymous data.

## Malware samples: offline metadata only

A Cowrie sensor may save untrusted file content inside its volume. Do not
open, execute, upload or extract it onto a production server. On a dedicated
isolated analysis host:

```sh
docker cp vynalth-lab-cowrie:/cowrie/cowrie-git/var/lib/cowrie/downloads sensor-stack/runtime/cowrie-downloads
python sensor-stack/sample_inventory.py --directory sensor-stack/runtime/cowrie-downloads --output sensor-stack/runtime/sample-manifest.json
```

The inventory uses byte hashing only, skips symlinks and nested directories,
limits individual files to 20 MiB, and emits SHA-256/size/UNVERIFIED_SAMPLE
status. **It never runs any file**. Detection or malware attribution must be
performed separately by a qualified, isolated analysis process. Never publish
untrusted binaries.

## Important production gates

The Docker lab ports bind **only to 127.0.0.1**, not the public internet.
The Docker bridge is not an egress firewall: before a public sensor release,
use a separate disposable VM/VLAN and verify host-level outbound allow/deny
rules from the host itself. No access to production Oracle VPN, voice, TiDB
root credentials, Cloudflare API tokens, SSH keys, DNS or other private
networks. Use non-root processes, resource and storage quotas, and pin
reviewed image digests. Confirm provider rules and actual zero cost first.

Never rebind public port 22 on an existing SSH machine. Never point public
`3306` at the real TiDB or its credentials. The lab is not a production
collector until the dedicated sensor node and authenticated ingestion are
independently tested.

## Shutdown without losing data

```sh
docker compose -f sensor-stack/compose.lab.yaml down
```

Do **not** add `-v` unless you explicitly intend to delete the Cowrie
volume and its session evidence.
