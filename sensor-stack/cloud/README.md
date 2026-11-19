# Dedicated 24/7 cloud sensor — STAGED, NOT PROVISIONED

All source code in this folder is deployable only to a **new, isolated**
Oracle Cloud Always Free-eligible VM after an operator authorizes cloud
creation, verifies available resources, and confirms there is no charge.
It is NOT a deployment to the existing Oracle VPN/Voice, Cloudflare or Vercel.

## Current actual evidence

PR #100's GitHub-hosted ephemeral integration test connected real SSH/Telnet,
FTP, MySQL and Redis services, then verified two Cowrie + four OpenCanary
sanitized log events. It also tested a synthetic review/signature/STIX/MISP
chain. Those controlled CI events are NOT public attacker observations and
were deleted after the run. The most recent user SQL result showed only
\`local_test\` in TiDB; no actual production Worker INSERT is yet verified.

## OCI free-tier and ARM64 readiness gates

- Official Oracle Free Tier: OCI Ampere A1 Flex consumes **monthly shared**
  resources across ALL running A1 instances. Also inspect 50-GB boot volume
  and region-specific capacity and public IPv4 billing before provisioning.
- Proposed VM shape: VM.Standard.A1.Flex, 1 OCPU / 6 GB RAM, 50 GB boot
  volume. **This is a design target, not proof it is available or free for
  this account.** Check every existing VM and volume in the tenancy first.
- Use a dedicated **new** compartment, VCN, security list and VM. No
  existing private IPs, SSH keys, subnets, volumes, database credentials,
  VPN interface, domain or workload may be reused.
- Both Cowrie and OpenCanary have ARM64 builds. The HAProxy release must be
  independently checked on ARM64 and all production images digest-pinned
  before any live run.
- Do NOT use GitHub Actions as an always-on public honeypot.
- Oracle Terraform module defaults: \`launch_approved=false\`,
  \`public_decoys_approved=false\`, \`admin_ssh_cidr=""\`.
- Terraform is intentionally never executed by GitHub CI. Do not run
  \`terraform apply\` until all owner authorization and quota/cost gates
  pass. There is no automatic charge/billing guard in the module.

## Default network topology

\`\`\`text
Public IP (ONLY AFTER AUTHORISATION)
    | OCI security list for HIGH ports (2222,2323,2121,13306)
    v
  HAProxy [proxy_front bridge, no privileged access]
    | [sensor_core: internal=true, no external route]
    +-- Cowrie SSH/Telnet [TTY evidence volume]
    +-- OpenCanary FTP/MySQL
    |
    X no public/production DB/VPN/Voice access
\`\`\`

The \`compose.public-staged.yaml\` has **loopback-only** published ports
by default, even if started on the dedicated VM.
Actual internet exposure requires changing \`HONEY_PUBLIC_BIND_IP\` to an
approved public interface (or 0.0.0.0) **only after**:
1. OCI network ingress list includes ONLY approved decoy high ports, with
   admin SSH limited to one trusted /32 (or use separately configured Bastion).
2. Host \`DOCKER-USER\` firewall fails closed for NEW egress from the
   \`proxy_front\` bridge; host IPv6 and OCI egress policies are also verified.
3. A real throwaway-client connection validates inbound port access and
   a separate outbound attempt validates no forwarding/pivot possible.
4. Minimum privileges, image digests/ARM64 manifests, encrypted evidence,
   storage quota, retention and emergency stop have been reviewed.
5. \`HONEY_SENSOR_INGEST_ENABLED\` remains OFF until actual Worker→TiDB
   written rows are proven and a separate trusted signing key exists.

The gateway forwards TCP bytes only and is not a proxy for arbitrary outbound
connections. Its bridge still has potential outbound connectivity unless the
host firewall and independent tests block it. An OCI security list allowing
HTTPS for package downloads is NOT sufficient container isolation.

## Safety / control plane

An immutable or restricted cloud operator account should provision the VM.
Do not give the honeypot containers cloud instance credentials, TiDB
administrator credentials, API tokens or unrestricted network access.
Use a separate trusted log forwarder and signed, bounded event summaries;
never forward real passwords, raw IPs or suspicious binaries to TiDB.

On any unexplained egress, cost increase, missing log provenance, sample
execution, or unexpected access to a private network: STOP public listeners
and retain the minimal evidence required for incident review.

## End-to-end production acceptance (not yet passed)

- [ ] Actual Worker→TiDB INSERT query shows a NEW \`cloudflare_worker\` row.
- [ ] Separate signed protocol intake shows NEW \`cowrie\`/\`opencanary\` rows.
- [ ] Dedicated VM deployed under a verified RM0/US$0 free allocation.
- [ ] Internet client can connect to the four decoy ports while host
      DOCKER-USER + OCI filtering block new outbound container connections.
- [ ] Cowrie's actual TTY is replayed, hashed, access restricted.
- [ ] Actual artifact hash proves chain of custody; no binary executes.
- [ ] TiDB data retention, DDL migration and secure read permissions approved.
- [ ] Real reviewer identities approve STIX and MISP compatibility tests.
- [ ] Actual shared indicators have valid TLP, recipient and export audit.

No Vercel change, no billing tier upgrade, no secrets committed and no
production TiDB schema modification is authorized by these files.

## Read-only verification of a newly deployed VM

- Consult \`cloud/oci/main.tf\`, \`variables.tf\` and \`host-egress-gate.sh\`.
- Before any public binding use the loopback default in
  \`compose.public-staged.yaml\` and verify HAProxy → Cowrie/OpenCanary
  protocol handshakes on the dedicated VM.
- All later image updates require a reviewed digest, not mutable \`latest\`.
