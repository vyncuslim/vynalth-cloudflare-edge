#!/usr/bin/env bash
# DEDICATED DISPOSABLE VM ONLY. Never run on production VPN/Voice servers.
# Requires operator review. Does not enable public ingress.
set -euo pipefail
mode="${1:-check}"
if [[ "$mode" != "check" && "$mode" != "install" ]]; then
  echo 'Usage: host-egress-gate.sh check|install' >&2
  exit 2
fi
project="vynalth-dedicated-sensor"
network="${project}_proxy_front"
for tool in docker iptables ip; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 3; }
done
[[ "$(id -u)" -eq 0 ]] || { echo 'requires host root' >&2; exit 3; }
docker network inspect "$network" >/dev/null 2>&1 || {
  echo 'Docker proxy front network unavailable; keep public binds OFF' >&2; exit 4;
}
id="$(docker network inspect -f '{{.Id}}' "$network")"
[[ "$id" =~ ^[0-9a-f]{64}$ ]] || { echo 'unexpected network identifier' >&2; exit 4; }
bridge="br-${id:0:12}"
ip link show dev "$bridge" >/dev/null 2>&1 || {
  echo 'unverified Docker bridge' >&2; exit 4;
}
iptables -nL DOCKER-USER >/dev/null 2>&1 || {
  echo 'DOCKER-USER chain unavailable; do not publish ports' >&2; exit 4;
}
# With the nftables-only Docker firewall backend, this refuses to pass
# until an equivalent reviewed nftables policy is explicitly configured.
rule=( -i "$bridge" -m conntrack --ctstate NEW -j DROP )
if [[ "$mode" == "install" ]]; then
  if ! iptables -C DOCKER-USER "${rule[@]}" >/dev/null 2>&1; then
    iptables -I DOCKER-USER 1 "${rule[@]}"
  fi
fi
if ! iptables -C DOCKER-USER "${rule[@]}" >/dev/null 2>&1; then
  echo 'Proxy egress deny rule missing; public ingress remains NOT APPROVED' >&2
  exit 5
fi
echo 'PASS: proxy front NEW forwarded egress is blocked by host firewall.'
echo 'Still required: real outbound test, IPv6/OCI firewall and disk-quota checks.'
