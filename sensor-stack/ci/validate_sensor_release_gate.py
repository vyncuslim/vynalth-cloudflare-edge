#!/usr/bin/env python3
"""Static, credential-free release guard for isolated honeypot sensors.

Guards against accidental public exposure in staged source configs. It does
NOT prove actual OCI firewall, account quotas, egress or TiDB SQL readback.
No network calls or cloud mutations.
"""
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]


def require(condition, why):
    if not condition:
        raise AssertionError(why)


def audit():
    variables=(ROOT/"sensor-stack/cloud/oci/variables.tf").read_text()
    main=(ROOT/"sensor-stack/cloud/oci/main.tf").read_text()
    compose=(ROOT/"sensor-stack/cloud/compose.public-staged.yaml").read_text()
    firewall=(ROOT/"sensor-stack/cloud/host-egress-gate.sh").read_text()
    config=(ROOT/"wrangler.toml").read_text()
    for flag in ("launch_approved","public_decoys_approved"):
        require(bool(re.search(
            r'variable\s+"'+flag+r'"\s*\{[^}]*\bdefault\s*=\s*false',
            variables,re.S)),f"{flag} must default false")
    require("count          = var.launch_approved ? 1 : 0" in main,
            "OCI launch requires explicit approval")
    require("var.public_decoys_approved ? local.decoy_ports : []" in main,
            "public decoy ingress must be gated")
    require("oci_core_vcn" in main and "oci_core_subnet" in main,
            "dedicated network/subnet not declared")
    listener=chr(36)+"{HONEY_PUBLIC_BIND_IP:-127.0.0.1}"
    require(compose.count(listener)>=4,
            "four decoy listeners must default to loopback")
    require("sensor_core:" in compose and
            bool(re.search(r"sensor_core:\s*\n(?:[^\n]*\n){0,4}\s*internal:\s*true",compose)),
            "sensor backend not an internal bridge")
    require("DOCKER-USER" in firewall and "--ctstate NEW -j DROP" in firewall,
            "dedicated host NEW egress DROP rule absent")
    require('HONEY_SENSOR_V2_ENABLED = "false"' in config,
            "V2 Worker intake must remain disabled")
    require('HONEY_SENSOR_V2_SAMPLE_RATE = "0.1"' in config,
            "V2 TiDB sampling must remain 10 percent")
    require('HONEY_SENSOR_INGEST_ENABLED = "false"' in config,
            "legacy sensor endpoint must remain disabled")
    # Host bootstrap HTTPS/DNS egress remains allowed by OCI. Firewall gate
    # is only code, not installed. Live isolation is NEVER claimed here.
    return {
      "scope":"static_source_only",
      "default_oci_vm_launch_approved":False,
      "default_public_decoys_approved":False,
      "default_public_listeners_enabled":False,
      "private_sensor_backend_configured":True,
      "v2_ingest_enabled":False,
      "sampling_rate":0.1,
      "provider_account_usage_checked":False,
      "live_host_firewall_egress_tested":False,
      "ipv6_and_metadata_isolation_live_verified":False,
      "actual_prod_tidb_row_readback_verified":False,
      "internet_facing_honeypot_go":False,
      "limitations":[
        "OCI security list allows host HTTPS/DNS egress",
        "Docker host firewall script is not installed or observed",
        "IPv6 and metadata isolation have no live acceptance",
        "No dedicated public host, hosted DO staging or TiDB readback"
      ]
    }


if __name__=="__main__":
    try:
        print(json.dumps(audit(),sort_keys=True))
    except (AssertionError,OSError) as exc:
        print("RELEASE_GUARD_BLOCKED: "+str(exc)[:130],file=sys.stderr)
        raise SystemExit(2)
