#!/usr/bin/env python3
"""Validate Worker configuration without trying to seize pre-existing routes.

Route ownership is intentionally managed by Cloudflare Dashboard. Error 10020
was caused by redeclaring already-owned patterns at Wrangler deploy time.
"""
from pathlib import Path
import sys
import tomllib
import json

ROOTS = (
    "vynalthai.com",
    "vyncuslim.com",
    "sleepsomno.com",
    "powiismunc.com",
    "vitamindai.online",
    "vynalthai.si",
    "vyncuslim.si",
)
# Operator-specified eight route patterns. Only vynalthai.com apex was
# requested; do not silently claim or replace other six apex routes.
EXPECTED = {
    ("*.sleepsomno.com/*", "sleepsomno.com"),
    ("*.vyncuslim.com/*", "vyncuslim.com"),
    ("*.vynalthai.com/*", "vynalthai.com"),
    ("*.vynalthai.si/*", "vynalthai.si"),
    ("*.powiismunc.com/*", "powiismunc.com"),
    ("*.vyncuslim.si/*", "vyncuslim.si"),
    ("vynalthai.com/*", "vynalthai.com"),
    ("*.vitamindai.online/*", "vitamindai.online"),
}

def check(path: Path) -> None:
    config = tomllib.loads(path.read_text(encoding="utf-8"))
    assert config.get("name") == "vynalth-cloudflare-edge", "Wrong Worker name"
    entry = config.get("main")
    if entry == "src/worker-entry.js":
        # The only authorized wrapper delegates unchanged HTTP routing to
        # src/index.js and separately exports the review-only DO class.
        wrapper = (path.parent / "src/worker-entry.js").read_text(
            encoding="utf-8")
        assert 'export { default } from "./index.js";' in wrapper, (
            "Wrangler wrapper must preserve exact main HTTP Worker handler"
        )
        assert 'export { SensorReplayLedger } from "./sensor-replay-ledger.js";' in wrapper, (
            "Dedicated SQLite replay ledger class export missing"
        )
        assert config.get("vars", {}).get("HONEY_SENSOR_V2_ENABLED") == "false", (
            "V2 sensor intake must remain disabled without a release gate"
        )
        assert config.get("vars", {}).get("HONEY_SENSOR_V2_SAMPLE_RATE") == "0.1", (
            "Do not increase TiDB sampling rate"
        )
        assert any(x.get("name") == "SENSOR_REPLAY_LEDGER"
                   and x.get("class_name") == "SensorReplayLedger"
                   for x in config.get("durable_objects", {}).get("bindings", [])), (
            "Missing private replay-ledger Durable Object binding"
        )
        assert any("SensorReplayLedger" in x.get("new_sqlite_classes", [])
                   for x in config.get("migrations", [])), (
            "Replay ledger MUST use SQLite-backed Durable Object migration"
        )
    else:
        assert entry == "src/index.js", "Worker entrypoint changed unexpectedly"
    # Keep this deployment route-free: never auto-create/delete a route.
    assert "routes" not in config and "route" not in config, (
        "Wrangler must not redeclare Cloudflare Dashboard-owned routes (10020)"
    )
    assert config.get("workers_dev") is True, (
        "Preserve the previously published workers.dev endpoint"
    )
    assert isinstance(config.get("vars"), dict), "[vars] section missing"
    assert "routes" not in config["vars"], "Never nest route declarations in [vars]"
    for flag in (
        "CONSENT_CMP_ENABLED",
        "SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED",
        "JINGXIN_PRIVATE_MEDIA_ENABLED",
    ):
        assert config["vars"].get(flag) == "false", (
            f"Safety switch must remain disabled in this routing-only change: {flag}"
        )
    assert config["vars"].get("GPS_GATE_ENABLED") == "true", "GPS must be explicitly enabled"
    assert config["vars"].get("GPS_POLYGON_MODE") == "enforce", "Polygon enforce is required"
    assert config["vars"].get("GPS_POLYGON_ENFORCEMENT_APPROVED") == "true", "Release authorization required"
    assert config["vars"].get("GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED") == "true", "OSM release authorization required"
    assert config["vars"].get("GPS_BOUNDARY_BUFFER_METERS") == "30", "30 m safeguard required"
    assert config["vars"].get("GPS_CONFIG_ERROR_ACTION") == "closed", "GPS must never bypass access on config failure"
    geodata = json.loads(config["vars"].get("GPS_CAMPUS_POLYGONS_JSON", "null"))
    assert geodata.get("type") == "FeatureCollection", "Expected GeoJSON FeatureCollection"
    shapes = geodata.get("features", [])
    assert len(shapes) == 2, "Exactly two schools must be declared"
    assert {x["properties"]["campus_id"] for x in shapes} == {
        "powiis-balik-pulau", "powiis-tanjung-bungah"
    }, "Unexpected school IDs"
    assert all(x["properties"].get("boundary_classification") == "OSM_MAPPED"
               and x["properties"].get("official_boundary_verified") is False for x in shapes), (
        "OSM is research/candidate data and cannot be labelled certified"
    )
    services = config.get("services") or []
    assert any(s.get("binding") == "SCHOOL_POLICY"
               and s.get("service") == "website-block-by-school-powiis"
               for s in services), "School policy service binding must remain unchanged"
    print("PASS: Wrangler will not re-register Cloudflare Dashboard-owned routes")
    print("REVIEW: Expected historical route inventory (must be audited in dashboard):")
    for pattern, zone in sorted(EXPECTED):
        print(f"  {pattern}  zone={zone}")

if __name__ == "__main__":
    try:
        check(Path(sys.argv[1] if len(sys.argv) > 1 else "wrangler.toml"))
    except (AssertionError, OSError, ValueError, KeyError) as error:
        sys.exit(f"FAIL: {error}")
