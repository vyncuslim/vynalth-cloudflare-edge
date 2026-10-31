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
    assert config.get("main") == "src/index.js", "Worker entrypoint changed"
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
