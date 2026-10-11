#!/usr/bin/env python3
"""Validate Vynalth's Cloudflare Worker routes with the TOML parser.

This deliberately parses TOML rather than grepping for route strings:
"routes" placed below [vars] is NOT a top-level Worker route definition.
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
    routes = config.get("routes")
    assert isinstance(routes, list), "Worker routes missing at TOML ROOT level"
    assert isinstance(config.get("vars"), dict), "[vars] section missing"
    assert "routes" not in config["vars"], "routes must NOT be nested inside [vars]"
    seen = []
    for r in routes:
        assert isinstance(r, dict), f"Invalid route item: {r!r}"
        assert isinstance(r.get("pattern"), str), f"Route pattern missing: {r!r}"
        assert isinstance(r.get("zone_name"), str), f"Zone name missing: {r!r}"
        seen.append((r["pattern"], r["zone_name"]))
    assert len(seen) == len(set(seen)), "Duplicate Cloudflare routes"
    assert len(seen) == 8, f"Expected 8 routes, found {len(seen)}"
    missing = EXPECTED - set(seen)
    unexpected = set(seen) - EXPECTED
    assert not missing and not unexpected, (
        f"Route mismatch, missing={sorted(missing)}, unexpected={sorted(unexpected)}"
    )
    for flag in (
        "CONSENT_CMP_ENABLED",
        "SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED",
        "JINGXIN_PRIVATE_MEDIA_ENABLED",
        "SCHOOL_EMAIL_GATE_ENABLED",
    ):
        assert config["vars"].get(flag) == "false", (
            f"Safety switch must remain disabled in this routing-only change: {flag}"
        )
    gps_enabled = config["vars"].get("GPS_GATE_ENABLED")
    assert gps_enabled in ("true", "false"), "GPS gate must be explicitly configured"
    if gps_enabled == "true":
        assert config["vars"].get("GPS_POLYGON_MODE") == "enforce", "Enabled GPS requires polygon enforcement"
        assert config["vars"].get("GPS_POLYGON_ENFORCEMENT_APPROVED") == "true", "GPS missing operator approval"
        assert config["vars"].get("GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED") == "true", "Provisional OSM approval missing"
        assert config["vars"].get("GPS_BOUNDARY_BUFFER_METERS") == "30", "Expected 30 metre safety buffer"
        assert config["vars"].get("GPS_CONFIG_ERROR_ACTION") == "bypass", "Prevent all-site outage during config failures"
        polygon_data = json.loads(config["vars"].get("GPS_CAMPUS_POLYGONS_JSON", "null"))
        assert polygon_data.get("type") == "FeatureCollection", "Expected GeoJSON FeatureCollection"
        features = polygon_data.get("features") or []
        ids = {f.get("properties", {}).get("campus_id") for f in features}
        assert ids == {"powiis-balik-pulau", "powiis-tanjung-bungah"}, "Only named campus candidates approved"
        assert len(features) == 2, "Expected exactly two campuses"
        assert all(f.get("properties", {}).get("official_boundary_verified") is False for f in features), (
            "Do not falsely certify OSM mapped candidate boundaries"
        )
        assert all(f.get("properties", {}).get("boundary_classification") == "OSM_MAPPED" for f in features), (
            "Must retain source classification"
        )
    services = config.get("services") or []
    assert any(s.get("binding") == "SCHOOL_POLICY"
               and s.get("service") == "website-block-by-school-powiis"
               for s in services), "School policy service binding must remain unchanged"
    print("PASS: 8 exact top-level routes across seven Cloudflare zones")
    for pattern, zone in sorted(EXPECTED):
        print(f"  {pattern}  zone={zone}")

if __name__ == "__main__":
    try:
        check(Path(sys.argv[1] if len(sys.argv) > 1 else "wrangler.toml"))
    except (AssertionError, OSError, ValueError, KeyError) as error:
        sys.exit(f"FAIL: {error}")
