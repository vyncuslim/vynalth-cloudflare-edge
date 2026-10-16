import test from "node:test";
import assert from "node:assert/strict";
import { parseCampusPolygons, decideCampusPolygons, MAX_GPS_ACCURACY_METERS } from "../src/gps-polygons.js";
import { guestGpsGate } from "../src/guest-gps.js";

// Synthetic campus geometry, not a statement about official campus boundaries.
const sample = {
  type: "FeatureCollection",
  features: [{
    type: "Feature",
    properties: {
      campus_id: "powiis-tanjung-bungah",
      boundary_classification: "OSM_MAPPED",
      official_boundary_verified: false
    },
    geometry: {
      type: "Polygon",
      coordinates: [[[100.28, 5.46], [100.282, 5.46], [100.282, 5.462],
                     [100.28, 5.462], [100.28, 5.46]]]
    }
  }]
};
const env = {
  GPS_GATE_ENABLED: "true",
  GPS_GATE_SESSION_SECRET: "test-only-not-a-real-secret-value-123456789abcdef",
  GPS_POLYGON_MODE: "enforce",
  GPS_POLYGON_ENFORCEMENT_APPROVED: "true",
  GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED: "true",
  GPS_CAMPUS_POLYGONS_JSON: JSON.stringify(sample),
  GPS_BOUNDARY_BUFFER_METERS: "30"
};
function verifyRequest(lat,lon,accuracy) {
  const url = "https://vynalthai.com/__shield/gps/verify";
  const request = new Request(url, {
    method: "POST",
    headers: {"Origin": "https://vynalthai.com", "Sec-Fetch-Site": "same-origin",
              "Content-Type": "application/json"},
    body: JSON.stringify({lat,lon,accuracy})
  });
  return guestGpsGate(request, env, new URL(url));
}
test("A coarse fix well outside campus can pass conservatively", async () => {
  const response = await verifyRequest(5.38, 100.33, 1500);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).classification, "outside");
});
test("A coarse fix that overlaps campus uncertainty is blocked, not given near-boundary access", async () => {
  const response = await verifyRequest(5.461, 100.286, 1500);
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "LOCATION_UNCERTAIN");
  assert.equal(response.headers.get("set-cookie"), null);
});
test("A reported point inside the campus is never authorized with coarse accuracy", async () => {
  const response = await verifyRequest(5.461, 100.281, 1500);
  assert.equal(response.status, 403);
  assert.equal((await response.json()).error, "CAMPUS_BOUNDARY_UNCERTAIN");
});
test("An unbounded inaccurate position is still rejected", async () => {
  const response = await verifyRequest(5.38, 100.33, MAX_GPS_ACCURACY_METERS + 1);
  assert.equal(response.status, 422);
  assert.equal((await response.json()).error, "PRECISE_LOCATION_UNAVAILABLE");
});
test("Polygon classifier measures the uncertainty envelope rather than using a 100m cutoff", () => {
  const polys = parseCampusPolygons(JSON.stringify(sample));
  assert.ok(polys);
  assert.equal(decideCampusPolygons(polys,5.38,100.33,1500,30),"OUTSIDE");
  assert.equal(decideCampusPolygons(polys,5.461,100.286,1500,30),"UNCERTAIN");
  assert.equal(decideCampusPolygons(polys,5.461,100.281,1500,30),"INSIDE_UNCERTAIN");
  assert.equal(decideCampusPolygons(polys,5.38,100.33,MAX_GPS_ACCURACY_METERS+1,30),"INVALID");
});
