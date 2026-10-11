# GPS polygon research integration — POWIIS (2026-10-11)

**Scope:** Draft PR #10 only. Do not merge or deploy until separately authorized. All five production gates, especially `GPS_GATE_ENABLED="false"`, stay disabled.

## Evidence

Two OSM-sourced, user-supplied candidate campus ways were validated as closed school-area polygons, but **neither has an authenticated Pelan Akui, NDCDB parcel extract, survey or title/lot association**.

| Campus | OSM Way | Reference geometry | Authenticated land boundary |
|---|---|---|---|
| Balik Pulau | [808258869](https://www.openstreetmap.org/way/808258869) | Research-only Polygon | **No** |
| Tanjung Bungah | [790940312](https://www.openstreetmap.org/way/790940312) | Research-only Polygon | **No** |

Reference data in `test/fixtures/powiis-osm-candidates.RESEARCH_ONLY.geojson` has `official_boundary_verified=false` for both entries. OSM attribution: © OpenStreetMap contributors, [ODbL 1.0](https://www.openstreetmap.org/copyright). Polygon coordinates are the uploaded candidate dataset; this PR does not assert an independent latest OSM server version or legal accuracy. **Never place that fixture into production environment variables.**

## New code

- `src/gps-polygons.js`: strict GeoJSON `FeatureCollection` validator accepting `Polygon` / `MultiPolygon` including holes, disjoint parts, finite WGS84 `[lon,lat]` vertices, unique school IDs, closure, no self-intersections, hole containment; limits 1–8 campuses, 4,096 vertices and 64 KiB JSON.
- `decideCampusPolygons()`: `INSIDE` / `OUTSIDE` / `UNCERTAIN` / `INVALID`, local equirectangular metric distance to all boundaries, uncertainty margin from browser-provided `accuracy` (0 < accuracy <= 100 m). This cannot prove a user's physical location, as the browser report can be spoofed.
- `src/guest-gps.js`: integrates shadow and opt-in enforcement selection while preserving existing legacy circles, GPS handoff, HMAC cookies, trusted status exemptions, same-origin check, JSON size limit, privacy behavior, and 900-second TTL.

### Runtime variables

- `GPS_POLYGON_MODE` **Text**, optional: `off` (default), `shadow`, `enforce`.
- `GPS_CAMPUS_POLYGONS_JSON` **Text**, optional; only read when mode is `shadow` or `enforce`. A GeoJSON FeatureCollection of `features[].properties.campus_id` and `features[].geometry`. This is **NOT** compatible with legacy `GPS_CAMPUS_GEOFENCES_JSON`, which continues to be a JSON array of `{id,lat,lon,radius}` circle definitions.
- `GPS_POLYGON_ENFORCEMENT_APPROVED` **Text**, optional: must explicitly be `"true"` to allow `enforce` along with `official_boundary_verified===true` for **every** campus geometry. These are configuration interlocks, **not cryptographic evidence of survey authority**. A genuine authenticated survey and written human release decision are still required.
- `GPS_GATE_ENABLED` remains `"false"` in production; if disabled, **none** of the polygon or circle geofencing evaluates incoming requests.
- `GPS_GATE_SESSION_SECRET` existing HMAC secret, unchanged. Other secrets, SSO, KV, R2, routes and DNS **not altered**.

**Safety:** OSM features marked `official_boundary_verified=false` cannot be hard-enforced even if `GPS_POLYGON_MODE=enforce` and approval flag is true. Misconfigured mode, absent secret or malformed active geometry returns 503 `GPS_GATE_CONFIGURATION_UNAVAILABLE` for non-exempt requests if GPS gate is enabled; the service must not silently treat errors as `OUTSIDE`. Verified exemptions and exempt paths follow existing handling.

### Shadow semantics

Shadow mode parses and evaluates polygon distance/accuracy but **does not send the shadow verdict to the browser, issue a polygon-based cookie, persist coordinates or decisions, log them, or change the legacy circle outcome**. To evaluate in staging, provide isolated preview bindings and synthetic authorized test requests, and keep the original production gate disabled. Polygon enforcement is testable with synthetic `official_boundary_verified=true` fixtures in CI, but this must not be interpreted as authority to enable production access blocking.

## Release criteria / open issues

1. Secure true cadastral boundary from JUPEM Pelan Akui/NDCDB or licensed surveyor for both campuses, and validate the CRS conversion to WGS84.
2. Review polygon offsets against entrances, roads, school land, and any surrounding businesses; conduct privacy/minor/user-access impact review.
3. Review caller-supplied browser location spoofing risks and clear UNCERTAIN handling; verify all seven zone routes and `vv` worker ownership independently.
4. Create isolated staging environment; verify that no GPS coordinates enter Cloudflare/Axiom/Telegram analytics.
5. Obtain explicit deployment and enforcement authorization; until then production stays **OFF** and Draft PR remains unmerged.

## Local test

`npm test` (uses Node built-in test runner). Test modules: `src/gps-polygons.test.js` and `src/guest-gps.test.js`, plus existing Consent/Edge suite.

## Operator-requested GPS proximity policy (review addition)

As of October 11, 2026, the operator accepts a **30 m engineering buffer** beyond browser-reported GPS accuracy around provisional mapped perimeters. This buffer is NOT official survey uncertainty and can miss unrecorded school parcels, overlap roads, or be evaded by spoofed GPS.

For polygon enforcement, distances to external and internal polygon-ring segments within `accuracy + GPS_BOUNDARY_BUFFER_METERS` become `UNCERTAIN`. An uncertain **valid and volunteered** GPS location is **not** declared OUTSIDE; instead the browser receives a distinct short-lived HMAC-signed `nearby` access token (300 seconds), bound to that first-party hostname. This avoids mistakenly treating nearby road users as confirmed INSIDE. The `nearby` verdict is preserved across signed cross-domain handoff rather than upgraded to `outside`. Clearly INSIDE still returns 403 and a temporary blocked Cookie; clearly OUTSIDE receives 15-minute permission.

If a visitor **does not grant GPS permission**, no signed permission is created and normal protected HTML/assets/APIs remain behind the GPS 403 verification/error page. The page supports retry. Independently authenticated trust/contact/status, auth recovery, status, contact and privacy/legal resources remain accessible under the existing explicit exceptions. Browser GPS can still be spoofed and should not be considered identification.

Additional opt-in approval `GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED=true` allows ONLY two named POWIIS polygons with `boundary_classification=OSM_MAPPED` in addition to `GPS_POLYGON_ENFORCEMENT_APPROVED=true`; this **does not change `official_boundary_verified=false`**. All release approvals default OFF. A signed `GPS_GATE_SESSION_SECRET`, valid `GPS_CAMPUS_POLYGONS_JSON`, `GPS_GATE_ENABLED=true`, and `GPS_POLYGON_MODE=enforce` are required before the gate can function. Configure these secrets only in authorized Cloudflare environments.

`GPS_CONFIG_ERROR_ACTION=bypass` is an EXPLICIT availability-oriented recovery policy: invalid GPS config stops returning a site-wide 503, emits a config error, and allows origin traffic without issuing any geofence verdict or claiming OUTSIDE. Unlike a valid denied-location check, this bypass means **GPS access controls are temporarily OFF**. It must be monitored using `/__shield/gps/status` and Cloudflare alarms. Remove the bypass value for strict 503 fail-closed. Other WAF/auth policies remain independent. A site operator must decide the availability/security tradeoff and confirm a fast rollback path.

**Not a production activation**: this PR stays Draft; `GPS_GATE_ENABLED=false`, `GPS_POLYGON_MODE=off`, and both approval flags false. Cloudflare production secrets/config, route ownership, end-to-end privacy audit, real browser permission-denied tests and authorization must be verified separately before merge/deploy.