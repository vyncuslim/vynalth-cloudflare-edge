import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseCampusPolygons,decideCampusPolygons } from "./gps-polygons.js";

const fixture=readFileSync(new URL("../test/fixtures/powiis-osm-candidates.RESEARCH_ONLY.geojson",import.meta.url),"utf8");
const raw=JSON.parse(fixture);
const parsed=parseCampusPolygons(fixture);
const sample=(p)=>JSON.stringify(p);
const shape=(polys,type="Polygon",campus="school-1",official=false)=>({
 type:"FeatureCollection",features:[{type:"Feature",
 properties:{campus_id:campus,official_boundary_verified:official},
 geometry:{type,coordinates:polys}}]
});
const sq=(a,b,span=0.003)=>[[a,b],[a+span,b],[a+span,b+span],[a,b+span],[a,b]];
test("OSM candidate features are well-formed and remain explicitly uncertified",()=>{
 assert.ok(parsed);
 assert.equal(parsed.length,2);
 assert.deepEqual(parsed.map(x=>x.id),["powiis-balik-pulau","powiis-tanjung-bungah"]);
 assert.ok(parsed.every(x=>x.officialBoundaryVerified===false));
 assert.ok(raw.features.every(x=>x.properties.official_boundary_verified===false));
});
test("two real OSM candidate interior centroids are classified INSIDE in research calculations",()=>{
 assert.equal(decideCampusPolygons(parsed,5.367711,100.219932,5),"INSIDE");
 assert.equal(decideCampusPolygons(parsed,5.461141,100.284225,5),"INSIDE");
 assert.equal(decideCampusPolygons(parsed,5.40,100.25,5),"OUTSIDE");
});
test("exact polygon vertices, edge midpoints and uncertainty bands are UNCERTAIN",()=>{
 for(const feature of raw.features){
  const r=feature.geometry.coordinates[0];
  const vertex=r[0];
  const mid=[(r[0][0]+r[1][0])/2,(r[0][1]+r[1][1])/2];
  assert.equal(decideCampusPolygons(parsed,vertex[1],vertex[0],1),"UNCERTAIN");
  assert.equal(decideCampusPolygons(parsed,mid[1],mid[0],1),"UNCERTAIN");
 }
});
test("polygon shape validation rejects malformed, self-intersecting, duplicated or out-of-range geometry",()=>{
 const outer=sq(100.22,5.36);
 const cases=[
  "{broken", "[]", "", "x".repeat(65537),
  sample({type:"FeatureCollection",features:[]}),
  sample(shape([[outer.slice(0,-1)]])),
  sample(shape([[[100.22,5.36],[100.223,5.363],[100.223,5.36],[100.22,5.363],[100.22,5.36]]])),
  sample(shape([[[100.22,5.36],[100.223,5.36],[100.223,5.36],[100.22,5.363],[100.22,5.36]]])),
  sample(shape([[[100.22,5.36],[100.223,5.36],[100.223,95],[100.22,5.363],[100.22,5.36]]])),
  sample(shape([[[100.22,5.36],[100.223,5.36],[100.223,5.36]]])),
  sample(shape([outer,sq(100.3,5.36,.002)])),
  sample({type:"FeatureCollection",features:[shape([outer]).features[0],shape([outer]).features[0]]})
 ];
 for(const bad of cases)assert.equal(parseCampusPolygons(bad),null,bad.slice(0,100));
});
test("hole and MultiPolygon semantics preserve OUTSIDE in holes and UNCERTAIN near rings",()=>{
 const outer=sq(100.22,5.36,.006),hole=sq(100.222,5.362,.002);
 const multi=[ [outer,hole], [sq(100.232,5.36,.004)] ];
 const v=parseCampusPolygons(sample(shape(multi,"MultiPolygon")));
 assert.ok(v);
 assert.equal(decideCampusPolygons(v,5.361,100.221,2),"INSIDE");
 assert.equal(decideCampusPolygons(v,5.363,100.223,2),"OUTSIDE");
 assert.equal(decideCampusPolygons(v,5.361,100.233,2),"INSIDE");
 assert.equal(decideCampusPolygons(v,5.362,100.223,2),"UNCERTAIN");
 assert.equal(decideCampusPolygons(v,5.37,100.25,2),"OUTSIDE");
});
test("GPS spoofed nonsense, malformed accuracy and absent polygons never assert OUTSIDE",()=>{
 for(const [lat,lon,acc] of [[1000,100,10],[5,200,10],[5,100,NaN],[5,100,0],[5,100,101],[null,100,10]]){
  assert.equal(decideCampusPolygons(parsed,lat,lon,acc),"INVALID");
 }
 assert.equal(decideCampusPolygons(null,5.4,100.25,5),"INVALID");
});
test("ring crossing, overlapping holes, nested multipolygon and wrong identifiers are rejected",()=>{
 const outer=sq(100.22,5.36,.01);
 for(const bad of [
  shape([outer,sq(100.229,5.362,.004)]),
  shape([outer,sq(100.222,5.362,.004),sq(100.223,5.363,.002)]),
  shape([[outer],[sq(100.223,5.363,.002)]],"MultiPolygon"),
  shape([outer],"Polygon","BAD ID")
 ])assert.equal(parseCampusPolygons(sample(bad)),null);
});


test("30m edge buffer covers location accuracy without rejecting clearly outside users",()=>{
 assert.equal(decideCampusPolygons(parsed,5.367711,100.219932,5,30),"INSIDE");
 const vertex=raw.features[0].geometry.coordinates[0][0];
 assert.equal(decideCampusPolygons(parsed,vertex[1],vertex[0],5,30),"UNCERTAIN");
 assert.equal(decideCampusPolygons(parsed,5.4,100.25,5,30),"OUTSIDE");
 assert.equal(decideCampusPolygons(parsed,5.4,100.25,5,101),"INVALID");
});
