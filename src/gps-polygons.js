/**
 * GPS polygon geometry for research/shadow verification and future
 * separately-approved authoritative geofences.
 * GeoJSON uses WGS84 [longitude, latitude]. No external APIs or storage.
 */
const R=6371008.8;
const RAD=Math.PI/180;
const MAX_BYTES=65536;
const MAX_POINTS=4096;
const EPS=1e-7;
// Maximum uncertainty accepted for a conservative outside-of-campus decision.
// Large uncertainties near a campus must be rejected at the HTTP policy layer.
export const MAX_GPS_ACCURACY_METERS=10000;
const validId=s=>typeof s==="string"&&/^[a-z0-9-]{2,48}$/.test(s);
const validPoint=p=>Array.isArray(p)&&p.length===2&&p.every(Number.isFinite)&&
 Math.abs(p[0])<=180&&Math.abs(p[1])<=90;
const same=(a,b)=>a[0]===b[0]&&a[1]===b[1];
function projection(p,lat0){
 return [p[0]*RAD*R*Math.cos(lat0*RAD),p[1]*RAD*R];
}
function cross(a,b,c){return (b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]);}
function onSegment(p,a,b){
 if(Math.abs(cross(a,b,p))>EPS)return false;
 return p[0]>=Math.min(a[0],b[0])-EPS&&p[0]<=Math.max(a[0],b[0])+EPS&&
 p[1]>=Math.min(a[1],b[1])-EPS&&p[1]<=Math.max(a[1],b[1])+EPS;
}
function segmentsIntersect(a,b,c,d){
 const ab1=cross(a,b,c),ab2=cross(a,b,d),cd1=cross(c,d,a),cd2=cross(c,d,b);
 if((ab1>EPS&&ab2< -EPS||ab1< -EPS&&ab2>EPS)&&
    (cd1>EPS&&cd2< -EPS||cd1< -EPS&&cd2>EPS))return true;
 return onSegment(c,a,b)||onSegment(d,a,b)||onSegment(a,c,d)||onSegment(b,c,d);
}
function intersectsRings(a,b){
 for(let i=0;i<a.length-1;i++)for(let j=0;j<b.length-1;j++)
  if(segmentsIntersect(a[i],a[i+1],b[j],b[j+1]))return true;
 return false;
}
function ringValid(ring,lat0,budget){
 if(!Array.isArray(ring)||ring.length<4||ring.length>MAX_POINTS+1||
    !ring.every(validPoint)||!same(ring[0],ring[ring.length-1]))return null;
 budget.count+=ring.length-1;
 if(budget.count>MAX_POINTS)return null;
 const points=ring.map(p=>projection(p,lat0));
 const unique=new Set(ring.slice(0,-1).map(p=>JSON.stringify(p)));
 if(unique.size!==ring.length-1)return null;
 const lons=ring.map(p=>p[0]),lats=ring.map(p=>p[1]);
 // School-scale polygons, not world-spanning or dateline-crossing shapes.
 if(Math.max(...lons)-Math.min(...lons)>0.1||
    Math.max(...lats)-Math.min(...lats)>0.1)return null;
 let area=0;
 for(let i=0;i<points.length-1;i++)
  area+=points[i][0]*points[i+1][1]-points[i+1][0]*points[i][1];
 if(!Number.isFinite(area)||Math.abs(area)<2)return null;
 for(let i=0;i<points.length-1;i++)for(let j=i+1;j<points.length-1;j++){
  if(j===i+1||(i===0&&j===points.length-2))continue;
  if(segmentsIntersect(points[i],points[i+1],points[j],points[j+1]))return null;
 }
 return points;
}
function pointInRing(p,ring){
 let inside=false;
 for(let i=0,j=ring.length-2;i<ring.length-1;j=i++){
  const a=ring[i],b=ring[j];
  if(onSegment(p,a,b))return true;
  if((a[1]>p[1])!==(b[1]>p[1])&&
     p[0]<(b[0]-a[0])*(p[1]-a[1])/(b[1]-a[1])+a[0])inside=!inside;
 }
 return inside;
}
function polygonValid(rings,lat0,budget){
 if(!Array.isArray(rings)||rings.length<1||rings.length>32)return null;
 const projected=[];
 for(const ring of rings){
  const p=ringValid(ring,lat0,budget);
  if(!p)return null;
  projected.push(p);
 }
 for(let i=1;i<projected.length;i++){
  if(!pointInRing(projected[i][0],projected[0])||
     intersectsRings(projected[i],projected[0]))return null;
  for(let j=1;j<i;j++){
   if(intersectsRings(projected[i],projected[j])||
      pointInRing(projected[i][0],projected[j])||
      pointInRing(projected[j][0],projected[i]))return null;
  }
 }
 return projected;
}
export function parseCampusPolygons(raw){
 if(typeof raw!=="string"||raw.length>MAX_BYTES)return null;
 let json;try{json=JSON.parse(raw);}catch{return null;}
 if(!json||json.type!=="FeatureCollection"||!Array.isArray(json.features)||
    json.features.length<1||json.features.length>8)return null;
 const budget={count:0},ids=new Set(),campuses=[];
 for(const feature of json.features){
  const id=feature?.properties?.campus_id;
  const geometry=feature?.geometry;
  if(feature?.type!=="Feature"||!validId(id)||ids.has(id)||!geometry||
     !["Polygon","MultiPolygon"].includes(geometry.type))return null;
  const polys=geometry.type==="Polygon"?[geometry.coordinates]:geometry.coordinates;
  if(!Array.isArray(polys)||polys.length<1||polys.length>16)return null;
  const lat0=polys?.[0]?.[0]?.[0]?.[1];
  if(!Number.isFinite(lat0)||Math.abs(lat0)>90)return null;
  const projected=[];
  for(const polygon of polys){
   const rings=polygonValid(polygon,lat0,budget);
   if(!rings)return null;
   projected.push(rings);
  }
  // Disjoint MultiPolygon pieces must not intersect one another.
  for(let i=0;i<projected.length;i++)for(let j=i+1;j<projected.length;j++){
   if(intersectsRings(projected[i][0],projected[j][0])||
      pointInRing(projected[i][0][0],projected[j][0])||
      pointInRing(projected[j][0][0],projected[i][0]))return null;
  }
  ids.add(id);
  campuses.push({id,lat0,polygons:projected,
   officialBoundaryVerified:feature.properties.official_boundary_verified===true,
   boundaryClassification:feature.properties.boundary_classification??null});
 }
 return campuses;
}
function distanceToSegment(p,a,b){
 const dx=b[0]-a[0],dy=b[1]-a[1],l=dx*dx+dy*dy;
 if(l<EPS)return Math.hypot(p[0]-a[0],p[1]-a[1]);
 const t=Math.max(0,Math.min(1,((p[0]-a[0])*dx+(p[1]-a[1])*dy)/l));
 return Math.hypot(p[0]-(a[0]+t*dx),p[1]-(a[1]+t*dy));
}
/** Returns INSIDE, INSIDE_UNCERTAIN, OUTSIDE, UNCERTAIN, or INVALID. No location is stored. */
export function decideCampusPolygons(campuses,lat,lon,accuracy,bufferMeters=0){
 if(!Array.isArray(campuses)||campuses.length<1||
    ![lat,lon,accuracy].every(Number.isFinite)||Math.abs(lat)>90||
    Math.abs(lon)>180||accuracy<=0||accuracy>MAX_GPS_ACCURACY_METERS||
    !Number.isFinite(bufferMeters)||bufferMeters<0||bufferMeters>100)return "INVALID";
 let confidentInside=false,nearInside=false,nearOutside=false;
 for(const campus of campuses){
  const p=projection([lon,lat],campus.lat0);
  for(const rings of campus.polygons){
   let within=pointInRing(p,rings[0]);
   for(let i=1;i<rings.length;i++)if(pointInRing(p,rings[i]))within=false;
   let boundary=Infinity;
   for(const ring of rings)for(let i=0;i<ring.length-1;i++)
    boundary=Math.min(boundary,distanceToSegment(p,ring[i],ring[i+1]));
   const nearEdge=boundary<=accuracy+bufferMeters+EPS;
   // A reported point inside the mapped school must never gain a 200
   // "nearby" token merely because its accuracy overlaps the boundary.
   // It may be a false positive: return retryable 403, not permanent block.
   if(within&&nearEdge)nearInside=true;
   else if(within)confidentInside=true;
   else if(nearEdge)nearOutside=true;
  }
 }
 if(confidentInside)return "INSIDE";
 if(nearInside)return "INSIDE_UNCERTAIN";
 return nearOutside?"UNCERTAIN":"OUTSIDE";
}
