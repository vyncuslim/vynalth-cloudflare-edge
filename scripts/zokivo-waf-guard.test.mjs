import test from 'node:test';
import assert from 'node:assert/strict';
import {proposeNatCounter,fingerprint} from './zokivo-waf-guard.mjs';
const make=()=>({id:'0123456789abcdef0123456789abcdef',version:'1',action:'block',enabled:true,
 expression:'(http.host eq "zokivo.vynalthai.com" and starts_with(http.request.uri.path, "/api/rooms/"))',
 ratelimit:{characteristics:['cf.colo.id','ip.src'],requests_per_period:50,period:10,mitigation_timeout:10},
 action_parameters:{response:{status_code:429,content_type:'application/json',content:'{"error":"Too many requests"}'}}});
test('converts only source-IP to NAT counter with unchanged thresholds and actions',()=>{
 const r=make(),p=proposeNatCounter(r);
 assert.deepEqual(p.patch.ratelimit.characteristics,['cf.colo.id','cf.unique_visitor_id']);
 assert.equal(p.patch.ratelimit.requests_per_period,50);
 assert.equal(p.patch.ratelimit.period,10);
 assert.equal(p.patch.ratelimit.mitigation_timeout,10);
 assert.equal(p.patch.expression,r.expression);
 assert.equal(p.patch.action,r.action);
 assert.deepEqual(p.patch.action_parameters,r.action_parameters);
 assert.equal(p.before,fingerprint(r));
 assert.equal(r.ratelimit.characteristics[1],'ip.src');
});
test('refuses zone-wide rule',()=>{const r=make();r.expression='(http.request.uri.path contains "/api")';assert.throws(()=>proposeNatCounter(r),/RULE_NOT_EXCLUSIVELY/)});
test('refuses unrelated hostname',()=>{const r=make();r.expression='(http.host eq "vynalthai.com")';assert.throws(()=>proposeNatCounter(r),/RULE_NOT_EXCLUSIVELY/)});
test('refuses OR multi-host rule',()=>{const r=make();r.expression='(http.host eq "zokivo.vynalthai.com" or http.host eq "vynalthai.com")';assert.throws(()=>proposeNatCounter(r),/RULE_NOT_EXCLUSIVELY/)});
test('refuses disabled rule',()=>{const r=make();r.enabled=false;assert.throws(()=>proposeNatCounter(r),/RULE_DISABLED/)});
test('refuses custom header counter',()=>{const r=make();r.ratelimit.characteristics.push('http.request.headers["x-player-token"]');assert.throws(()=>proposeNatCounter(r),/CUSTOM_COUNTER/)});
test('refuses IP referenced in counting expression',()=>{const r=make();r.ratelimit.counting_expression='ip.src.country eq "MY"';assert.throws(()=>proposeNatCounter(r),/COUNTING_EXPRESSION/)});
test('refuses when original IP counter absent',()=>{const r=make();r.ratelimit.characteristics=['cf.colo.id','cf.unique_visitor_id'];assert.throws(()=>proposeNatCounter(r),/EXPECTED_IP_BASED/)});
test('refuses skip action',()=>{const r=make();r.action='skip';assert.throws(()=>proposeNatCounter(r),/ONLY_BLOCK/)});
test('fingerprint changes with rate settings',()=>{const r=make(),f=fingerprint(r);r.ratelimit.requests_per_period=70;assert.notEqual(fingerprint(r),f)});
