import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { isPublicCyberCommandReadOnly } from './public-cyber-command.js';
const base = 'https://vynalthai.com';
const yes = (path, hostname='vynalthai.com',method='GET') => {
  const url=new URL(path, 'https://' + hostname);
  return isPublicCyberCommandReadOnly({method},url);
};

test('only public Cyber Command documents are exempt from the GPS prompt', () => {
  const sections=['','overview','live','threats','map','infrastructure','intel','ips','incidents','methodology'];
  for(const language of ['', 'en/', 'cn/', 'ms/']){
    for(const section of sections){
      const path='/' + language + 'cyber-command' + (section ? '/' + section : '');
      assert.equal(yes(path),true,path);
      assert.equal(yes(path+'/'),true,path+'/');
      assert.equal(yes(path, 'www.vynalthai.com'),true,path);
      assert.equal(yes(path, 'vynalthai.com','HEAD'),true,path);
    }
  }
});

test('only fixed public GET and HEAD consensus API is GPS exempt',()=>{
  const path='/api/public/cyber-command/ip-consensus';
  assert.equal(yes(path),true);
  assert.equal(yes(path,'vynalthai.com','HEAD'),true);
  for(const method of ['POST','PUT','DELETE','PATCH','OPTIONS']){
    assert.equal(yes(path,'vynalthai.com',method),false,method);
  }
  assert.equal(yes('/api/public/cyber-command/ip-consensus/private'),false);
});

test('do not exempt private routes, other domains, malformed paths, or methods',()=>{
  for(const path of [
    '/','/c','/en/c','/admin','/en/admin','/api/security/telemetry',
    '/en/cyber-command/ips/export','/cyber-command/private','/cn/cyber-command/admin',
    '/cn/cyber-command/ips/sensitive','/en/cyber-command-live','/cyber-command//map',
    '/cyber-command/%2e%2e/admin','/en/security','/login','/__shield/gps/verify',
  ])assert.equal(yes(path),false,path);
  for(const host of ['vynlink.xyz','zokivo.xyz','search.vynalthai.com','evil-vynalthai.com']){
    assert.equal(yes('/en/cyber-command',host),false,host);
  }
  for(const method of ['POST','PATCH','DELETE','OPTIONS']){
    assert.equal(yes('/en/cyber-command', 'vynalthai.com',method),false,method);
  }
});

test('the exception is located only at the GPS gate and other policies still execute',()=>{
  const src=readFileSync(new URL('./index.js',import.meta.url),'utf8');
  const marker=src.indexOf('const publicReadOnlyIntelligence = isPublicCyberCommandReadOnly(request,incomingUrl)');
  const gate=src.indexOf('const gpsDecision = await guestGpsGate(request,env,incomingUrl,ctx,requestId)');
  const block=src.indexOf('const temporaryDenial = temporaryIpBlockResponse(request,incomingUrl)');
  const federated=src.indexOf('const federatedDenial = await checkFederatedDeviceAccess(request, env, incomingUrl)');
  const school=src.indexOf('const denial = await checkSchoolPolicy(request, env, rootDomain, ctx)');
  assert.ok(block >= 0 && block < federated && federated < marker && marker < gate && gate < school);
  assert.ok(src.includes('&& !publicReadOnlyIntelligence'));
  assert.ok(src.includes('if (!isValidationPath(incomingUrl.pathname))'));
});
