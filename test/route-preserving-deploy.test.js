import test from 'node:test';
import assert from 'node:assert/strict';
import {
  releaseTag,releaseCommands,commitShaFromEnvOrGit,deployPreservingRoutes
} from '../scripts/deploy-preserve-routes.mjs';

const sha='ca10bc0978d0bf39c58efe5b41ddab4e6ae8189b';

test('release tag is deterministic and rejects ambiguous revision IDs',()=>{
 assert.equal(releaseTag(sha),'git-ca10bc0978d0bf39');
 for(const invalid of ['', 'ca10bc0','cafebabe','../'+sha,'f'.repeat(41)]) {
  assert.throws(()=>releaseTag(invalid),/40-character/);
 }
});

test('uploaded version is pinned, route synchronization is never invoked',()=>{
 const plan=releaseCommands(sha);
 assert.equal(plan.length,2);
 assert.deepEqual(plan.map(x=>x.args.slice(0,2)),[
  ['versions','upload'],['versions','deploy']]);
 assert.ok(plan[0].args.includes('--keep-vars'));
 assert.ok(plan[0].args.includes('git-ca10bc0978d0bf39'));
 assert.deepEqual(plan[1].args.slice(2,4),['--version-tag','git-ca10bc0978d0bf39']);
 assert.ok(plan[1].args.includes('100'));
 assert.ok(!plan.some(x=>x.args.includes('triggers')||x.args[0]==='deploy'));
});

test('explicit full SHA is resolved from recognized build environments',()=>{
 assert.equal(commitShaFromEnvOrGit({CF_PAGES_COMMIT_SHA:sha}),sha);
 assert.equal(commitShaFromEnvOrGit({GITHUB_SHA:sha}),sha);
 assert.throws(()=>commitShaFromEnvOrGit({CF_PAGES_COMMIT_SHA:'cafebabe'}),/40-character/);
});

test('two-stage deployment stops when version upload fails',async()=>{
 const calls=[];
 await assert.rejects(deployPreservingRoutes({
  env:{GITHUB_SHA:sha},
  invoke:async args=>{calls.push(args);throw new Error('upload blocked')}
 }),/upload blocked/);
 assert.equal(calls.length,1);
 assert.deepEqual(calls[0].slice(0,2),['versions','upload']);
});

test('successful promotion only touches version APIs',async()=>{
 const calls=[];
 await deployPreservingRoutes({
  env:{GITHUB_SHA:sha},
  invoke:async args=>calls.push(args)
 });
 assert.equal(calls.length,2);
 assert.deepEqual(calls.map(args=>args.slice(0,2)),[
  ['versions','upload'],['versions','deploy']]);
});
