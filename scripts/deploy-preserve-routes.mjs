// Deploy code without re-registering Cloudflare zone routes.
// Source: Cloudflare docs "Versions & deployments" - route triggers are managed
// separately with "wrangler triggers deploy".
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export function releaseTag(sha) {
  const full = String(sha || '').trim().toLowerCase();
  if (!/^[a-f0-9]{40}$/.test(full)) {
    throw new Error('A full 40-character Git commit SHA is required; refusing an ambiguous version release.');
  }
  return 'git-' + full.slice(0, 16);
}

export function releaseCommands(sha) {
  const tag = releaseTag(sha);
  const note = 'vynalth-cloudflare-edge ' + sha.slice(0, 12) + ' (retain existing routes)';
  return [
    {
      label: 'Upload Worker version without modifying routes',
      args: ['versions', 'upload', '--tag', tag, '--message', note, '--keep-vars'],
    },
    {
      label: 'Deploy the exact version tag to 100% of current Worker traffic',
      args: ['versions', 'deploy', '--version-tag', tag, '--percentage', '100',
        '--message', note, '--yes'],
    },
  ];
}

function runProcess(binary, args, options = {}) {
  const child = spawnSync(binary, args, { stdio: 'inherit', ...options });
  if (child.error) throw child.error;
  if (child.status !== 0) {
    throw new Error(binary + ' exited unsuccessfully (code ' + child.status + ')');
  }
}

export function commitShaFromEnvOrGit(env = process.env) {
  const supplied = String(env.CF_PAGES_COMMIT_SHA || env.GITHUB_SHA || '').trim();
  if (supplied) {
    releaseTag(supplied);
    return supplied.toLowerCase();
  }
  const git = spawnSync('git', ['rev-parse', 'HEAD'], {
    encoding: 'utf8', maxBuffer: 4096,
  });
  if (git.error || git.status !== 0) {
    throw new Error('Cannot identify the Git commit; no Worker upload attempted.');
  }
  const sha = String(git.stdout).trim();
  releaseTag(sha);
  return sha.toLowerCase();
}

export async function deployPreservingRoutes({
  env = process.env,
  invoke = (args) => runProcess(process.platform === 'win32' ? 'npx.cmd' : 'npx',
    ['--no-install', 'wrangler', ...args]),
} = {}) {
  const sha = commitShaFromEnvOrGit(env);
  const steps = releaseCommands(sha);
  for (const step of steps) {
    console.log('[Cloudflare code release] ' + step.label);
    await invoke(step.args);
  }
  console.log('[Cloudflare code release] Worker version promoted; route triggers were not updated.');
  console.log('[Cloudflare code release] Check production routes separately, especially after error 10020.');
}

const directCall = process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (directCall) {
  deployPreservingRoutes().catch(error => {
    console.error('[Cloudflare code release FAILED]', String(error.message || error));
    process.exitCode = 1;
  });
}
