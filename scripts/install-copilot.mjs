#!/usr/bin/env node
/**
 * Clone r3ngine-copilot next to this repo (if needed) and bring up the compose
 * profile (mirrors install-mcp.mjs). Uses the shared `ollama` service.
 *
 *   node scripts/install-copilot.mjs
 *   node scripts/install-copilot.mjs --update
 *   node scripts/install-copilot.mjs --stop
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  ensureCopilotProfileEnabled,
  isCopilotRunning,
  stopCopilot,
  upCopilot,
  updateCopilot,
} from './copilot-stack.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_REPO = 'https://github.com/whiterabb17/r3ngine-copilot.git';
const DEFAULT_DIR = path.join(ROOT, 'r3ngine-copilot');
/** Compose build context: docker/docker-compose*.yml uses `context: ../r3ngine-copilot`. */
export const COMPOSE_COPILOT_CONTEXT = path.join(ROOT, 'r3ngine-copilot');

function log(message) {
  process.stderr.write(`${message}\n`);
}

function run(command, args, cwd = ROOT) {
  const result = spawnSync(command, args, {
    cwd,
    stdio: 'inherit',
    env: process.env,
    windowsHide: true,
    shell: process.platform === 'win32' && /\.(cmd|bat)$/i.test(command),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit ${result.status}`);
  }
}

function hasGit(dir) {
  return fs.existsSync(path.join(dir, '.git'));
}

export function isCopilotCheckout(dir) {
  return fs.existsSync(path.join(dir, 'Dockerfile'))
    && fs.existsSync(path.join(dir, 'app', 'main.py'))
    && fs.existsSync(path.join(dir, 'requirements.txt'));
}

export function parseWrapperArgs(argv) {
  const out = {
    repo: process.env.R3NGINE_COPILOT_REPO || DEFAULT_REPO,
    dir: DEFAULT_DIR,
    update: false,
    stop: false,
    noDocker: false,
    help: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--repo') {
      i += 1;
      out.repo = argv[i];
      continue;
    }
    if (arg === '--dir') {
      i += 1;
      out.dir = path.resolve(argv[i]);
      continue;
    }
    if (arg === '--update') {
      out.update = true;
      continue;
    }
    if (arg === '--stop') {
      out.stop = true;
      continue;
    }
    if (arg === '--no-docker') {
      out.noDocker = true;
      continue;
    }
    if (arg === '-h' || arg === '--help') {
      out.help = true;
      continue;
    }
    throw new Error(`Unknown option: ${arg}`);
  }
  return out;
}

function usage() {
  log(`Usage: node scripts/install-copilot.mjs [options]

Options:
  --repo <url>   git remote (default ${DEFAULT_REPO})
  --dir <path>   checkout path (default ./r3ngine-copilot)
  --update       git pull + rebuild Copilot image (recreate if running)
  --stop         stop assessment-copilot (shared ollama stays up)
  --no-docker    clone/update checkout only (skip compose)

Examples:
  node scripts/install-copilot.mjs
  node scripts/install-copilot.mjs --update
  node scripts/install-copilot.mjs --stop

Make targets: install-copilot, update-copilot, up-copilot, stop-copilot
`);
}

export function ensureCheckout({ dir, repo, update }) {
  if (isCopilotCheckout(dir)) {
    log(`Using existing r3ngine-copilot at ${dir}`);
    if (update && hasGit(dir)) {
      log('Updating r3ngine-copilot…');
      run('git', ['pull', '--ff-only'], dir);
    }
    return dir;
  }
  if (fs.existsSync(dir)) {
    throw new Error(
      `${dir} exists but is not an r3ngine-copilot checkout `
      + '(missing Dockerfile / app/main.py)',
    );
  }
  log(`Cloning ${repo} → ${dir}`);
  run('git', ['clone', repo, dir]);
  if (!isCopilotCheckout(dir)) {
    throw new Error('Clone succeeded but app/main.py was not found');
  }
  return dir;
}

export function pullCopilotCheckout(dir) {
  if (!isCopilotCheckout(dir) || !hasGit(dir)) return false;
  log(`Updating r3ngine-copilot at ${dir}…`);
  run('git', ['pull', '--ff-only'], dir);
  return true;
}

/** Sync sibling MSF catalog into Django vendored path (runtime does not depend on sibling). */
export function syncMsfCatalog(dir = COMPOSE_COPILOT_CONTEXT) {
  const src = path.join(dir, 'data', 'msf_aux_catalog.json');
  const destDir = path.join(ROOT, 'web', 'copilot', 'data');
  const dest = path.join(destDir, 'msf_aux_catalog.json');
  if (!fs.existsSync(src)) {
    log(`Warning: MSF catalog missing at ${src}; skipping Django sync.`);
    return false;
  }
  fs.mkdirSync(destDir, { recursive: true });
  fs.copyFileSync(src, dest);
  log(`Synced MSF catalog → ${dest}`);
  return true;
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseWrapperArgs(argv);
  if (opts.help) {
    usage();
    return 0;
  }

  if (opts.stop) {
    stopCopilot();
    return 0;
  }

  const dir = ensureCheckout(opts);
  const composeCtx = COMPOSE_COPILOT_CONTEXT;
  if (path.resolve(composeCtx) !== path.resolve(dir) && isCopilotCheckout(composeCtx)) {
    if (opts.update) pullCopilotCheckout(composeCtx);
  } else if (!isCopilotCheckout(composeCtx)) {
    log(
      `Warning: compose build context ${composeCtx} is missing; `
      + 'docker will use whatever path docker-compose.yml references.',
    );
  }

  syncMsfCatalog(isCopilotCheckout(composeCtx) ? composeCtx : dir);

  if (opts.noDocker) {
    log('Checkout ready (--no-docker). Enable with make up-copilot when ready.');
    return 0;
  }

  if (opts.update) {
    ensureCopilotProfileEnabled();
    updateCopilot();
    if (!isCopilotRunning()) {
      log('Starting Assessment Copilot after update…');
      upCopilot();
    }
    return 0;
  }

  upCopilot();
  return 0;
}

const invoked = Boolean(process.argv[1])
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invoked) {
  try {
    process.exit(main() ?? 0);
  } catch (error) {
    log(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
