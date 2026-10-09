#!/usr/bin/env node
/**
 * Clone r3ngine-mcp next to this repo (if needed) and run its Node setup script.
 *
 *   node scripts/install-mcp.mjs --url https://host --key r3n_mcp_… --yes
 *   node scripts/install-mcp.mjs --update
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const DEFAULT_REPO = 'https://github.com/whiterabb17/r3ngine-mcp.git';
const DEFAULT_DIR = path.join(ROOT, 'r3ngine-mcp');
/** Compose build context: docker/docker-compose*.yml uses `context: ../r3ngine-mcp`. */
export const COMPOSE_MCP_CONTEXT = path.join(ROOT, 'r3ngine-mcp');
const MCP_SERVICE = 'r3ngine-mcp';
const MCP_PROFILE = 'mcp';

function log(message) {
  process.stderr.write(`${message}\n`);
}

export function nodeBin(env = process.env) {
  return env.NODE || 'node';
}

export function usesCmdShell(command, platform = process.platform) {
  return platform === 'win32' && /\.(cmd|bat)$/i.test(command);
}

function run(command, args, cwd = ROOT) {
  const result = spawnSync(command, args, {
    cwd,
    stdio: 'inherit',
    env: process.env,
    windowsHide: true,
    shell: usesCmdShell(command),
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(' ')} failed with exit ${result.status}`);
  }
}

function hasGit(dir) {
  return fs.existsSync(path.join(dir, '.git'));
}

function isMcpCheckout(dir) {
  return fs.existsSync(path.join(dir, 'scripts', 'install.mjs'))
    && fs.existsSync(path.join(dir, 'package.json'));
}

export function parseWrapperArgs(argv) {
  const out = {
    repo: process.env.R3NGINE_MCP_REPO || DEFAULT_REPO,
    dir: DEFAULT_DIR,
    update: false,
    noDocker: false,
    help: false,
    rest: [],
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--') {
      out.rest = argv.slice(i + 1);
      break;
    }
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
    if (arg === '--no-docker') {
      out.noDocker = true;
      continue;
    }
    if (arg === '-h' || arg === '--help') {
      out.help = true;
      continue;
    }
    out.rest = argv.slice(i);
    break;
  }
  return out;
}

function usage() {
  log(`Usage: node scripts/install-mcp.mjs [wrapper options] [--] [setup options]

Wrapper:
  --repo <url>   git remote (default ${DEFAULT_REPO})
  --dir <path>   checkout path (default ./r3ngine-mcp)
  --update       git pull, rebuild local MCP (incl. allowlisted cyber skills sync),
                 and rebuild/recreate the Docker MCP sidecar
                 (creates and starts it if missing; uses --profile mcp)
  --no-docker    skip Docker image/container ensure (local/stdio only)

Setup options are forwarded to r3ngine-mcp/scripts/install.mjs
  (e.g. --url --key --transport --yes --write-cursor --detach --stop --restart --update)

Cyber skills are portable under r3ngine-mcp/skills/vendor/anthropic/ (not ~/.claude/skills).
On-demand: node r3ngine-mcp/scripts/sync-cyber-skills.mjs --missing-only

Examples:
  node scripts/install-mcp.mjs --url https://host --key r3n_mcp_… --yes --write-cursor
  node scripts/install-mcp.mjs --update
`);
}

export function ensureCheckout({ dir, repo, update }) {
  if (isMcpCheckout(dir)) {
    log(`Using existing r3ngine-mcp at ${dir}`);
    if (update && hasGit(dir)) {
      log('Updating r3ngine-mcp…');
      run('git', ['pull', '--ff-only'], dir);
    }
    return dir;
  }
  if (fs.existsSync(dir)) {
    throw new Error(`${dir} exists but is not an r3ngine-mcp checkout (missing scripts/install.mjs)`);
  }
  log(`Cloning ${repo} → ${dir}`);
  run('git', ['clone', repo, dir]);
  if (!isMcpCheckout(dir)) {
    throw new Error('Clone succeeded but scripts/install.mjs was not found');
  }
  return dir;
}

/** Prefer `docker compose`, fall back to `docker-compose`. */
export function resolveDockerCompose(exec = spawnSync) {
  const probe = exec('docker', ['compose', 'version'], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (!probe.error && probe.status === 0) {
    return { command: 'docker', argsPrefix: ['compose'] };
  }
  return { command: 'docker-compose', argsPrefix: [] };
}

function parseComposeLabels(raw) {
  try {
    return JSON.parse(String(raw || '{}'));
  } catch {
    return {};
  }
}

/** Build compose CLI args from labels and/or default compose files under root. */
export function buildComposeArgs(root, {
  project,
  configFiles = [],
  includeProfile = true,
} = {}) {
  const composeArgs = [];
  if (project) composeArgs.push('-p', project);
  const envFile = path.join(root, '.env');
  if (fs.existsSync(envFile)) composeArgs.push('--env-file', envFile);
  if (configFiles.length) {
    for (const file of configFiles) composeArgs.push('-f', file);
  } else {
    const prod = path.join(root, 'docker', 'docker-compose.yml');
    const dev = path.join(root, 'docker', 'docker-compose.dev.yml');
    if (fs.existsSync(prod)) composeArgs.push('-f', prod);
    else if (fs.existsSync(dev)) composeArgs.push('-f', dev);
  }
  // Prod compose gates the service behind profiles: ["mcp"]; harmless on files without it.
  if (includeProfile) composeArgs.push('--profile', MCP_PROFILE);
  return composeArgs;
}

function labelsToComposeTarget(labels, { root, id = null, name = null, status = '' } = {}) {
  const configFiles = String(labels['com.docker.compose.project.config_files'] || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const project = labels['com.docker.compose.project'] || undefined;
  const workingDir = labels['com.docker.compose.project.working_dir'] || root;
  return {
    id,
    name,
    running: /^\s*Up\b/i.test(status || ''),
    service: MCP_SERVICE,
    cwd: workingDir,
    composeArgs: buildComposeArgs(root, { project, configFiles }),
    configFiles,
    project,
  };
}

/**
 * Locate an existing r3ngine-mcp container and the compose invocation that owns it.
 * Returns null when Docker is unavailable or no MCP container exists.
 */
export function findMcpComposeService({ exec = spawnSync, root = ROOT } = {}) {
  const list = exec(
    'docker',
    ['ps', '-a', '--filter', 'name=r3ngine-mcp', '--format', '{{.ID}}\t{{.Names}}\t{{.Status}}'],
    { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (list.error || list.status !== 0) return null;
  const line = String(list.stdout || '').trim().split(/\r?\n/).find(Boolean);
  if (!line) return null;
  const [id, name, status = ''] = line.split('\t');
  if (!id || !name) return null;

  const insp = exec('docker', ['inspect', '-f', '{{json .Config.Labels}}', id], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (insp.error || insp.status !== 0) return null;
  return labelsToComposeTarget(parseComposeLabels(insp.stdout), { root, id, name, status });
}

/**
 * Infer compose project/files from a running stack container (web/proxy) when MCP
 * has never been created (prod profile keeps it off `make up`).
 */
export function findStackComposeService({ exec = spawnSync, root = ROOT } = {}) {
  const list = exec(
    'docker',
    ['ps', '-a', '--filter', 'name=r3ngine', '--format', '{{.ID}}\t{{.Names}}\t{{.Status}}'],
    { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (list.error || list.status !== 0) return null;
  const lines = String(list.stdout || '').trim().split(/\r?\n/).filter(Boolean);
  if (!lines.length) return null;

  const rank = (names) => {
    const n = String(names || '').toLowerCase();
    if (n.includes('r3ngine-mcp')) return 99;
    if (n.includes('-web-') || n.endsWith('-web') || n.includes('_web_')) return 0;
    if (n.includes('-proxy-') || n.includes('_proxy_')) return 1;
    return 5;
  };
  const ranked = lines
    .map((line) => {
      const [id, name, status = ''] = line.split('\t');
      return { id, name, status, rank: rank(name) };
    })
    .filter((row) => row.id && row.name && row.rank < 99)
    .sort((a, b) => a.rank - b.rank);
  for (const row of ranked) {
    const insp = exec('docker', ['inspect', '-f', '{{json .Config.Labels}}', row.id], {
      encoding: 'utf8',
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (insp.error || insp.status !== 0) continue;
    const labels = parseComposeLabels(insp.stdout);
    if (!labels['com.docker.compose.project'] && !labels['com.docker.compose.project.config_files']) {
      continue;
    }
    const target = labelsToComposeTarget(labels, {
      root,
      id: null,
      name: null,
      status: '',
    });
    target.from = row.name;
    return target;
  }
  return null;
}

/** Resolve compose target for MCP: existing container, else stack labels, else defaults. */
export function resolveMcpComposeTarget({ exec = spawnSync, root = ROOT } = {}) {
  const existing = findMcpComposeService({ exec, root });
  if (existing) return { ...existing, source: 'mcp-container' };
  const stack = findStackComposeService({ exec, root });
  if (stack) return { ...stack, source: 'stack' };
  return {
    id: null,
    name: null,
    running: false,
    service: MCP_SERVICE,
    cwd: root,
    composeArgs: buildComposeArgs(root, {}),
    configFiles: [],
    source: 'defaults',
  };
}

export function pullMcpCheckout(dir) {
  if (!isMcpCheckout(dir)) return false;
  if (!hasGit(dir)) return false;
  log(`Updating r3ngine-mcp at ${dir}…`);
  run('git', ['pull', '--ff-only'], dir);
  return true;
}

function dockerAvailable(exec = spawnSync) {
  const probe = exec('docker', ['version'], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return !probe.error && probe.status === 0;
}

/**
 * Build and start the MCP compose service (creates it when missing).
 * Uses --profile mcp so prod stacks that gate the service still get a container.
 */
export function ensureMcpDockerContainer({
  exec = spawnSync,
  root = ROOT,
  runFn = run,
  forceRecreate = false,
} = {}) {
  if (!dockerAvailable(exec)) {
    log('Docker is not available; skipping r3ngine-mcp container ensure.');
    return { updated: false, started: false, reason: 'no-docker' };
  }

  const info = resolveMcpComposeTarget({ exec, root });
  const hasComposeFile = info.composeArgs.includes('-f');
  if (!hasComposeFile) {
    log('No docker-compose.yml found under docker/; skipping MCP container ensure.');
    return { updated: false, started: false, reason: 'no-compose' };
  }

  const dc = resolveDockerCompose(exec);
  const buildArgs = [...dc.argsPrefix, ...info.composeArgs, 'build', info.service];
  const label = info.name || info.from || info.source;
  log(`Building Docker image for ${info.service} (${label})…`);
  runFn(dc.command, buildArgs, info.cwd);

  const upArgs = [
    ...dc.argsPrefix,
    ...info.composeArgs,
    'up',
    '-d',
    '--no-deps',
  ];
  if (forceRecreate || info.running) upArgs.push('--force-recreate');
  upArgs.push(info.service);

  log(`Starting MCP container (${info.service})…`);
  runFn(dc.command, upArgs, info.cwd);
  log('MCP container is up.');
  return {
    updated: true,
    started: true,
    recreated: Boolean(forceRecreate || info.running),
    name: info.name,
    source: info.source,
  };
}

/** @deprecated Prefer ensureMcpDockerContainer — kept for older callers/tests. */
export function updateMcpDockerContainer(opts = {}) {
  return ensureMcpDockerContainer({ ...opts, forceRecreate: true });
}

export function main(argv = process.argv.slice(2)) {
  const opts = parseWrapperArgs(argv);
  if (opts.help) {
    usage();
    return 0;
  }
  const major = Number(String(process.versions.node).split('.')[0]);
  if (!Number.isFinite(major) || major < 20) {
    throw new Error(`Node.js 20+ is required (found ${process.versions.node})`);
  }
  const dir = ensureCheckout(opts);
  const installer = path.join(dir, 'scripts', 'install.mjs');
  const setupArgs = [...opts.rest];
  // Wrapper --update pulls the checkout; forward --update so the sidecar rebuilds/restarts.
  if (opts.update && !setupArgs.includes('--update')) {
    setupArgs.unshift('--update');
  }

  if (!opts.noDocker) {
    const composeCtx = COMPOSE_MCP_CONTEXT;
    if (opts.update && path.resolve(composeCtx) !== path.resolve(dir) && isMcpCheckout(composeCtx)) {
      pullMcpCheckout(composeCtx);
    }
    if (!isMcpCheckout(composeCtx) && path.resolve(composeCtx) !== path.resolve(dir)) {
      log(
        `Warning: compose build context ${composeCtx} is missing; `
        + `docker will use whatever path docker-compose.yml references.`,
      );
    }
    ensureMcpDockerContainer({
      root: ROOT,
      forceRecreate: Boolean(opts.update),
    });
  }

  log(`Running ${installer}`);
  run(nodeBin(), [installer, ...setupArgs], dir);
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
