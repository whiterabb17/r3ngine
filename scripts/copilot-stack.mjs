#!/usr/bin/env node
/**
 * Assessment Copilot compose helpers (mirrors install-mcp Docker ensure).
 *
 *   up      Ensure COMPOSE_PROFILES includes `copilot`, then build and start.
 *   update  Rebuild images; force-recreate only if a copilot container was running.
 *   stop    Stop copilot containers (profile stays enabled so `make up` brings them back).
 *
 * Usage: node scripts/copilot-stack.mjs <up|update|stop>
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const ENV_PATH = path.join(ROOT, '.env');
const PROFILE = 'copilot';
const SERVICES = ['assessment-ollama', 'assessment-copilot'];

function log(msg) {
  console.log(`[copilot-stack] ${msg}`);
}

function resolveDockerCompose() {
  const probe = spawnSync('docker', ['compose', 'version'], {
    encoding: 'utf8',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (!probe.error && probe.status === 0) {
    return { command: 'docker', argsPrefix: ['compose'] };
  }
  return { command: 'docker-compose', argsPrefix: [] };
}

function composeBaseArgs() {
  return ['--env-file', '.env', '-f', 'docker/docker-compose.yml'];
}

function runCompose(args, { allowFail = false } = {}) {
  const dc = resolveDockerCompose();
  const full = [...dc.argsPrefix, ...composeBaseArgs(), ...args];
  log(`${dc.command} ${full.join(' ')}`);
  const result = spawnSync(dc.command, full, {
    cwd: ROOT,
    encoding: 'utf8',
    windowsHide: true,
    stdio: 'inherit',
    env: {
      ...process.env,
      DOCKER_BUILDKIT: process.env.DOCKER_BUILDKIT || '1',
      COMPOSE_DOCKER_CLI_BUILD: process.env.COMPOSE_DOCKER_CLI_BUILD || '1',
      COMPOSE_BAKE: process.env.COMPOSE_BAKE || 'false',
    },
  });
  if (!allowFail && result.status !== 0) {
    process.exit(result.status ?? 1);
  }
  return result.status ?? 1;
}

function readEnvFile() {
  if (!fs.existsSync(ENV_PATH)) return '';
  return fs.readFileSync(ENV_PATH, 'utf8');
}

function parseProfiles(envText) {
  const match = envText.match(/^\s*COMPOSE_PROFILES\s*=\s*(.*)$/m);
  if (!match) return [];
  let raw = match[1].trim();
  if (
    (raw.startsWith('"') && raw.endsWith('"')) ||
    (raw.startsWith("'") && raw.endsWith("'"))
  ) {
    raw = raw.slice(1, -1);
  }
  return raw
    .split(',')
    .map((p) => p.trim())
    .filter(Boolean);
}

/** Ensure COMPOSE_PROFILES in .env includes `copilot` (create the line if missing). */
export function ensureCopilotProfileEnabled() {
  let text = readEnvFile();
  if (!text && !fs.existsSync(ENV_PATH)) {
    throw new Error('.env not found. Copy .env.example to .env first.');
  }
  const profiles = parseProfiles(text);
  if (profiles.map((p) => p.toLowerCase()).includes(PROFILE)) {
    log(`COMPOSE_PROFILES already includes "${PROFILE}".`);
    return false;
  }
  profiles.push(PROFILE);
  const next = profiles.join(',');
  if (/^\s*COMPOSE_PROFILES\s*=/m.test(text)) {
    text = text.replace(
      /^\s*COMPOSE_PROFILES\s*=.*$/m,
      `COMPOSE_PROFILES=${next}`,
    );
  } else {
    const suffix = text.endsWith('\n') || text.length === 0 ? '' : '\n';
    text = `${text}${suffix}# Enabled by make up-copilot so make up/start bring Copilot back.\nCOMPOSE_PROFILES=${next}\n`;
  }
  fs.writeFileSync(ENV_PATH, text, 'utf8');
  log(`Enabled profile "${PROFILE}" in .env (COMPOSE_PROFILES=${next}).`);
  return true;
}

/** True if any assessment-copilot / assessment-ollama container is currently Up. */
export function isCopilotRunning() {
  const probe = spawnSync(
    'docker',
    [
      'ps',
      '--filter',
      'name=assessment-copilot',
      '--filter',
      'name=assessment-ollama',
      '--format',
      '{{.Names}}\t{{.Status}}',
    ],
    { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (probe.error || probe.status !== 0) return false;
  return (probe.stdout || '')
    .split(/\r?\n/)
    .filter(Boolean)
    .some((line) => /^\S+\tUp\b/i.test(line));
}

export function upCopilot() {
  ensureCopilotProfileEnabled();
  runCompose(['up', '-d', '--build', ...SERVICES]);
  log('Assessment Copilot is up.');
}

export function updateCopilot() {
  const wasRunning = isCopilotRunning();
  log(wasRunning
    ? 'Copilot containers are running — rebuild and recreate.'
    : 'Copilot containers are not running — rebuild only (will not start).');
  runCompose(['build', ...SERVICES]);
  if (wasRunning) {
    runCompose(['up', '-d', '--force-recreate', '--no-deps', ...SERVICES]);
    log('Assessment Copilot images rebuilt and containers recreated.');
  } else {
    log('Assessment Copilot images rebuilt. Run `make up-copilot` (or `make up` if enabled) to start.');
  }
}

export function stopCopilot() {
  runCompose(['stop', ...SERVICES], { allowFail: true });
  log('Assessment Copilot stopped (COMPOSE_PROFILES left unchanged so make up can restart it).');
}

function usage() {
  console.log(`Usage: node scripts/copilot-stack.mjs <up|update|stop>

  up      Enable COMPOSE_PROFILES=copilot in .env, build and start Copilot
  update  Rebuild Copilot images; recreate containers only if they were running
  stop    Stop Copilot containers (keeps profile enabled for make up)
`);
}

function main(argv = process.argv.slice(2)) {
  const cmd = (argv[0] || '').toLowerCase();
  if (cmd === 'up') return upCopilot();
  if (cmd === 'update') return updateCopilot();
  if (cmd === 'stop') return stopCopilot();
  usage();
  process.exit(cmd ? 1 : 0);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
