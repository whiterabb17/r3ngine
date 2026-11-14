#!/usr/bin/env node
/**
 * Assessment Copilot compose helpers (mirrors install-mcp Docker ensure).
 *
 * Uses the shared `ollama` service (r3ngine-ollama image). Starts ollama if it
 * is not already running. Never builds a separate assessment-ollama image.
 *
 *   up      Ensure COMPOSE_PROFILES includes `ollama` + `copilot`, start ollama
 *           if down, then build and start assessment-copilot.
 *   update  Rebuild assessment-copilot; force-recreate only if it was running.
 *   stop    Stop assessment-copilot only (shared ollama stays up).
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
const COPILOT_PROFILE = 'copilot';
const OLLAMA_PROFILE = 'ollama';
const COPILOT_SERVICE = 'assessment-copilot';
const OLLAMA_SERVICE = 'ollama';

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

/** Ensure COMPOSE_PROFILES in .env includes the given profile names. */
export function ensureProfilesEnabled(profilesToAdd) {
  let text = readEnvFile();
  if (!text && !fs.existsSync(ENV_PATH)) {
    throw new Error('.env not found. Copy .env.example to .env first.');
  }
  const profiles = parseProfiles(text);
  const lower = new Set(profiles.map((p) => p.toLowerCase()));
  let changed = false;
  for (const name of profilesToAdd) {
    if (lower.has(name.toLowerCase())) continue;
    profiles.push(name);
    lower.add(name.toLowerCase());
    changed = true;
  }
  if (!changed) {
    log(`COMPOSE_PROFILES already includes ${profilesToAdd.join(', ')}.`);
    return false;
  }
  const next = profiles.join(',');
  if (/^\s*COMPOSE_PROFILES\s*=/m.test(text)) {
    text = text.replace(
      /^\s*COMPOSE_PROFILES\s*=.*$/m,
      `COMPOSE_PROFILES=${next}`,
    );
  } else {
    const suffix = text.endsWith('\n') || text.length === 0 ? '' : '\n';
    text = `${text}${suffix}# Enabled by make up-copilot so make up/start bring Copilot + Ollama back.\nCOMPOSE_PROFILES=${next}\n`;
  }
  fs.writeFileSync(ENV_PATH, text, 'utf8');
  log(`Enabled profiles in .env (COMPOSE_PROFILES=${next}).`);
  return true;
}

/** @deprecated Prefer ensureProfilesEnabled(['copilot','ollama']). */
export function ensureCopilotProfileEnabled() {
  return ensureProfilesEnabled([OLLAMA_PROFILE, COPILOT_PROFILE]);
}

function isContainerUp(nameFilter) {
  const probe = spawnSync(
    'docker',
    ['ps', '--filter', `name=${nameFilter}`, '--format', '{{.Names}}\t{{.Status}}'],
    { encoding: 'utf8', windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  if (probe.error || probe.status !== 0) return false;
  return (probe.stdout || '')
    .split(/\r?\n/)
    .filter(Boolean)
    .some((line) => {
      const [name, status = ''] = line.split('\t');
      // Prefer exact compose service suffix; avoid matching unrelated names.
      const n = String(name || '').toLowerCase();
      const needle = String(nameFilter || '').toLowerCase();
      if (!n.includes(needle)) return false;
      return /^\s*Up\b/i.test(status);
    });
}

/** True if the shared ollama container is Up. */
export function isOllamaRunning() {
  return isContainerUp(OLLAMA_SERVICE);
}

/** True if assessment-copilot is currently Up. */
export function isCopilotRunning() {
  return isContainerUp(COPILOT_SERVICE);
}

/** Start shared ollama if it is not already running (explicit service target). */
export function ensureOllamaRunning() {
  if (isOllamaRunning()) {
    log('Shared ollama is already running.');
    return false;
  }
  log('Shared ollama is not running — starting it.');
  // Explicit service name starts a profiled service without requiring the
  // profile flag; we still persist `ollama` in COMPOSE_PROFILES for make up.
  runCompose(['up', '-d', '--build', OLLAMA_SERVICE]);
  return true;
}

export function upCopilot() {
  ensureProfilesEnabled([OLLAMA_PROFILE, COPILOT_PROFILE]);
  ensureOllamaRunning();
  runCompose(['up', '-d', '--build', COPILOT_SERVICE]);
  log('Assessment Copilot is up (shared ollama).');
}

export function updateCopilot() {
  const wasRunning = isCopilotRunning();
  log(wasRunning
    ? 'Copilot container is running — rebuild and recreate.'
    : 'Copilot container is not running — rebuild only (will not start).');
  runCompose(['build', COPILOT_SERVICE]);
  if (wasRunning) {
    ensureOllamaRunning();
    runCompose(['up', '-d', '--force-recreate', '--no-deps', COPILOT_SERVICE]);
    log('Assessment Copilot image rebuilt and container recreated.');
  } else {
    log('Assessment Copilot image rebuilt. Run `make up-copilot` (or `make up` if enabled) to start.');
  }
}

export function stopCopilot() {
  // Leave shared ollama running — AI Hub / other consumers may use it.
  runCompose(['stop', COPILOT_SERVICE], { allowFail: true });
  log('Assessment Copilot stopped (shared ollama left running; COMPOSE_PROFILES unchanged).');
}

function usage() {
  console.log(`Usage: node scripts/copilot-stack.mjs <up|update|stop>

  up      Enable ollama+copilot profiles, start shared ollama if needed, start Copilot
  update  Rebuild Copilot image; recreate container only if it was running
  stop    Stop Copilot only (shared ollama stays up)
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
