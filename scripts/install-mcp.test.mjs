import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  parseWrapperArgs,
  nodeBin,
  usesCmdShell,
  findMcpComposeService,
  findStackComposeService,
  resolveMcpComposeTarget,
  ensureMcpDockerContainer,
  updateMcpDockerContainer,
  resolveDockerCompose,
  COMPOSE_MCP_CONTEXT,
} from './install-mcp.mjs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('wrapper flags stop at first setup argument', () => {
  const opts = parseWrapperArgs(['--update', '--url', 'https://h', '--yes']);
  assert.equal(opts.update, true);
  assert.deepEqual(opts.rest, ['--url', 'https://h', '--yes']);
});

test('wrapper update alone leaves empty rest for setup forwarding', () => {
  const opts = parseWrapperArgs(['--update']);
  assert.equal(opts.update, true);
  assert.equal(opts.noDocker, false);
  assert.deepEqual(opts.rest, []);
});

test('wrapper accepts --no-docker', () => {
  const opts = parseWrapperArgs(['--update', '--no-docker']);
  assert.equal(opts.update, true);
  assert.equal(opts.noDocker, true);
});

test('double dash separates wrapper from setup', () => {
  const opts = parseWrapperArgs(['--repo', 'https://git.example/mcp.git', '--', '--transport', 'http']);
  assert.equal(opts.repo, 'https://git.example/mcp.git');
  assert.deepEqual(opts.rest, ['--transport', 'http']);
});

test('nodeBin uses NODE from env, not an absolute install path', () => {
  assert.equal(nodeBin({}), 'node');
  assert.equal(nodeBin({ NODE: 'node' }), 'node');
  assert.equal(usesCmdShell('C:\\Program Files\\nodejs\\node.exe', 'win32'), false);
  assert.equal(usesCmdShell('npm.cmd', 'win32'), true);
  assert.equal(usesCmdShell('npm.cmd', 'linux'), false);
});

test('compose MCP context is r3ngine/r3ngine-mcp (compose ../ from docker/)', () => {
  assert.equal(COMPOSE_MCP_CONTEXT, path.join(ROOT, 'r3ngine-mcp'));
});

test('findMcpComposeService returns null when no container', () => {
  const exec = (cmd, args) => {
    assert.equal(cmd, 'docker');
    if (args[0] === 'ps') return { status: 0, stdout: '', error: null };
    throw new Error(`unexpected ${args.join(' ')}`);
  };
  assert.equal(findMcpComposeService({ exec }), null);
});

test('findMcpComposeService reads compose labels', () => {
  const labels = {
    'com.docker.compose.project': 'r3ngine',
    'com.docker.compose.project.config_files': '/repo/docker/docker-compose.yml',
    'com.docker.compose.project.working_dir': '/repo',
    'com.docker.compose.service': 'r3ngine-mcp',
  };
  const exec = (cmd, args) => {
    assert.equal(cmd, 'docker');
    if (args[0] === 'ps') {
      return { status: 0, stdout: 'abc123\tr3ngine-r3ngine-mcp-1\tUp 2 hours\n', error: null };
    }
    if (args[0] === 'inspect') {
      return { status: 0, stdout: JSON.stringify(labels), error: null };
    }
    throw new Error(`unexpected ${args.join(' ')}`);
  };
  const info = findMcpComposeService({ exec, root: '/repo' });
  assert.equal(info.name, 'r3ngine-r3ngine-mcp-1');
  assert.equal(info.running, true);
  assert.equal(info.service, 'r3ngine-mcp');
  assert.equal(info.cwd, '/repo');
  assert.deepEqual(info.composeArgs, [
    '-p', 'r3ngine',
    '-f', '/repo/docker/docker-compose.yml',
    '--profile', 'mcp',
  ]);
});

test('findStackComposeService prefers web when MCP missing', () => {
  const labels = {
    'com.docker.compose.project': 'r3ngine',
    'com.docker.compose.project.config_files': '/repo/docker/docker-compose.yml',
    'com.docker.compose.project.working_dir': '/repo/docker',
    'com.docker.compose.service': 'web',
  };
  const exec = (cmd, args) => {
    if (args[0] === 'ps') {
      return {
        status: 0,
        stdout: 'w1\tr3ngine-web-1\tUp\np1\tr3ngine-proxy-1\tUp\n',
        error: null,
      };
    }
    if (args[0] === 'inspect' && args.includes('w1')) {
      return { status: 0, stdout: JSON.stringify(labels), error: null };
    }
    throw new Error(`unexpected ${cmd} ${args.join(' ')}`);
  };
  const info = findStackComposeService({ exec, root: '/repo' });
  assert.equal(info.from, 'r3ngine-web-1');
  assert.equal(info.service, 'r3ngine-mcp');
  assert.equal(info.cwd, '/repo/docker');
  assert.ok(info.composeArgs.includes('--profile'));
  assert.ok(info.composeArgs.includes('mcp'));
});

test('resolveMcpComposeTarget falls back to stack then defaults', () => {
  const noMcp = (cmd, args) => {
    if (args[0] === 'ps' && args.includes('name=r3ngine-mcp')) {
      return { status: 0, stdout: '', error: null };
    }
    if (args[0] === 'ps' && args.includes('name=r3ngine')) {
      return { status: 0, stdout: '', error: null };
    }
    throw new Error(`unexpected ${args.join(' ')}`);
  };
  const defaults = resolveMcpComposeTarget({ exec: noMcp, root: ROOT });
  assert.equal(defaults.source, 'defaults');
  assert.equal(defaults.service, 'r3ngine-mcp');
  assert.ok(defaults.composeArgs.includes('-f'));
  assert.ok(defaults.composeArgs.includes('--profile'));
});

test('ensureMcpDockerContainer builds and starts when container missing', () => {
  const labels = {
    'com.docker.compose.project': 'r3ngine',
    'com.docker.compose.project.config_files': '/repo/docker/docker-compose.yml',
    'com.docker.compose.project.working_dir': '/repo',
    'com.docker.compose.service': 'web',
  };
  const exec = (cmd, args) => {
    if (cmd === 'docker' && args[0] === 'version') {
      return { status: 0, stdout: 'ok', error: null };
    }
    if (cmd === 'docker' && args[0] === 'compose' && args[1] === 'version') {
      return { status: 0, stdout: 'Docker Compose version v2', error: null };
    }
    if (cmd === 'docker' && args[0] === 'ps' && args.includes('name=r3ngine-mcp')) {
      return { status: 0, stdout: '', error: null };
    }
    if (cmd === 'docker' && args[0] === 'ps' && args.includes('name=r3ngine')) {
      return { status: 0, stdout: 'w1\tr3ngine-web-1\tUp\n', error: null };
    }
    if (cmd === 'docker' && args[0] === 'inspect') {
      return { status: 0, stdout: JSON.stringify(labels), error: null };
    }
    throw new Error(`unexpected exec ${cmd} ${args.join(' ')}`);
  };
  const calls = [];
  const result = ensureMcpDockerContainer({
    exec,
    root: '/repo',
    runFn: (command, args, cwd) => calls.push({ command, args, cwd }),
  });
  assert.equal(result.updated, true);
  assert.equal(result.started, true);
  assert.equal(result.source, 'stack');
  assert.equal(calls.length, 2);
  assert.ok(calls[0].args.includes('build'));
  assert.ok(calls[0].args.includes('r3ngine-mcp'));
  assert.ok(calls[0].args.includes('--profile'));
  assert.ok(calls[1].args.includes('up'));
  assert.ok(calls[1].args.includes('-d'));
  assert.ok(!calls[1].args.includes('--force-recreate'));
  assert.equal(calls[1].cwd, '/repo');
});

test('updateMcpDockerContainer builds and recreates when running', () => {
  const labels = {
    'com.docker.compose.project': 'r3ngine',
    'com.docker.compose.project.config_files': '/repo/docker/docker-compose.yml',
    'com.docker.compose.project.working_dir': '/repo',
    'com.docker.compose.service': 'r3ngine-mcp',
  };
  const exec = (cmd, args) => {
    if (cmd === 'docker' && args[0] === 'version') {
      return { status: 0, stdout: 'ok', error: null };
    }
    if (cmd === 'docker' && args[0] === 'compose' && args[1] === 'version') {
      return { status: 0, stdout: 'Docker Compose version v2', error: null };
    }
    if (cmd === 'docker' && args[0] === 'ps') {
      return { status: 0, stdout: 'abc\tr3ngine-r3ngine-mcp-1\tUp 1 minute\n', error: null };
    }
    if (cmd === 'docker' && args[0] === 'inspect') {
      return { status: 0, stdout: JSON.stringify(labels), error: null };
    }
    throw new Error(`unexpected exec ${cmd} ${args.join(' ')}`);
  };
  const calls = [];
  const runFn = (command, args, cwd) => {
    calls.push({ command, args, cwd });
  };
  const result = updateMcpDockerContainer({ exec, root: '/repo', runFn });
  assert.equal(result.updated, true);
  assert.equal(result.started, true);
  assert.equal(calls.length, 2);
  assert.equal(calls[0].command, 'docker');
  assert.ok(calls[0].args.includes('build'));
  assert.ok(calls[0].args.includes('r3ngine-mcp'));
  assert.ok(calls[1].args.includes('up'));
  assert.ok(calls[1].args.includes('--force-recreate'));
  assert.equal(calls[1].cwd, '/repo');
});

test('ensureMcpDockerContainer starts a previously stopped container', () => {
  const labels = {
    'com.docker.compose.project.config_files': '/repo/docker/docker-compose.dev.yml',
    'com.docker.compose.project.working_dir': '/repo',
    'com.docker.compose.service': 'r3ngine-mcp',
  };
  const exec = (cmd, args) => {
    if (cmd === 'docker' && args[0] === 'version') {
      return { status: 0, stdout: 'ok', error: null };
    }
    if (cmd === 'docker' && args[0] === 'compose' && args[1] === 'version') {
      return { status: 0, stdout: 'ok', error: null };
    }
    if (cmd === 'docker' && args[0] === 'ps') {
      return { status: 0, stdout: 'abc\tr3ngine-r3ngine-mcp-1\tExited (0) 3 days ago\n', error: null };
    }
    if (cmd === 'docker' && args[0] === 'inspect') {
      return { status: 0, stdout: JSON.stringify(labels), error: null };
    }
    throw new Error(`unexpected ${cmd} ${args.join(' ')}`);
  };
  const calls = [];
  const result = ensureMcpDockerContainer({
    exec,
    root: '/repo',
    runFn: (command, args) => calls.push({ command, args }),
  });
  assert.equal(result.updated, true);
  assert.equal(result.started, true);
  assert.equal(calls.length, 2);
  assert.ok(calls[0].args.includes('build'));
  assert.ok(calls[1].args.includes('up'));
});

test('resolveDockerCompose falls back to docker-compose', () => {
  const exec = () => ({ status: 1, stdout: '', error: null });
  const dc = resolveDockerCompose(exec);
  assert.equal(dc.command, 'docker-compose');
  assert.deepEqual(dc.argsPrefix, []);
});
