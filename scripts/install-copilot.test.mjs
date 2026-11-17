import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import fs from 'node:fs';
import {
  COMPOSE_COPILOT_CONTEXT,
  isCopilotCheckout,
  parseWrapperArgs,
  syncMsfCatalog,
} from './install-copilot.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('compose Copilot context is r3ngine/r3ngine-copilot (compose ../ from docker/)', () => {
  assert.equal(COMPOSE_COPILOT_CONTEXT, path.join(ROOT, 'r3ngine-copilot'));
});

test('syncMsfCatalog copies sibling catalog into web/copilot/data when present', () => {
  const dest = path.join(ROOT, 'web', 'copilot', 'data', 'msf_aux_catalog.json');
  if (isCopilotCheckout(COMPOSE_COPILOT_CONTEXT)) {
    assert.equal(syncMsfCatalog(COMPOSE_COPILOT_CONTEXT), true);
    assert.ok(fs.existsSync(dest));
    const raw = JSON.parse(fs.readFileSync(dest, 'utf8'));
    assert.ok(Array.isArray(raw));
    assert.ok(raw.length > 0);
    assert.ok(String(raw[0].module || '').startsWith('auxiliary/') || String(raw[0].module || '').startsWith('post/'));
  } else {
    assert.equal(syncMsfCatalog(path.join(ROOT, 'does-not-exist-copilot')), false);
  }
});

test('parseWrapperArgs defaults and flags', () => {
  assert.deepEqual(parseWrapperArgs([]), {
    repo: 'https://github.com/whiterabb17/r3ngine-copilot.git',
    dir: path.join(ROOT, 'r3ngine-copilot'),
    update: false,
    stop: false,
    noDocker: false,
    help: false,
  });
  const updated = parseWrapperArgs(['--update', '--no-docker']);
  assert.equal(updated.update, true);
  assert.equal(updated.noDocker, true);
  const stopped = parseWrapperArgs(['--stop']);
  assert.equal(stopped.stop, true);
});

test('isCopilotCheckout recognizes sibling layout markers', () => {
  assert.equal(isCopilotCheckout(path.join(ROOT, 'does-not-exist-copilot')), false);
});
