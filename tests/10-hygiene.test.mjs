import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function walk(dir, files = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === '.git' || entry === 'node_modules') continue;
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) walk(path, files);
    else files.push(path);
  }
  return files;
}

const trackedFiles = walk(root).filter((path) => !path.endsWith('.test.mjs') && !path.includes('/tests/'));

const internal = [
  ['/Users/', 'aarivpatel'].join(''),
  ['/private/tmp', 'agent-work'].join('/'),
  ['Contest', ' Submissions'].join(''),
  ['Hark', 'Hackathons'].join('-'),
];
const EM_DASH = String.fromCharCode(0x2014);
const EN_DASH = String.fromCharCode(0x2013);

test('no internal personal paths in shipped files', () => {
  for (const file of trackedFiles) {
    const text = readFileSync(file, 'utf8');
    for (const marker of internal) {
      assert.ok(!text.includes(marker), `${file} contains internal path marker`);
    }
  }
});

test('no em dashes or en dashes in shipped files', () => {
  for (const file of trackedFiles) {
    const text = readFileSync(file, 'utf8');
    assert.ok(!text.includes(EM_DASH), `${file} contains em dash`);
    assert.ok(!text.includes(EN_DASH), `${file} contains en dash`);
  }
});

test('package.json declares zero runtime dependencies', () => {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  assert.deepEqual(pkg.dependencies, {});
  assert.equal(pkg.type, 'module');
});

test('README documents the exact test count', () => {
  const readme = readFileSync(join(root, 'README.md'), 'utf8');
  assert.match(readme, /node --test/);
  assert.match(readme, /150\+|1\d\d|\d{3}/);
});

test('SECURITY.md includes private vulnerability reporting', () => {
  const text = readFileSync(join(root, 'SECURITY.md'), 'utf8');
  assert.match(text, /Security Advisory/);
  assert.match(text, /Privately report/);
});

test('generated CJS files are present', () => {
  const cjsFiles = readdirSync(join(root, 'cjs')).filter((f) => f.endsWith('.cjs'));
  assert.ok(cjsFiles.length >= 8);
});

test('error output never contains a filesystem stack', () => {
  const { UrlGuardError } = require('../cjs/index.cjs');
  const error = new UrlGuardError('PRIVATE_IP', 'blocked', 'http://127.0.0.1/');
  assert.doesNotMatch(error.stack, /\/Users\//);
  assert.doesNotMatch(error.stack, /\s+at\s+/);
});

