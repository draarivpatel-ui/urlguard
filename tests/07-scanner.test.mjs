import test from 'node:test';
import assert from 'node:assert/strict';
import { scanToolArguments } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('scanToolArguments accepts empty input', () => {
  const r = scanToolArguments(null, HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 0);
});

test('scans a URL in a value', () => {
  const r = scanToolArguments({ url: 'https://example.com/' }, HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].path, '$.url');
});

test('detects SSRF in nested objects', () => {
  const r = scanToolArguments({
    tool: 'fetch',
    args: { nested: { deep: { url: 'http://127.0.0.1/admin' } } },
  }, HTTP);
  assert.equal(r.ok, false);
  assert.equal(r.rejected, 1);
  assert.equal(r.findings[0].code, 'PRIVATE_IP');
  assert.equal(r.findings[0].path, '$.args.nested.deep.url');
});

test('scans URL values in arrays', () => {
  const r = scanToolArguments({ urls: ['https://example.com/', 'http://169.254.169.254/'] }, HTTP);
  assert.equal(r.ok, false);
  assert.equal(r.findings.length, 2);
});

test('scans bare URL strings', () => {
  const r = scanToolArguments('https://example.com/', HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.findings.length, 1);
});

test('URL in key with safe value is checked', () => {
  const r = scanToolArguments({ 'https://evil.com/': 'harmless' }, HTTP);
  assert.equal(r.ok, true); // key strings are not network destinations
});

test('depth cap prevents infinite recursion', () => {
  let node = { url: 'http://127.0.0.1/' };
  for (let i = 0; i < 20; i += 1) node = { child: node };
  const r = scanToolArguments(node, { ...HTTP, maxDepth: 5 });
  assert.equal(r.ok, true); // deep SSRF not reached due to cap
});

test('node cap is enforced and reported', () => {
  const value = Array.from({ length: 100 }, (_, i) => ({ url: `https://example${i}.com/` }));
  const r = scanToolArguments(value, { ...HTTP, maxNodes: 5 });
  assert.equal(r.truncated, true);
  assert.ok(r.findings.length <= 5);
});

test('cyclic input does not hang', () => {
  const cycle = { url: 'https://example.com/' };
  cycle.self = cycle;
  const r = scanToolArguments(cycle, HTTP);
  assert.equal(r.ok, true);
});

test('non-URL strings are ignored', () => {
  const r = scanToolArguments({ text: 'not a url', scheme: 'mailto:someone@example.com' }, HTTP);
  assert.equal(r.findings.length, 0);
});

test('options can be passed via options key', () => {
  const r = scanToolArguments({ url: 'http://example.com/' }, {
    options: { allowedSchemes: ['https:'] },
  });
  assert.equal(r.ok, false);
  assert.equal(r.findings[0].code, 'UNSAFE_SCHEME');
});

test('scanner findings agree with validateUrl', async () => {
  const { validateUrl } = await import('../src/index.mjs');
  for (const url of ['https://example.com/', 'http://127.0.0.1/', 'ftp://example.com/']) {
    const r = scanToolArguments({ url }, HTTP);
    assert.equal(r.findings[0].ok, validateUrl(url, HTTP).ok);
  }
});
