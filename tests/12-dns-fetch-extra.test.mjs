import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateRedirectChain, createSafeFetch, resolveSafe, createGuard,
  UrlGuardError,
} from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('chain DNS failure stops validation', async () => {
  const r = await validateRedirectChain(['https://example.com/'], {
    ...HTTP, dns: async () => { throw new Error('timeout'); },
  });
  assert.equal(r.ok, false);
  assert.equal(r.code, 'RESOLUTION_FAILED');
  assert.equal(r.hop, 0);
});

test('chain rebinding failure stops validation', async () => {
  let call = 0;
  const r = await validateRedirectChain(['https://example.com/'], {
    ...HTTP,
    dns: async () => { call += 1; return call === 1 ? ['8.8.8.8'] : ['1.1.1.1']; },
    checkRebinding: true,
    rebindDelayMs: 0,
  });
  assert.equal(r.code, 'DNS_REBIND');
});

test('chain stops at first unsafe hop', async () => {
  const r = await validateRedirectChain([
    'https://example.com/', 'file:///etc/passwd', 'https://other.com/',
  ], HTTP);
  assert.equal(r.ok, false);
  assert.equal(r.hop, 1);
  assert.equal(r.hops.length, 1);
});

test('chain accepts a string input as single hop', async () => {
  const r = await validateRedirectChain('https://example.com/', HTTP);
  assert.equal(r.ok, true);
});

test('createSafeFetch with DNS pinning calls resolver', async () => {
  let resolved = 0;
  const safeFetch = createSafeFetch({
    ...HTTP,
    dns: async () => { resolved += 1; return ['93.184.216.34']; },
    fetch: async () => ({ status: 200, headers: { get: () => null } }),
  });
  await safeFetch('https://example.com/');
  assert.ok(resolved >= 1);
});

test('createSafeFetch rejects DNS-resolved private IP', async () => {
  let called = false;
  const safeFetch = createSafeFetch({
    ...HTTP,
    dns: async () => ['127.0.0.1'],
    fetch: async () => { called = true; return { status: 200 }; },
  });
  await assert.rejects(() => safeFetch('https://example.com/'), (e) => e.code === 'PRIVATE_IP');
  assert.equal(called, false);
});

test('createSafeFetch strips proxy-authorization and referer', async () => {
  let init;
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, i) => { init = i; return { status: 200, headers: { get: () => null } }; },
  });
  await safeFetch('https://example.com/', {
    headers: { 'Proxy-Authorization': 'Basic secret', Referer: 'https://secret.example/' },
  });
  assert.equal(init.headers.get('proxy-authorization'), null);
  assert.equal(init.headers.get('referer'), null);
});

test('createSafeFetch rejects dangerous redirect location scheme', async () => {
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url) => url === 'https://example.com/'
      ? { status: 301, headers: { get: (n) => n === 'location' ? 'gopher://127.0.0.1/' : null } }
      : { status: 200, headers: { get: () => null } },
  });
  await assert.rejects(() => safeFetch('https://example.com/'), (e) => e.code === 'UNSAFE_SCHEME');
});

test('createSafeFetch preserves non-redirect status responses', async () => {
  for (const status of [201, 204, 400, 404, 500]) {
    const safeFetch = createSafeFetch({
      ...HTTP,
      fetch: async () => ({ status, headers: { get: () => null } }),
    });
    const r = await safeFetch('https://example.com/');
    assert.equal(r.status, status);
  }
});

test('resolveSafe sorts addresses deterministically', async () => {
  const r = await resolveSafe('example.com', {
    ...HTTP, dns: async () => ['9.9.9.9', '1.1.1.1', '8.8.8.8'],
  });
  assert.deepEqual(r.addresses, ['1.1.1.1', '8.8.8.8', '9.9.9.9']);
});

test('resolveSafe handles mixed string and object records', async () => {
  const r = await resolveSafe('example.com', {
    ...HTTP, dns: async () => ['8.8.8.8', { address: '1.1.1.1' }, null, 42],
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.addresses, ['1.1.1.1', '8.8.8.8']);
});

test('guard options are frozen', () => {
  const guard = createGuard(HTTP);
  assert.throws(() => { guard.options.allowedSchemes = []; }, TypeError);
});

test('error code from scanner propagates correctly', async () => {
  const { scanToolArguments } = await import('../src/index.mjs');
  const r = scanToolArguments({ url: 'http://[::ffff:127.0.0.1]/' }, HTTP);
  assert.equal(r.ok, false);
  assert.equal(r.findings[0].code, 'PRIVATE_IP');
});
