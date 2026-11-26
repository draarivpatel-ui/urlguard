import test from 'node:test';
import assert from 'node:assert/strict';
import { validateRedirectChain, createSafeFetch, UrlGuardError } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('single-hop chain', async () => {
  const r = await validateRedirectChain(['https://example.com/'], HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.hops.length, 1);
  assert.equal(r.finalUrl, 'https://example.com/');
});

test('multi-hop chain', async () => {
  const r = await validateRedirectChain([
    'https://example.com/', 'https://sub.example.com/', 'https://other.com/final',
  ], HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.hops.length, 3);
  assert.equal(r.hops[2].crossOrigin, true);
});

test('empty chain is rejected', async () => {
  const r = await validateRedirectChain([], HTTP);
  assert.equal(r.ok, false);
  assert.equal(r.code, 'INVALID_URL');
});

test('too many hops are rejected', async () => {
  const urls = Array.from({ length: 8 }, (_, i) => `https://example${i}.com/`);
  const r = await validateRedirectChain(urls, { ...HTTP, maxRedirects: 5 });
  assert.equal(r.code, 'TOO_MANY_HOPS');
});

test('redirect loop is detected', async () => {
  const r = await validateRedirectChain([
    'https://example.com/a', 'https://example.com/b', 'https://example.com/a',
  ], HTTP);
  assert.equal(r.code, 'REDIRECT_LOOP');
});

test('private IP in any hop is rejected', async () => {
  const r = await validateRedirectChain([
    'https://example.com/', 'http://127.0.0.1/admin',
  ], HTTP);
  assert.equal(r.code, 'PRIVATE_IP');
  assert.equal(r.hop, 1);
});

test('scheme downgrade is checked against allowlist', async () => {
  const r = await validateRedirectChain(['https://example.com/', 'http://example.com/'], HTTP);
  assert.equal(r.ok, true);
  const strict = await validateRedirectChain(['https://example.com/', 'http://example.com/'], { allowedSchemes: ['https:'] });
  assert.equal(strict.code, 'UNSAFE_SCHEME');
});

test('relative URL in chain is rejected (must be absolute)', async () => {
  const r = await validateRedirectChain(['https://example.com/', '/relative'], HTTP);
  assert.equal(r.ok, false);
});

test('DNS results are attached to each hop', async () => {
  const r = await validateRedirectChain(['https://example.com/'], {
    ...HTTP, dns: async () => ['93.184.216.34'],
  });
  assert.equal(r.ok, true);
  assert.deepEqual(r.hops[0].addresses, ['93.184.216.34']);
});

function fakeResponse(status, location) {
  return {
    status,
    headers: { get: (name) => name.toLowerCase() === 'location' ? location : null },
  };
}

test('createSafeFetch calls injected fetch for safe URL', async () => {
  const calls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, init) => { calls.push({ url, init }); return fakeResponse(200); },
  });
  const response = await safeFetch('https://example.com/');
  assert.equal(response.status, 200);
  assert.equal(calls.length, 1);
});

test('createSafeFetch strips credentials and forces manual redirects', async () => {
  let captured;
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, init) => { captured = init; return fakeResponse(200); },
  });
  await safeFetch('https://example.com/', {
    credentials: 'include',
    headers: { Authorization: 'Bearer secret', Cookie: 'session=x', 'X-Safe': '1' },
  });
  assert.equal(captured.credentials, undefined);
  assert.equal(captured.headers.get('authorization'), null);
  assert.equal(captured.headers.get('cookie'), null);
  assert.equal(captured.headers.get('x-safe'), '1');
  assert.equal(captured.redirect, 'manual');
});

test('createSafeFetch follows and validates redirect chain', async () => {
  const urls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url) => {
      urls.push(url);
      if (url === 'https://example.com/') return fakeResponse(302, 'https://sub.example.com/');
      return fakeResponse(200);
    },
  });
  const response = await safeFetch('https://example.com/');
  assert.equal(response.status, 200);
  assert.deepEqual(urls, ['https://example.com/', 'https://sub.example.com/']);
});

test('createSafeFetch blocks redirect to private IP', async () => {
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url) => url.startsWith('https://example.com')
      ? fakeResponse(302, 'http://127.0.0.1/admin')
      : fakeResponse(200),
  });
  await assert.rejects(() => safeFetch('https://example.com/'), (e) =>
    e instanceof UrlGuardError && e.code === 'PRIVATE_IP');
});

test('createSafeFetch enforces max redirect hops', async () => {
  let count = 0;
  const safeFetch = createSafeFetch({
    ...HTTP, maxRedirects: 2,
    fetch: async () => { count += 1; return fakeResponse(302, `https://example.com/${count}`); },
  });
  await assert.rejects(() => safeFetch('https://example.com/'), (e) => e.code === 'TOO_MANY_HOPS');
});

test('createSafeFetch blocks unsafe initial URL', async () => {
  let called = false;
  const safeFetch = createSafeFetch({ ...HTTP, fetch: async () => { called = true; } });
  await assert.rejects(() => safeFetch('file:///etc/passwd'), (e) => e.code === 'UNSAFE_SCHEME');
  assert.equal(called, false);
});
