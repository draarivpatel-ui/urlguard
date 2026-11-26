import test from 'node:test';
import assert from 'node:assert/strict';
import { resolveSafe, validateUrl } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('DNS is skipped when no resolver is configured', async () => {
  const r = await resolveSafe('example.com', HTTP);
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
});

test('DNS is skipped with dns: false', async () => {
  const r = await resolveSafe('example.com', { ...HTTP, dns: false });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
});

test('public A records are accepted', async () => {
  const resolver = async () => ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'];
  const r = await resolveSafe('example.com', { ...HTTP, dns: resolver });
  assert.equal(r.ok, true);
  assert.deepEqual(r.addresses, ['2606:2800:220:1:248:1893:25c8:1946', '93.184.216.34']);
});

test('private A records are rejected', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1']) {
    const r = await resolveSafe('example.com', { ...HTTP, dns: async () => [address] });
    assert.equal(r.ok, false, address);
    assert.equal(r.code, 'PRIVATE_IP', address);
  }
});

test('mixed public/private DNS answers are rejected', async () => {
  const r = await resolveSafe('example.com', { ...HTTP, dns: async () => ['93.184.216.34', '127.0.0.1'] });
  assert.equal(r.code, 'PRIVATE_IP');
});

test('resolver returning no addresses is rejected', async () => {
  const r = await resolveSafe('example.com', { ...HTTP, dns: async () => [] });
  assert.equal(r.code, 'RESOLUTION_FAILED');
});

test('resolver throwing or timing out never leaks', async () => {
  for (const resolver of [
    async () => { throw new Error('internal secret path /Users/private'); },
    async () => { throw new Error('query timed out'); },
  ]) {
    const r = await resolveSafe('example.com', { ...HTTP, dns: resolver });
    assert.equal(r.code, 'RESOLUTION_FAILED');
    assert.doesNotMatch(JSON.stringify(r), /Users\/private/);
  }
});

test('resolver object entries with address field are supported', async () => {
  const resolver = async () => [{ address: '93.184.216.34', family: 4 }];
  const r = await resolveSafe('example.com', { ...HTTP, dns: resolver });
  assert.equal(r.ok, true);
});

test('DNS rebinding is detected when answers change', async () => {
  let call = 0;
  const resolver = async () => {
    call += 1;
    return call === 1 ? ['93.184.216.34'] : ['8.8.8.8'];
  };
  const r = await resolveSafe('example.com', {
    ...HTTP, dns: resolver, checkRebinding: true, rebindDelayMs: 0,
  });
  assert.equal(r.code, 'DNS_REBIND');
  assert.equal(call, 2);
});

test('rebinding check passes when answers are identical', async () => {
  const resolver = async () => ['93.184.216.34', '8.8.8.8'];
  const r = await resolveSafe('example.com', {
    ...HTTP, dns: resolver, checkRebinding: true, rebindDelayMs: 0,
  });
  assert.equal(r.ok, true);
  assert.equal(r.pinnedIp, '8.8.8.8');
  assert.deepEqual(r.addresses, ['8.8.8.8', '93.184.216.34']);
});

test('rebinding to a private IP is rejected on the second lookup', async () => {
  let call = 0;
  const resolver = async () => {
    call += 1;
    return call === 1 ? ['93.184.216.34'] : ['127.0.0.1'];
  };
  const r = await resolveSafe('example.com', {
    ...HTTP, dns: resolver, checkRebinding: true, rebindDelayMs: 0,
  });
  assert.equal(r.code, 'PRIVATE_IP');
});

test('validateUrl stays synchronous and never calls DNS', () => {
  let called = false;
  const r = validateUrl('https://example.com/', {
    ...HTTP, dns: async () => { called = true; return ['127.0.0.1']; },
    checkRebinding: true,
  });
  assert.equal(r.ok, true);
  assert.equal(called, false);
});

test('invalid resolver type is rejected without throwing', async () => {
  const r = await resolveSafe('example.com', { ...HTTP, dns: 'not-a-function' });
  assert.equal(r.code, 'RESOLUTION_FAILED');
});
