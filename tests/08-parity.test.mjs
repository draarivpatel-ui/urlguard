import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import * as esm from '../src/index.mjs';

const require = createRequire(import.meta.url);
const cjs = require('../cjs/index.cjs');

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('CJS and ESM expose the same export names', () => {
  assert.deepEqual(
    Object.keys(cjs).sort(),
    Object.keys(esm).sort()
  );
});

test('classifyIp parity across all tricky forms', () => {
  const hosts = [
    '127.0.0.1', '2130706433', '0177.0.0.1', '0x7f000001', '127.1',
    '::1', '::', '::ffff:127.0.0.1', '::ffff:7f00:1', '2002:7f00:1::',
    '64:ff9b::7f00:1', 'fd00:ec2::254', '169.254.169.254', '8.8.8.8',
    'example.com', 'not-an-ip',
  ];
  for (const host of hosts) {
    assert.equal(cjs.classifyIp(host), esm.classifyIp(host), host);
  }
});

test('validateUrl parity across bypass matrix', () => {
  const urls = [
    'https://example.com/', 'http://example.com/', 'file:///etc/passwd',
    'https://user:pass@example.com/', 'http://2130706433/', 'http://0177.0.0.1/',
    'http://0x7f000001/', 'http://127.1/', 'http://[::ffff:127.0.0.1]/',
    'http://[2002:7f00:1::]/', 'http://[64:ff9b::7f00:1]/',
    'https://metadata.google.internal/', 'http://example.com\\@evil.com/',
  ];
  for (const url of urls) {
    const a = esm.validateUrl(url, HTTP);
    const b = cjs.validateUrl(url, HTTP);
    assert.equal(a.ok, b.ok, url);
    assert.equal(a.ok ? a.normalized : a.code, b.ok ? b.normalized : b.code, url);
  }
});

test('parseIpv4 and parseIpv6 parity', () => {
  for (const value of ['127.1', '2130706433', '0177.0.0.1', '0x7f000001', '8.8.8.8', '256.1.1.1']) {
    assert.equal(cjs.parseIpv4(value), esm.parseIpv4(value), value);
  }
  for (const value of ['::1', '::ffff:7f00:1', '2002:7f00:1::', '1:2:3']) {
    assert.deepEqual(cjs.parseIpv6(value), esm.parseIpv6(value), value);
  }
});

test('CIDR helpers parity', () => {
  for (const [cidr, ip] of [['10.0.0.0/8', '10.1.2.3'], ['10.0.0.0/8', '8.8.8.8'], ['fd00::/8', 'fd00::1']]) {
    assert.equal(cjs.cidrContains(cidr, ip), esm.cidrContains(cidr, ip));
  }
});

test('UrlGuardError class works in both module systems', () => {
  const a = new esm.UrlGuardError('PRIVATE_IP', 'blocked', 'http://127.0.0.1/');
  const b = new cjs.UrlGuardError('PRIVATE_IP', 'blocked', 'http://127.0.0.1/');
  assert.deepEqual(a.toJSON(), b.toJSON());
});

test('createSafeFetch is a function in both', async () => {
  assert.equal(typeof cjs.createSafeFetch, 'function');
  const fetchImpl = async () => ({ status: 200, headers: { get: () => null } });
  const cjsFetch = cjs.createSafeFetch({ ...HTTP, fetch: fetchImpl });
  const esmFetch = esm.createSafeFetch({ ...HTTP, fetch: fetchImpl });
  assert.equal((await cjsFetch('https://example.com/')).status, 200);
  assert.equal((await esmFetch('https://example.com/')).status, 200);
});

test('validateRedirectChain parity', async () => {
  const chain = ['https://example.com/', 'https://sub.example.com/'];
  const a = await esm.validateRedirectChain(chain, HTTP);
  const b = await cjs.validateRedirectChain(chain, HTTP);
  assert.equal(a.ok, b.ok);
  assert.equal(a.finalUrl, b.finalUrl);
});

test('scanToolArguments parity', () => {
  const payload = { args: { url: 'http://127.0.0.1/' } };
  const a = esm.scanToolArguments(payload, HTTP);
  const b = cjs.scanToolArguments(payload, HTTP);
  assert.equal(a.ok, b.ok);
  assert.equal(a.findings[0].code, b.findings[0].code);
});

test('runtime/node adapter parity', async () => {
  const nodeEsm = await import('../src/runtime-node.mjs');
  const nodeCjs = require('../cjs/runtime-node.cjs');
  assert.equal(typeof nodeEsm.nodeResolve, 'function');
  assert.equal(typeof nodeCjs.nodeResolve, 'function');
});
