import test from 'node:test';
import assert from 'node:assert/strict';
import { classifyIp, parseIpv4, normalizeIp, validateUrl } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:'] };

test('parseIpv4 canonical forms', () => {
  assert.equal(parseIpv4('127.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('8.8.8.8'), '8.8.8.8');
  assert.equal(parseIpv4('1.2.3.4'), '1.2.3.4');
  assert.equal(parseIpv4('0.0.0.0'), '0.0.0.0');
});

test('parseIpv4 decimal integer forms', () => {
  assert.equal(parseIpv4('2130706433'), '127.0.0.1');
  assert.equal(parseIpv4('3232235777'), '192.168.1.1');
  assert.equal(parseIpv4('0'), '0.0.0.0');
  assert.equal(parseIpv4('4294967295'), '255.255.255.255');
  assert.equal(parseIpv4('4294967296'), null);
  assert.equal(parseIpv4('-1'), null);
});

test('parseIpv4 hex forms', () => {
  assert.equal(parseIpv4('0x7f000001'), '127.0.0.1');
  assert.equal(parseIpv4('0X7F000001'), '127.0.0.1');
  assert.equal(parseIpv4('0x7f.1'), '127.0.0.1');
  assert.equal(parseIpv4('0xc0a80101'), '192.168.1.1');
});

test('parseIpv4 octal forms', () => {
  assert.equal(parseIpv4('0177.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('0o177.0.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('0b1111111000000000000000000000001'), '127.0.0.1');
  assert.equal(parseIpv4('010.0.0.1'), '8.0.0.1');
});

test('parseIpv4 shorthand forms', () => {
  assert.equal(parseIpv4('127.1'), '127.0.0.1');
  assert.equal(parseIpv4('127.0.1'), '127.0.0.1');
  assert.equal(parseIpv4('10.1'), '10.0.0.1');
  assert.equal(parseIpv4('192.168.1'), '192.168.0.1');
});

test('parseIpv4 rejects invalid forms', () => {
  for (const bad of ['256.1.1.1', '1.2.3.4.5', '1..2', 'abc', '', '1.2.3.-1', '0xGG']) {
    assert.equal(parseIpv4(bad), null, bad);
  }
});

test('classifyIp private IPv4 ranges', () => {
  const expectations = {
    '127.0.0.1': 'loopback', '127.1': 'loopback', '2130706433': 'loopback',
    '0177.0.0.1': 'loopback', '0x7f000001': 'loopback',
    '10.0.0.1': 'private-10', '172.16.0.1': 'private-172',
    '172.31.255.255': 'private-172', '192.168.1.1': 'private-192',
    '169.254.169.254': 'cloud-metadata', '169.254.1.1': 'link-local',
    '100.64.0.1': 'cgnat', '100.127.255.254': 'cgnat',
    '100.100.100.200': 'alibaba-metadata',
    '224.0.0.1': 'multicast', '239.255.255.255': 'multicast',
    '198.18.0.1': 'benchmark', '192.0.2.1': 'documentation-1',
    '198.51.100.1': 'documentation-2', '203.0.113.1': 'documentation-3',
    '0.0.0.0': 'unspecified', '255.255.255.255': 'broadcast',
    '240.0.0.1': 'blackhole-240',
    '8.8.8.8': 'public', '1.1.1.1': 'public',
  };
  for (const [ip, expected] of Object.entries(expectations)) {
    assert.equal(classifyIp(ip), expected, ip);
  }
});

test('classifyIp rejects invalid addresses', () => {
  assert.equal(classifyIp('not-an-ip'), 'invalid');
  assert.equal(classifyIp(''), 'invalid');
  assert.equal(classifyIp('256.1.1.1'), 'invalid');
});

test('normalizeIp canonicalizes odd IPv4 forms', () => {
  assert.equal(normalizeIp('2130706433'), '127.0.0.1');
  assert.equal(normalizeIp('0177.0.0.1'), '127.0.0.1');
  assert.equal(normalizeIp('0x7f000001'), '127.0.0.1');
  assert.equal(normalizeIp('127.1'), '127.0.0.1');
  assert.equal(normalizeIp('example.com'), null);
});

test('validateUrl blocks all odd IPv4 representations', () => {
  for (const url of [
    'http://2130706433/', 'http://0177.0.0.1/', 'http://0x7f000001/',
    'http://127.1/', 'http://0/', 'http://10.0.0.1/', 'http://169.254.169.254/',
    'http://100.100.100.200/', 'http://100.64.0.1/', 'http://192.0.2.1/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'PRIVATE_IP', url);
  }
});

test('leading-zero forms are decoded consistently, never smuggled past policy', () => {
  // Octal 0177.0.0.1 is 127.0.0.1 and must be blocked.
  assert.equal(classifyIp('127.000.000.001'), 'loopback');
  assert.equal(classifyIp('0177.0.0.1'), 'loopback');
  // WHATWG normalizes these consistently: 127.000.000.001 -> 127.0.0.1, blocked.
  assert.equal(validateUrl('http://127.000.000.001/', HTTP).code, 'PRIVATE_IP');
  assert.equal(validateUrl('http://0177.0.0.1/', HTTP).code, 'PRIVATE_IP');
  // 00127.0.0.1 is octal 87.0.0.1 (public); it decodes identically in both parsers.
  assert.equal(validateUrl('http://00127.0.0.1/', HTTP).ok, true);
});
