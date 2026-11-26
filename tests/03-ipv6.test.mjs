import test from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyIp, parseIpv6, normalizeIp, mappedIpv4, sixToFourIpv4,
  nat64Ipv4, isTeredo, formatIpv6, validateUrl,
} from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:'] };

test('parseIpv6 basic and compressed forms', () => {
  assert.deepEqual(parseIpv6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIpv6('::'), [0, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(parseIpv6('2001:db8::1'), [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIpv6('0:0:0:0:0:0:0:1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.equal(parseIpv6('1:2:3'), null);
  assert.equal(parseIpv6('1::2::3'), null);
});

test('parseIpv6 with embedded IPv4', () => {
  assert.deepEqual(parseIpv6('::ffff:127.0.0.1'), [0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  assert.deepEqual(parseIpv6('::ffff:7f00:1'), [0, 0, 0, 0, 0, 0xffff, 0x7f00, 1]);
  assert.deepEqual(parseIpv6('64:ff9b::127.0.0.1'), [0x64, 0xff9b, 0, 0, 0, 0, 0x7f00, 1]);
});

test('IPv6 zone IDs are stripped, not trusted', () => {
  assert.deepEqual(parseIpv6('fe80::1%eth0'), [0xfe80, 0, 0, 0, 0, 0, 0, 1]);
  assert.equal(classifyIp('fe80::1%eth0'), 'link-local');
  assert.equal(normalizeIp('fe80::1%eth0'), null); // normalizeIp rejects zone IDs
});

test('mappedIpv4 extracts IPv4-mapped addresses', () => {
  const groups = parseIpv6('::ffff:127.0.0.1');
  assert.equal(mappedIpv4(groups), '127.0.0.1');
  assert.equal(mappedIpv4(parseIpv6('::ffff:c0a8:101')), '192.168.1.1');
  assert.equal(mappedIpv4(parseIpv6('2001:db8::1')), null);
});

test('sixToFourIpv4 extracts 6to4 embedded IPv4', () => {
  assert.equal(sixToFourIpv4(parseIpv6('2002:7f00:1::')), '127.0.0.1');
  assert.equal(sixToFourIpv4(parseIpv6('2002:c0a8:101::')), '192.168.1.1');
  assert.equal(sixToFourIpv4(parseIpv6('2001:db8::1')), null);
});

test('nat64Ipv4 extracts NAT64 embedded IPv4', () => {
  assert.equal(nat64Ipv4(parseIpv6('64:ff9b::127.0.0.1')), '127.0.0.1');
  assert.equal(nat64Ipv4(parseIpv6('64:ff9b::7f00:1')), '127.0.0.1');
  assert.equal(nat64Ipv4(parseIpv6('2001:db8::1')), null);
});

test('isTeredo detects 2001:0000::/32', () => {
  assert.equal(isTeredo(parseIpv6('2001:0:4136:e378:8000:63bf:3fff:fdd2')), true);
  assert.equal(isTeredo(parseIpv6('2001:db8::1')), false);
});

test('formatIpv6 produces RFC 5952 compressed form', () => {
  assert.equal(formatIpv6(parseIpv6('0:0:0:0:0:0:0:1')), '::1');
  assert.equal(formatIpv6(parseIpv6('2001:db8:0:0:0:0:0:1')), '2001:db8::1');
  assert.equal(formatIpv6(parseIpv6('::ffff:7f00:1')), '::ffff:7f00:1');
});

test('classifyIp IPv6 private ranges', () => {
  const expectations = {
    '::1': 'loopback', '::': 'unspecified',
    '::ffff:127.0.0.1': 'loopback', '::ffff:7f00:1': 'loopback',
    '::ffff:192.168.1.1': 'private-192', '::ffff:a9fe:a9fe': 'cloud-metadata',
    '2002:7f00:1::': 'loopback', '2002:c0a8:101::': 'private-192',
    '64:ff9b::127.0.0.1': 'loopback', '64:ff9b::7f00:1': 'loopback',
    'fe80::1': 'link-local', 'fc00::1': 'unique-local', 'fd00::1': 'unique-local',
    'fd00:ec2::254': 'unique-local', 'ff02::1': 'multicast',
    '2001:db8::1': 'documentation', '2001:2::1': 'benchmark',
    '2001:0:4136:e378:8000:63bf:3fff:fdd2': 'private',
    '2606:4700:4700::1111': 'public', '2001:4860:4860::8888': 'public',
  };
  for (const [ip, expected] of Object.entries(expectations)) {
    assert.equal(classifyIp(ip), expected, ip);
  }
});

test('validateUrl blocks IPv6 bypass vectors', () => {
  for (const url of [
    'http://[::1]/', 'http://[::]/', 'http://[::ffff:127.0.0.1]/',
    'http://[::ffff:7f00:1]/', 'http://[::ffff:192.168.1.1]/',
    'http://[2002:7f00:1::]/', 'http://[64:ff9b::7f00:1]/',
    'http://[fe80::1]/', 'http://[fd00::1]/', 'http://[ff02::1]/',
    'http://[fd00:ec2::254]/', 'http://[2001:db8::1]/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'PRIVATE_IP', url);
  }
});

test('validateUrl allows public IPv6', () => {
  assert.equal(validateUrl('http://[2606:4700:4700::1111]/', HTTP).ok, true);
});

test('AWS metadata IPv6 full address form', () => {
  // fd00::/8 unique-local overlaps the specific AWS endpoint; both are blocked.
  assert.equal(classifyIp('fd00:ec2:0:0:0:0:0:254'), 'unique-local');
  assert.equal(validateUrl('http://[fd00:ec2::254]/', HTTP).code, 'PRIVATE_IP');
});
