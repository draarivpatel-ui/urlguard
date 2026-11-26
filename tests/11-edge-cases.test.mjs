import test from 'node:test';
import assert from 'node:assert/strict';
import {
  validateUrl, assertSafeUrl, classifyIp, parseIpv4, parseIpv6,
  isPublicHostname, createGuard, UrlGuardError,
} from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };
const HTTPS = { allowedSchemes: ['https:'] };

// Scheme edge cases
test('uppercase schemes with mixed case host', () => {
  assert.equal(validateUrl('HTTPS://EXAMPLE.COM/', HTTPS).ok, true);
});

test('scheme with plus and dot characters is rejected by default', () => {
  assert.equal(validateUrl('https+x://example.com/', HTTPS).code, 'UNSAFE_SCHEME');
  assert.equal(validateUrl('https.x://example.com/', HTTPS).code, 'UNSAFE_SCHEME');
});

test('custom scheme can be explicitly allowed', () => {
  const r = validateUrl('myapp://example.com/', { allowedSchemes: ['myapp:'] });
  assert.equal(r.ok, true);
  assert.equal(r.port, undefined); // no default port mapping
});

test('scheme normalization deduplicates options', () => {
  const guard = createGuard({ ...HTTP, allowedSchemes: ['HTTPS', 'https:', 'HTTP'] });
  assert.equal(guard.options.allowedSchemes.length, 2);
});

test('input exactly at max length is accepted', () => {
  const base = 'https://example.com/';
  const opts = { ...HTTPS, maxInputLength: base.length };
  assert.equal(validateUrl(base, opts).ok, true);
});

// Host parsing edge cases
test('multiple @ characters in authority', () => {
  assert.equal(validateUrl('https://a@b@example.com/', HTTP).code, 'USERINFO_FORBIDDEN');
});

test('empty username with password', () => {
  assert.equal(validateUrl('https://:pass@example.com/', HTTP).code, 'USERINFO_FORBIDDEN');
});

test('host with consecutive dots is rejected', () => {
  assert.equal(validateUrl('https://example..com/', HTTPS).ok, false);
});

test('IPv6 bracket requirement is enforced', () => {
  assert.equal(validateUrl('http://::1/', HTTP).ok, false);
});

test('fragment-only and query-only strings are invalid URLs', () => {
  for (const url of ['#foo', '?q=1', '/path']) {
    assert.equal(validateUrl(url, HTTP).ok, false);
  }
});

test('URL with empty path is normalized to slash', () => {
  const r = validateUrl('https://example.com', HTTPS);
  assert.equal(r.ok, true);
  assert.equal(r.normalized, 'https://example.com/');
});

// IPv4 edge cases
test('parseIpv4 rejects whitespace around octets', () => {
  for (const ip of [' 127.0.0.1', '127.0.0.1 ', '127 .0.0.1']) {
    assert.equal(parseIpv4(ip), null, ip);
  }
});

test('parseIpv4 rejects plus signs and negative numbers', () => {
  for (const ip of ['+127.0.0.1', '-127.0.0.1', '1.2.3.+4']) {
    assert.equal(parseIpv4(ip), null, ip);
  }
});

test('parseIpv4 handles max uint32', () => {
  assert.equal(parseIpv4('4294967295'), '255.255.255.255');
  assert.equal(parseIpv4('0xffffffff'), '255.255.255.255');
  assert.equal(classifyIp('255.255.255.255'), 'broadcast');
});

test('parseIpv4 rejects too many digits', () => {
  assert.equal(parseIpv4('12345678901234567890'), null);
});

// IPv6 edge cases
test('parseIpv6 rejects invalid group counts', () => {
  for (const ip of ['1:2:3:4:5:6:7', '1:2:3:4:5:6:7:8:9', 'gggg::1']) {
    assert.equal(parseIpv6(ip), null, ip);
  }
});

test('parseIpv6 handles leading and trailing compression', () => {
  assert.deepEqual(parseIpv6('::1'), [0, 0, 0, 0, 0, 0, 0, 1]);
  assert.deepEqual(parseIpv6('1::'), [1, 0, 0, 0, 0, 0, 0, 0]);
});

test('classifyIp IPv4-mapped documentation range', () => {
  assert.equal(classifyIp('::ffff:192.0.2.1'), 'documentation-1');
});

test('6to4 embedded private address is blocked', () => {
  assert.equal(classifyIp('2002:0a00:1::'), 'private-10');
  assert.equal(validateUrl('http://[2002:0a00:1::]/', HTTP).code, 'PRIVATE_IP');
});

// Policy edge cases
test('deny suffix blocks subdomains', () => {
  const opts = { ...HTTPS, hostPolicy: { deny: ['evil.com'] } };
  assert.equal(validateUrl('https://evil.com/', opts).code, 'HOST_DENIED');
  assert.equal(validateUrl('https://sub.evil.com/', opts).code, 'HOST_DENIED');
});

test('suffix confusion is prevented', () => {
  const opts = { ...HTTPS, hostPolicy: { allow: ['good.com'] } };
  assert.equal(validateUrl('https://evil-good.com/', opts).code, 'HOST_NOT_ALLOWED');
});

test('case-insensitive host policy', () => {
  const opts = { ...HTTPS, hostPolicy: { allow: ['EXAMPLE.COM'] } };
  assert.equal(validateUrl('https://example.com/', opts).ok, true);
});

test('CIDR /0 matches everything', () => {
  assert.equal(validateUrl('https://8.8.8.8/', { ...HTTPS, denyCidrs: ['0.0.0.0/0'] }).code, 'HOST_DENIED');
});

test('invalid CIDR entries are ignored safely', () => {
  const r = validateUrl('https://example.com/', { ...HTTPS, denyCidrs: ['not-a-cidr', '10.0.0.0/99'] });
  assert.equal(r.ok, true);
});

test('isPublicHostname rejects metadata names', () => {
  assert.equal(isPublicHostname('metadata.google.internal', HTTPS), false);
  assert.equal(isPublicHostname('foo.internal', HTTPS), false);
});

// Error edge cases
test('UrlGuardError code is enumerable and stable', () => {
  const error = new UrlGuardError('PORT_FORBIDDEN', 'blocked', 'https://example.com:22/');
  assert.equal(error.code, 'PORT_FORBIDDEN');
  assert.equal(Object.keys(error).includes('code'), true);
});

test('error input is truncated for very long hostile strings', () => {
  const long = `https://${'a'.repeat(500)}/`;
  const error = new UrlGuardError('INVALID_URL', 'bad', long);
  assert.ok(error.input.includes('[truncated]'));
  assert.ok(error.input.length < 300);
});

test('assertSafeUrl returns the same shape as validateUrl', () => {
  const r1 = assertSafeUrl('https://example.com/', HTTPS);
  const r2 = validateUrl('https://example.com/', HTTPS);
  assert.deepEqual(r1, r2);
});

test('no raw exceptions from hostile option objects', () => {
  const hostile = [null, 42, 'string', { toString() { throw new Error('evil'); } }];
  for (const opts of hostile) {
    assert.doesNotThrow(() => validateUrl('https://example.com/', opts));
  }
});
