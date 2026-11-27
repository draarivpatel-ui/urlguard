import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';

import { UrlGuardError, assertSafeUrl, classifyIp, validateUrl } from '../src/index.mjs';

const HTTP = Object.freeze({ allowedSchemes: ['http:', 'https:'] });
const HTTPS_ONLY = Object.freeze({ allowedSchemes: ['https:'] });
const LABEL_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('');
const PATH_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.split('');

function stringFrom(chars, minLength, maxLength) {
  return fc.array(fc.constantFrom(...chars), { minLength, maxLength }).map((items) => items.join(''));
}

const publicHost = stringFrom(LABEL_CHARS, 1, 10).map((label) => 'app' + label + '.example.com');
const safePath = fc.array(stringFrom(PATH_CHARS, 1, 10), { minLength: 0, maxLength: 3 })
  .map((parts) => parts.length === 0 ? '/' : '/' + parts.join('/'));

test('positive: valid public HTTPS hostnames are accepted and normalized', () => {
  fc.assert(fc.property(publicHost, safePath, (host, urlPath) => {
    const input = 'https://' + host + urlPath;
    const result = validateUrl(input, HTTPS_ONLY);
    assert.equal(result.ok, true);
    assert.equal(result.hostname, host);
    assert.equal(result.port, 443);
    assert.equal(typeof result.normalized, 'string');
    assert.doesNotThrow(() => assertSafeUrl(input, HTTPS_ONLY));
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: private, loopback and metadata IP forms are rejected', () => {
  const octet = fc.integer({ min: 0, max: 255 });
  const privateIp = fc.oneof(
    fc.tuple(octet, octet, octet).map(([b, c, d]) => '10.' + b + '.' + c + '.' + d),
    fc.tuple(octet, octet).map(([c, d]) => '192.168.' + c + '.' + d),
    fc.tuple(fc.integer({ min: 16, max: 31 }), octet, octet).map(([b, c, d]) => '172.' + b + '.' + c + '.' + d),
    fc.tuple(octet, octet, octet).map(([b, c, d]) => '127.' + b + '.' + c + '.' + d),
    fc.constant('169.254.169.254'),
    fc.constant('100.64.0.1'),
    fc.constant('2130706433'),
    fc.constant('0177.0.0.1'),
    fc.constant('0x7f000001')
  );
  fc.assert(fc.property(privateIp, (ip) => {
    const result = validateUrl('http://' + ip + '/', HTTP);
    assert.equal(result.ok, false);
    assert.equal(result.code, 'PRIVATE_IP');
    assert.notEqual(classifyIp(ip), 'public');
    assert.throws(() => assertSafeUrl('http://' + ip + '/', HTTP), (error) => {
      return error instanceof UrlGuardError && error.code === 'PRIVATE_IP';
    });
  }), { seed: 20261127, numRuns: 120 });
});

test('negative: unsafe schemes, credentials, controls and backslashes are rejected', () => {
  const hostile = fc.oneof(
    publicHost.map((host) => 'javascript:alert(1)//' + host),
    publicHost.map((host) => 'file:///' + host),
    publicHost.map((host) => 'https://user:pass@' + host + '/'),
    publicHost.map((host) => 'https://' + host + '/\u0000'),
    publicHost.map((host) => 'https://' + host + '\\admin'),
    publicHost.map((host) => '//' + host + '/')
  );
  fc.assert(fc.property(hostile, (input) => {
    const result = validateUrl(input, HTTPS_ONLY);
    assert.equal(result.ok, false);
    assert.ok(['UNSAFE_SCHEME', 'USERINFO_FORBIDDEN', 'INVALID_URL'].includes(result.code));
    assert.throws(() => assertSafeUrl(input, HTTPS_ONLY), UrlGuardError);
  }), { seed: 20261127, numRuns: 100 });
});

test('negative: mutated URLs never throw and throwing and non-throwing APIs agree', () => {
  const scheme = fc.constantFrom('https', 'http', 'file', 'javascript', 'HTTPS');
  const port = fc.constantFrom('', ':443', ':80', ':0', ':65536');
  const mutation = fc.constantFrom('', '%', '@', '[', ']', '\\', ' ', '\n');
  fc.assert(fc.property(scheme, publicHost, port, safePath, mutation, (schemeName, host, portText, urlPath, tail) => {
    const input = schemeName + '://' + host + portText + urlPath + tail;
    const result = validateUrl(input, HTTP);
    assert.equal(typeof result.ok, 'boolean');
    if (result.ok) {
      assert.doesNotThrow(() => assertSafeUrl(input, HTTP));
    } else {
      assert.throws(() => assertSafeUrl(input, HTTP), (error) => {
        return error instanceof UrlGuardError && error.code === result.code;
      });
    }
  }), { seed: 20261127, numRuns: 120 });
});
