import test from 'node:test';
import assert from 'node:assert/strict';
import { validateUrl, isPublicHostname, createGuard } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('rejects backslash separators', () => {
  for (const url of [
    'https://example.com\\@evil.com/', 'https://example.com\\evil/',
    'http:\\\\example.com/', 'https://user\\@example.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'INVALID_URL', url);
  }
});

test('rejects userinfo and credentials', () => {
  for (const url of [
    'https://user:pass@example.com/', 'https://user@example.com/',
    'https://good.com@evil.com/', 'https://a:b:c@example.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'USERINFO_FORBIDDEN', url);
  }
});

test('allowUserinfo opt-in works', () => {
  assert.equal(validateUrl('https://user:pass@example.com/', { ...HTTP, allowUserinfo: true }).ok, true);
});

test('rejects encoded host characters', () => {
  assert.equal(validateUrl('https://example%2ecom/', HTTP).code, 'INVALID_URL');
  assert.equal(validateUrl('https://example.com%2f.evil.com/', HTTP).code, 'INVALID_URL');
});

test('rejects unicode hostnames by default, allows opt-in', () => {
  assert.equal(validateUrl('https://例え.テスト/', HTTP).code, 'UNSUPPORTED_IDNA');
  assert.equal(validateUrl('https://例え.テスト/', { ...HTTP, idna: 'allow-unicode' }).ok, true);
});

test('trailing dot in hostname is accepted and normalized', () => {
  assert.equal(validateUrl('https://example.com./', HTTP).ok, true);
});

test('empty host is rejected', () => {
  assert.equal(validateUrl('https:///path', HTTP).ok, false);
});

test('oversized hostname and labels are rejected', () => {
  const longLabel = `https://${'a'.repeat(64)}.com/`;
  assert.equal(validateUrl(longLabel, HTTP).code, 'INVALID_URL');
  const longHost = `https://${'a.'.repeat(140)}com/`;
  assert.equal(validateUrl(longHost, HTTP).code, 'INVALID_URL');
});

test('localhost and metadata hostnames are denied', () => {
  for (const host of [
    'localhost', 'metadata', 'metadata.google.internal', 'metadata.goog',
    'metadata.azure.com', 'instance-data', 'foo.internal', 'foo.localhost',
    'foo.local', 'foo.home.arpa',
  ]) {
    assert.equal(validateUrl(`https://${host}/`, HTTP).code, 'HOST_DENIED', host);
  }
});

test('default ports are accepted', () => {
  assert.equal(validateUrl('https://example.com:443/', HTTP).ok, true);
  assert.equal(validateUrl('http://example.com:80/', HTTP).ok, true);
  assert.equal(validateUrl('https://example.com:8443/', HTTP).code, 'PORT_FORBIDDEN');
});

test('port 0 and out-of-range ports are rejected', () => {
  assert.equal(validateUrl('http://example.com:0/', HTTP).code, 'PORT_FORBIDDEN');
  assert.equal(validateUrl('http://example.com:65536/', HTTP).ok, false);
});

test('allowedPorts array', () => {
  const opts = { ...HTTP, allowedPorts: [8443] };
  assert.equal(validateUrl('https://example.com:8443/', opts).ok, true);
  assert.equal(validateUrl('https://example.com/', opts).code, 'PORT_FORBIDDEN');
});

test('allowedPorts any', () => {
  const opts = { ...HTTP, allowedPorts: 'any' };
  assert.equal(validateUrl('https://example.com:8443/', opts).ok, true);
});

test('host allow list', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['example.com'] } };
  assert.equal(validateUrl('https://example.com/', opts).ok, true);
  assert.equal(validateUrl('https://sub.example.com/', opts).ok, true);
  assert.equal(validateUrl('https://evil.com/', opts).code, 'HOST_NOT_ALLOWED');
  assert.equal(validateUrl('https://evil-example.com/', opts).code, 'HOST_NOT_ALLOWED');
});

test('host deny takes precedence over allow', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['example.com'], deny: ['admin.example.com'] } };
  assert.equal(validateUrl('https://admin.example.com/', opts).code, 'HOST_DENIED');
});

test('wildcard host patterns', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['*.example.com'] } };
  assert.equal(validateUrl('https://api.example.com/', opts).ok, true);
  assert.equal(validateUrl('https://example.com/', opts).ok, true);
  assert.equal(validateUrl('https://notexample.com/', opts).code, 'HOST_NOT_ALLOWED');
});

test('public suffix allowlist requires explicit opt-in', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['com'] } };
  assert.equal(validateUrl('https://example.com/', opts).code, 'HOST_NOT_ALLOWED');
  const permissive = { ...HTTP, hostPolicy: { allow: ['com'], allowPublicSuffix: true } };
  assert.equal(validateUrl('https://example.com/', permissive).ok, true);
});

test('isPublicHostname checks hostname policy', () => {
  assert.equal(isPublicHostname('example.com', HTTP), true);
  assert.equal(isPublicHostname('127.0.0.1', HTTP), false);
  assert.equal(isPublicHostname('localhost', HTTP), false);
  assert.equal(isPublicHostname('', HTTP), false);
});

test('custom CIDR allow and deny', () => {
  const deny = { ...HTTP, denyCidrs: ['8.8.8.0/24'] };
  assert.equal(validateUrl('https://8.8.8.8/', deny).code, 'HOST_DENIED');
  const allow = { ...HTTP, allowCidrs: ['1.1.1.0/24'] };
  assert.equal(validateUrl('https://1.1.1.1/', allow).ok, true);
  assert.equal(validateUrl('https://8.8.8.8/', allow).code, 'HOST_NOT_ALLOWED');
});

test('createGuard compiles a reusable policy', () => {
  const guard = createGuard({ ...HTTP, hostPolicy: { allow: ['example.com'] } });
  assert.equal(guard.validate('https://example.com/').ok, true);
  assert.throws(() => guard.assert('https://evil.com/'));
  assert.equal(guard.isPublicHostname('example.com'), true);
  assert.equal(Object.isFrozen(guard.options), true);
});
