import test from 'node:test';
import assert from 'node:assert/strict';
import { validateUrl, assertSafeUrl, UrlGuardError } from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };

test('https is the default allowed scheme', () => {
  const r = validateUrl('https://example.com/');
  assert.equal(r.ok, true);
  assert.equal(r.url.protocol, 'https:');
  assert.equal(r.port, 443);
  assert.equal(r.ipClass, 'invalid'); // hostname, not an IP literal
});

test('http is opt-in', () => {
  assert.equal(validateUrl('http://example.com/').code, 'UNSAFE_SCHEME');
  assert.equal(validateUrl('http://example.com/', HTTP).ok, true);
});

test('scheme case normalization', () => {
  assert.equal(validateUrl('HTTPS://example.com/').ok, true);
  assert.equal(validateUrl('HTTP://example.com/', HTTP).ok, true);
  assert.equal(validateUrl('HtTp://example.com/', HTTP).ok, true);
});

test('rejects file, gopher, data, javascript, ftp, ws and custom schemes', () => {
  for (const url of [
    'file:///etc/passwd', 'gopher://example.com/', 'data:text/html,x',
    'javascript:alert(1)', 'ftp://example.com/', 'ws://example.com/',
    'wss://example.com/', 'custom://example.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'UNSAFE_SCHEME', url);
  }
});

test('rejects scheme-relative URLs', () => {
  assert.equal(validateUrl('//example.com/', HTTP).code, 'INVALID_URL');
});

test('rejects empty scheme and malformed URLs', () => {
  for (const url of ['', '://example.com', 'example.com', 'https://', 'http:///path']) {
    assert.equal(validateUrl(url, HTTP).ok, false, url);
  }
});

test('rejects control characters in scheme and host', () => {
  for (const url of [
    'https://example.com/\u0000', 'https://exa\u0001mple.com/',
    'https://example.com/\u001f', 'https://example.com/\u007f',
    'http\tps://example.com/', 'https://example.com\n.evil.com/',
  ]) {
    assert.equal(validateUrl(url, HTTP).code, 'INVALID_URL', url);
  }
});

test('rejects whitespace-prefixed and trailing-whitespace URLs', () => {
  for (const url of [' https://example.com/', 'https://example.com/ ', '\thttps://example.com/']) {
    assert.equal(validateUrl(url, HTTP).code, 'INVALID_URL', url);
  }
});

test('rejects null bytes', () => {
  assert.equal(validateUrl('https://example.com/\u0000', HTTP).code, 'INVALID_URL');
});

test('assertSafeUrl throws typed errors with stable codes', () => {
  assert.throws(
    () => assertSafeUrl('file:///etc/passwd', HTTP),
    (error) => error instanceof UrlGuardError && error.code === 'UNSAFE_SCHEME'
      && error.name === 'UrlGuardError' && typeof error.reason === 'string'
  );
});

test('error reason and input never include raw control chars or credentials', () => {
  try {
    assertSafeUrl('https://user:secret@example.com/\u0000', HTTP);
    assert.fail('should throw');
  } catch (error) {
    assert.match(error.input, /\[redacted\]@/);
    assert.doesNotMatch(error.input, /secret/);
    assert.doesNotMatch(error.input, /\u0000/);
  }
});

test('error stack has no internal frames', () => {
  try {
    assertSafeUrl('ftp://x/', HTTP);
  } catch (error) {
    assert.ok(error.stack.startsWith('UrlGuardError [UNSAFE_SCHEME]:'));
    assert.doesNotMatch(error.stack, /\s+at\s+/);
  }
});

test('error toJSON is stable', () => {
  const error = new UrlGuardError('PRIVATE_IP', 'blocked', 'http://127.0.0.1/');
  assert.deepEqual(Object.keys(error.toJSON()).sort(), ['code', 'input', 'name', 'reason']);
});

test('oversized input is rejected with INPUT_TOO_LARGE', () => {
  const big = `https://example.com/${'a'.repeat(9000)}`;
  assert.equal(validateUrl(big, HTTP).code, 'INPUT_TOO_LARGE');
  assert.equal(validateUrl(big, { ...HTTP, maxInputLength: 10000 }).ok, true);
});

test('non-string input never throws', () => {
  for (const input of [null, undefined, 42, {}, [], Symbol('x'), { toString() { throw new Error('evil'); } }]) {
    assert.equal(validateUrl(input, HTTP).ok, false);
  }
});
