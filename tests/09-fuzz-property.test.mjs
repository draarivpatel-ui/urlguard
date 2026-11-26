import test from 'node:test';
import assert from 'node:assert/strict';
import { validateUrl, assertSafeUrl, classifyIp, UrlGuardError } from '../src/index.mjs';

// Deterministic pseudo-random generator (seeded, no dependencies).
function makeRng(seed) {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

const HTTP = { allowedSchemes: ['http:', 'https:'] };
const SCHEMES = ['https', 'http', 'HTTP', 'HTTPS', 'file', 'gopher', 'data', 'ftp', 'ws', 'javascript'];
const HOSTS = [
  'example.com', 'sub.example.com', '127.0.0.1', '2130706433', '0177.0.0.1',
  '0x7f000001', '127.1', '169.254.169.254', '10.0.0.1', '100.64.0.1',
  'localhost', 'metadata.google.internal', '[::1]', '[::ffff:127.0.0.1]',
  '[2002:7f00:1::]', '[64:ff9b::7f00:1]', '[2606:4700:4700::1111]',
  '0', '8.8.8.8', '192.0.2.1', 'evil.com', 'good.com',
];
const PORTS = ['', ':80', ':443', ':8080', ':0', ':65536'];
const PATHS = ['', '/', '/path', '/a?b=c', '/%2e%2e/', '/admin'];

function makeUrl(rng) {
  const scheme = SCHEMES[Math.floor(rng() * SCHEMES.length)];
  const host = HOSTS[Math.floor(rng() * HOSTS.length)];
  const port = PORTS[Math.floor(rng() * PORTS.length)];
  const path = PATHS[Math.floor(rng() * PATHS.length)];
  return `${scheme}://${host}${port}${path}`;
}

test('fuzz: 500 mutated URLs never throw', () => {
  const rng = makeRng(0xC0FFEE);
  for (let i = 0; i < 500; i += 1) {
    const url = makeUrl(rng);
    assert.doesNotThrow(() => validateUrl(url, HTTP), url);
  }
});

test('fuzz: validateUrl is deterministic', () => {
  const rng = makeRng(42);
  for (let i = 0; i < 200; i += 1) {
    const url = makeUrl(rng);
    const a = validateUrl(url, HTTP);
    const b = validateUrl(url, HTTP);
    assert.deepEqual(a, b, url);
  }
});

test('fuzz: assertSafeUrl and validateUrl agree', () => {
  const rng = makeRng(1337);
  for (let i = 0; i < 200; i += 1) {
    const url = makeUrl(rng);
    const result = validateUrl(url, HTTP);
    if (result.ok) {
      assert.doesNotThrow(() => assertSafeUrl(url, HTTP), url);
    } else {
      assert.throws(() => assertSafeUrl(url, HTTP), (e) =>
        e instanceof UrlGuardError && e.code === result.code, url);
    }
  }
});

test('fuzz: hostile string mutations never leak or throw', () => {
  const rng = makeRng(9999);
  const chars = ['\u0000', '\t', '\n', '\r', '\\', '%', '@', ':', '[', ']', '#', '?', ' ', '\u007f'];
  for (let i = 0; i < 200; i += 1) {
    let url = makeUrl(rng);
    const pos = Math.floor(rng() * url.length);
    url = url.slice(0, pos) + chars[Math.floor(rng() * chars.length)] + url.slice(pos);
    const result = validateUrl(url, HTTP);
    assert.equal(typeof result.ok, 'boolean');
    if (!result.ok) {
      assert.doesNotMatch(result.detail, /\bAt\s+\/|\bnode_modules\b/);
    }
  }
});

test('property: every allowed IP-literal URL classifies as public', () => {
  const rng = makeRng(2026);
  for (let i = 0; i < 200; i += 1) {
    const octets = Array.from({ length: 4 }, () => Math.floor(rng() * 256));
    const ip = octets.join('.');
    const result = validateUrl(`http://${ip}/`, HTTP);
    if (result.ok) assert.equal(classifyIp(ip), 'public', ip);
    else assert.notEqual(classifyIp(ip), 'public', ip);
  }
});

test('property: private IP hosts are never accepted', () => {
  const privateHosts = [
    '127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.1.1', '169.254.169.254',
    '100.100.100.200', '100.64.0.1', '224.0.0.1', '0.0.0.0', '192.0.2.1',
    '[::1]', '[::]', '[::ffff:127.0.0.1]', '[fd00::1]', '[fe80::1]',
  ];
  for (const host of privateHosts) {
    assert.equal(validateUrl(`http://${host}/`, HTTP).ok, false, host);
  }
});

test('property: error codes are from the stable set', () => {
  const allowed = new Set([
    'INVALID_URL', 'UNSAFE_SCHEME', 'USERINFO_FORBIDDEN', 'PRIVATE_IP',
    'DNS_REBIND', 'HOST_DENIED', 'HOST_NOT_ALLOWED', 'PORT_FORBIDDEN',
    'TOO_MANY_HOPS', 'REDIRECT_LOOP', 'INPUT_TOO_LARGE', 'UNSUPPORTED_IDNA',
    'RESOLUTION_FAILED',
  ]);
  const rng = makeRng(555);
  for (let i = 0; i < 200; i += 1) {
    const result = validateUrl(makeUrl(rng), HTTP);
    if (!result.ok) assert.ok(allowed.has(result.code), result.code);
  }
});
