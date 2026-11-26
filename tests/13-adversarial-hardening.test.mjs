import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import {
  validateUrl, isPublicHostname, classifyIp, parseIpv6, parseCidr, cidrContains,
  teredoClientIpv4, isTeredo, siitIpv4, ipv4CompatibleIpv4, isNat64LocalUse,
  validateRedirectChain, createSafeFetch, resolveSafe, createGuard,
  scanToolArguments, UrlGuardError,
} from '../src/index.mjs';

const HTTP = { allowedSchemes: ['http:', 'https:'] };
const require = createRequire(import.meta.url);

function fakeResponse(status, location) {
  return {
    status,
    headers: { get: (name) => (name.toLowerCase() === 'location' ? location : null) },
  };
}

test('IPv4-compatible IPv6 (::/96) is not a public destination', () => {
  for (const host of ['::127.0.0.1', '::0:127.0.0.1', '::a9fe:a9fe', '::7f00:1']) {
    assert.notEqual(classifyIp(host), 'public', host);
  }
  for (const url of ['https://[::127.0.0.1]/', 'https://[::0:127.0.0.1]/', 'https://[::a9fe:a9fe]/']) {
    assert.equal(validateUrl(url).code, 'PRIVATE_IP', url);
  }
  assert.equal(classifyIp('::127.0.0.1'), 'loopback');
  assert.equal(classifyIp('::a9fe:a9fe'), 'cloud-metadata');
  assert.equal(ipv4CompatibleIpv4(parseIpv6('::127.0.0.1')), '127.0.0.1');
  assert.equal(ipv4CompatibleIpv4(parseIpv6('::ffff:7f00:1')), null);
});

test('SIIT IPv4-translated IPv6 (::ffff:0:0:0/96) is blocked', () => {
  for (const url of [
    'https://[::ffff:0:127.0.0.1]/', 'https://[::ffff:0:7f00:1]/',
    'https://[::ffff:0:a9fe:a9fe]/', 'https://[::ffff:0:c0a8:101]/',
  ]) {
    assert.equal(validateUrl(url).code, 'PRIVATE_IP', url);
  }
  assert.equal(siitIpv4(parseIpv6('::ffff:0:7f00:1')), '127.0.0.1');
  assert.equal(siitIpv4(parseIpv6('::ffff:0:a9fe:a9fe')), '169.254.169.254');
  assert.equal(siitIpv4(parseIpv6('::ffff:7f00:1')), null);
});

test('NAT64 local-use prefix (64:ff9b:1::/48) is never public', () => {
  for (const url of [
    'https://[64:ff9b:1::7f00:1]/', 'https://[64:ff9b:1::a9fe:a9fe]/',
    'https://[64:ff9b:1::808:808]/',
  ]) {
    assert.equal(validateUrl(url).code, 'PRIVATE_IP', url);
  }
  assert.equal(classifyIp('64:ff9b:1::7f00:1'), 'nat64-local-use');
  assert.equal(isNat64LocalUse(parseIpv6('64:ff9b:1::1')), true);
  assert.equal(isNat64LocalUse(parseIpv6('64:ff9b::1')), false);
});

test('Teredo client IPv4 is decoded with the 0xffffffff XOR', () => {
  const groups = parseIpv6('2001:0:4136:e378:8000:63bf:3fff:fdd2');
  assert.equal(isTeredo(groups), true);
  assert.equal(teredoClientIpv4(groups), '192.0.2.45');
  assert.equal(teredoClientIpv4(parseIpv6('2001:db8::1')), null);
  assert.equal(teredoClientIpv4(null), null);
  assert.equal(validateUrl('https://[2001:0:4136:e378:8000:63bf:3fff:fdd2]/').code, 'PRIVATE_IP');
});

test('uppercase and mixed-case IPv6 hex is still classified', () => {
  assert.equal(validateUrl('https://[::FFFF:7F00:1]/').code, 'PRIVATE_IP');
  assert.equal(validateUrl('https://[2002:A9FE:A9FE::]/').code, 'PRIVATE_IP');
  assert.equal(validateUrl('https://[64:FF9B::A9FE:A9FE]/').code, 'PRIVATE_IP');
});

test('multiple trailing dots cannot smuggle a private address', () => {
  assert.equal(validateUrl('https://127.0.0.1../').code, 'INVALID_URL');
  assert.equal(validateUrl('https://example.com../').code, 'INVALID_URL');
  assert.equal(validateUrl('https://example.com./').ok, true);
  assert.equal(isPublicHostname('127.0.0.1..', HTTP), false);
  assert.equal(isPublicHostname('127.0.0.1.', HTTP), false);
  assert.equal(isPublicHostname('example.com.', HTTP), true);
});

test('unicode dot variants are normalized and still blocked', () => {
  const opts = { ...HTTP, idna: 'allow-unicode' };
  for (const url of ['https://127。0。0。1/', 'https://127．0．0．1/', 'https://127｡0｡0｡1/']) {
    assert.equal(validateUrl(url, opts).code, 'PRIVATE_IP', url);
  }
});

test('bracketed IPv6 with percent-encoded zone is rejected', () => {
  for (const url of [
    'https://[::ffff:7f00:1%25eth0]/',
    'https://[64:ff9b:1::a9fe:a9fe%25eth0]/',
    'https://[fe80::1%25en0]/',
  ]) {
    assert.equal(validateUrl(url).code, 'INVALID_URL', url);
  }
});

test('cloud platform addresses beyond IMDS are classified', () => {
  assert.equal(classifyIp('168.63.129.16'), 'azure-platform');
  assert.equal(validateUrl('https://168.63.129.16/').code, 'PRIVATE_IP');
  assert.equal(classifyIp('2002:a83f:8110::'), 'azure-platform');
  assert.equal(classifyIp('64:ff9b::a83f:8110'), 'azure-platform');
  assert.equal(classifyIp('::ffff:0:a83f:8110'), 'azure-platform');
});

test('DNS answers with any private address reject regardless of order', async () => {
  for (const answers of [
    ['8.8.8.8', '127.0.0.1'], ['127.0.0.1', '8.8.8.8'],
    ['8.8.8.8', '::1'], ['2606:4700::1111', '10.0.0.1'],
    ['::127.0.0.1'], ['::ffff:0:7f00:1'], ['64:ff9b:1::a9fe:a9fe'],
    ['2002:7f00:1::'], ['::ffff:a9fe:a9fe'],
  ]) {
    const result = await resolveSafe('example.com', { ...HTTP, dns: async () => answers });
    assert.equal(result.ok, false, JSON.stringify(answers));
  }
});

test('DNS dual-stack public answers are accepted', async () => {
  const result = await resolveSafe('example.com', {
    ...HTTP, dns: async () => ['2606:4700:4700::1111', '8.8.8.8'],
  });
  assert.equal(result.ok, true);
  assert.deepEqual(result.addresses, ['2606:4700:4700::1111', '8.8.8.8']);
});

test('redirect chain does not false-positive on query-only changes', async () => {
  const r = await validateRedirectChain([
    'https://example.com/a?x=1', 'https://example.com/a?x=2',
  ], HTTP);
  assert.equal(r.ok, true);
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url) => (url === 'https://example.com/a?x=1'
      ? fakeResponse(302, '/a?x=2')
      : fakeResponse(200)),
  });
  const response = await safeFetch('https://example.com/a?x=1');
  assert.equal(response.status, 200);
});

test('crossOrigin tracks scheme and port changes, not only host', async () => {
  const scheme = await validateRedirectChain(['https://example.com/', 'http://example.com/'], HTTP);
  assert.equal(scheme.hops[1].crossOrigin, true);
  const port = await validateRedirectChain(['https://example.com/', 'https://example.com:8443/'], {
    ...HTTP, allowedPorts: 'any',
  });
  assert.equal(port.hops[1].crossOrigin, true);
  const same = await validateRedirectChain(['https://example.com/a', 'https://example.com/b'], HTTP);
  assert.equal(same.hops[1].crossOrigin, false);
});

test('protocol-relative redirect to loopback is blocked', async () => {
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async () => fakeResponse(302, '//127.0.0.1/admin'),
  });
  await assert.rejects(() => safeFetch('https://example.com/'), (e) => e.code === 'PRIVATE_IP');
});

test('relative redirect stays on the validated origin', async () => {
  const urls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url) => {
      urls.push(url);
      return urls.length === 1 ? fakeResponse(302, '/next') : fakeResponse(200);
    },
  });
  await safeFetch('https://example.com/a');
  assert.deepEqual(urls, ['https://example.com/a', 'https://example.com/next']);
});

test('302 and 303 redirects drop a POST body and switch to GET', async () => {
  for (const status of [301, 302, 303]) {
    const calls = [];
    const safeFetch = createSafeFetch({
      ...HTTP,
      fetch: async (url, init) => {
        calls.push({ url, method: init.method, body: init.body });
        return calls.length === 1 ? fakeResponse(status, '/done') : fakeResponse(200);
      },
    });
    await safeFetch('https://example.com/submit', { method: 'POST', body: 'payload' });
    assert.equal(calls.length, 2, String(status));
    assert.equal(calls[1].method, 'GET', String(status));
    assert.equal(calls[1].body, undefined, String(status));
  }
});

test('307 same-origin redirect preserves method and body', async () => {
  const calls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, init) => {
      calls.push({ url, method: init.method, body: init.body });
      return calls.length === 1 ? fakeResponse(307, '/retry') : fakeResponse(200);
    },
  });
  await safeFetch('https://example.com/submit', { method: 'POST', body: 'payload' });
  assert.equal(calls[1].method, 'POST');
  assert.equal(calls[1].body, 'payload');
});

test('307 and 308 cross-origin redirects never replay the body', async () => {
  for (const status of [307, 308]) {
    const calls = [];
    const safeFetch = createSafeFetch({
      ...HTTP,
      fetch: async (url, init) => {
        calls.push({ url, method: init.method, body: init.body, headers: new Headers(init.headers) });
        return calls.length === 1 ? fakeResponse(status, 'https://evil.example/collect') : fakeResponse(200);
      },
    });
    await safeFetch('https://example.com/submit', {
      method: 'POST',
      body: 'SECRET-TOKEN',
      headers: { 'content-type': 'text/plain', host: 'internal.example' },
    });
    assert.equal(calls[1].url, 'https://evil.example/collect');
    assert.equal(calls[1].body, undefined, String(status));
    assert.equal(calls[1].method, 'GET', String(status));
    assert.equal(calls[1].headers.get('content-type'), null);
    assert.equal(calls[1].headers.get('host'), null);
  }
});

test('credentials are stripped from every hop', async () => {
  const calls = [];
  const safeFetch = createSafeFetch({
    ...HTTP,
    fetch: async (url, init) => {
      calls.push(new Headers(init.headers));
      return calls.length === 1 ? fakeResponse(302, 'https://other.example/') : fakeResponse(200);
    },
  });
  await safeFetch('https://example.com/', {
    credentials: 'include',
    headers: {
      authorization: 'Bearer secret', cookie: 'sid=1',
      'proxy-authorization': 'Basic x', referer: 'https://private.example/',
    },
  });
  for (const headers of calls) {
    assert.equal(headers.get('authorization'), null);
    assert.equal(headers.get('cookie'), null);
    assert.equal(headers.get('proxy-authorization'), null);
    assert.equal(headers.get('referer'), null);
  }
});

test('hostPolicy arrays are copied and frozen against mutation', () => {
  const allow = ['example.com'];
  const guard = createGuard({ ...HTTP, hostPolicy: { allow } });
  allow.push('evil.com');
  assert.equal(guard.validate('https://evil.com/').ok, false);
  assert.throws(() => { guard.options.hostPolicy.allow.push('evil.com'); }, TypeError);
  assert.throws(() => { guard.options.allowCidrs.push('0.0.0.0/0'); }, TypeError);
});

test('prototype pollution keys do not weaken host policy', () => {
  const hostPolicy = JSON.parse('{"allow":["example.com"],"__proto__":{"allowPublicSuffix":true}}');
  const guard = createGuard({ ...HTTP, hostPolicy });
  assert.equal(guard.validate('https://evil.com/').ok, false);
  assert.equal({}.allowPublicSuffix, undefined);
  assert.equal(guard.validate('https://example.com/').ok, true);
});

test('scanner survives hostile getters and proxies', () => {
  const hostile = {};
  Object.defineProperty(hostile, 'url', { enumerable: true, get() { throw new Error('boom'); } });
  let scanned;
  assert.doesNotThrow(() => { scanned = scanToolArguments(hostile, HTTP); });
  assert.equal(scanned.ok, false);
  assert.equal(scanned.rejected, 1);
  const proxied = new Proxy({}, { ownKeys() { throw new Error('no keys'); } });
  assert.doesNotThrow(() => { scanToolArguments({ nested: proxied }, HTTP); });
});

test('parseCidr exposes the parsed base for both families', () => {
  const v4 = parseCidr('10.0.0.0/8');
  assert.equal(v4.family, 4);
  assert.equal(v4.bits, 8);
  assert.equal(v4.value, 0x0a000000);
  const v6 = parseCidr('fd00::/8');
  assert.equal(v6.family, 6);
  assert.deepEqual(v6.groups, [0xfd00, 0, 0, 0, 0, 0, 0, 0]);
});

test('custom scheme documents an undefined port at runtime', () => {
  const result = validateUrl('myapp://example.com/', { allowedSchemes: ['myapp:'] });
  assert.equal(result.ok, true);
  assert.equal(result.port, undefined);
});

test('public suffix typo fixture: at is treated as a public suffix', () => {
  const opts = { ...HTTP, hostPolicy: { allow: ['at'] } };
  assert.equal(validateUrl('https://example.at/', opts).code, 'HOST_NOT_ALLOWED');
});

test('type declarations match the runtime export surface', () => {
  const source = readFileSync(new URL('../types/index.d.ts', import.meta.url), 'utf8');
  for (const name of [
    'isNat64LocalUse', 'ipv4CompatibleIpv4', 'siitIpv4', 'teredoClientIpv4',
    'validateUrl', 'validateRedirectChain', 'createSafeFetch', 'scanToolArguments',
    'DEFAULT_OPTIONS', 'VERSION', 'UrlGuardError', 'guardError', 'resolveSafe',
    'parseCidr', 'cidrContains', 'classifyIp', 'mappedIpv4', 'sixToFourIpv4',
    'nat64Ipv4', 'formatIpv6', 'ipv4ToUint32', 'parseIpv4', 'parseIpv6', 'normalizeIp',
  ]) {
    assert.ok(source.includes(name), `types/index.d.ts is missing ${name}`);
  }
  assert.ok(source.includes('port: number | undefined'));
  assert.ok(source.includes('urls: string | Iterable<string>'));
  assert.ok(source.includes('ResolveResult'));
});

test('CJS build exposes the new IP helpers', () => {
  const cjs = require('../cjs/index.cjs');
  for (const name of ['isNat64LocalUse', 'ipv4CompatibleIpv4', 'siitIpv4', 'teredoClientIpv4']) {
    assert.equal(typeof cjs[name], 'function', name);
  }
  assert.equal(cjs.classifyIp('::ffff:0:7f00:1'), 'loopback');
  assert.equal(cjs.classifyIp('64:ff9b:1::1'), 'nat64-local-use');
});

test('reserved IPv6 space is never a public destination', () => {
  for (const host of [
    '::2:0:0:0:1', '::ffff:1:0:0:1', '::1:2:3:4:5:6',
    '::ffff:0:0:7f00:1', '64:ff9b:0:0:0:ffff:7f00:1',
  ]) {
    assert.notEqual(classifyIp(host), 'public', host);
    const result = validateUrl(`https://[${host}]/`);
    assert.equal(result.ok, false, host);
    assert.equal(result.code, 'PRIVATE_IP', host);
  }
  assert.equal(classifyIp('::2:0:0:0:1'), 'reserved');
  assert.equal(classifyIp('::'), 'unspecified');
  assert.equal(classifyIp('::1'), 'loopback');
  assert.equal(classifyIp('3fff::1'), 'documentation-2');
  assert.equal(validateUrl('https://[3fff::1]/').code, 'PRIVATE_IP');
});

test('DNS answers in reserved IPv6 space are rejected', async () => {
  for (const answers of [
    ['::2:0:0:0:1'], ['::ffff:0:0:7f00:1'], ['3fff::1'],
  ]) {
    const result = await resolveSafe('example.com', { ...HTTP, dns: async () => answers });
    assert.equal(result.ok, false, JSON.stringify(answers));
  }
});

test('IPv4 CIDR lists see through IPv6 transition forms', () => {
  const deny = { ...HTTP, denyCidrs: ['1.1.1.0/24'] };
  for (const url of [
    'https://1.1.1.1/', 'https://[::ffff:1.1.1.1]/', 'https://[::1.1.1.1]/',
    'https://[::ffff:0:1.1.1.1]/', 'https://[2002:101:101::]/', 'https://[64:ff9b::1.1.1.1]/',
  ]) {
    assert.equal(validateUrl(url, deny).code, 'HOST_DENIED', url);
  }
  assert.equal(cidrContains('1.1.1.0/24', '::ffff:1.1.1.1'), true);
  assert.equal(cidrContains('1.1.1.0/24', '2002:101:101::'), true);
  assert.equal(cidrContains('1.1.1.0/24', '2606:4700::1'), false);
});

test('only 301, 302, 303, 307 and 308 are followed as redirects', async () => {
  for (const status of [300, 304, 305, 306, 399]) {
    let calls = 0;
    const safeFetch = createSafeFetch({
      ...HTTP,
      fetch: async () => { calls += 1; return fakeResponse(status, 'https://other.example/'); },
    });
    const response = await safeFetch('https://example.com/');
    assert.equal(response.status, status, String(status));
    assert.equal(calls, 1, String(status));
  }
  for (const status of [301, 302, 303, 307, 308]) {
    let calls = 0;
    const safeFetch = createSafeFetch({
      ...HTTP,
      fetch: async () => {
        calls += 1;
        return calls === 1 ? fakeResponse(status, '/next') : fakeResponse(200);
      },
    });
    const response = await safeFetch('https://example.com/');
    assert.equal(response.status, 200, String(status));
    assert.equal(calls, 2, String(status));
  }
});

test('failure results redact credentials in the input field', async () => {
  const opts = { allowedSchemes: ['https:'], allowUserinfo: true, hostPolicy: { deny: ['evil.com'] } };
  const single = validateUrl('https://user:supersecret@evil.com/path', opts);
  assert.equal(single.code, 'HOST_DENIED');
  assert.ok(!single.input.includes('supersecret'));
  const chain = await validateRedirectChain(['https://user:supersecret@evil.com/path'], opts);
  assert.equal(chain.code, 'HOST_DENIED');
  assert.ok(!chain.input.includes('supersecret'));
});

test('prototype pollution cannot weaken option defaults', () => {
  const polluted = {
    allowUserinfo: true,
    idna: 'allow-unicode',
    allowedSchemes: ['file:'],
    allowPublicSuffix: true,
  };
  for (const [key, value] of Object.entries(polluted)) Object.prototype[key] = value;
  try {
    assert.equal(validateUrl('https://user:pass@example.com/', HTTP).code, 'USERINFO_FORBIDDEN');
    assert.equal(validateUrl('https://example.com/', HTTP).ok, true);
    assert.equal(validateUrl('https://例え.テスト/', HTTP).code, 'UNSUPPORTED_IDNA');
    assert.equal(validateUrl('https://example.com/', {
      ...HTTP, hostPolicy: { allow: ['com'] },
    }).code, 'HOST_NOT_ALLOWED');
    assert.equal(validateUrl('file:///etc/passwd', {}).code, 'UNSAFE_SCHEME');
  } finally {
    for (const key of Object.keys(polluted)) delete Object.prototype[key];
  }
});

test('inherited option properties are ignored', () => {
  const inherited = Object.create({
    allowUserinfo: true,
    allowedSchemes: ['http:', 'https:'],
    hostPolicy: { allow: ['evil.com'] },
  });
  assert.equal(validateUrl('https://user:pass@example.com/', inherited).code, 'USERINFO_FORBIDDEN');
  assert.equal(validateUrl('http://example.com/', inherited).code, 'UNSAFE_SCHEME');
  assert.equal(validateUrl('https://good.example/', inherited).ok, true);
});

test('prototype pollution cannot inject a fetch implementation', async () => {
  let injected = 0;
  const inherited = Object.create({
    fetch: async () => {
      injected += 1;
      return fakeResponse(200);
    },
    allowedSchemes: ['http:', 'https:'],
  });
  inherited.dns = false;
  const safeFetch = createSafeFetch(inherited);
  let thrown = null;
  try {
    await safeFetch('http://example.com/');
  } catch (error) {
    thrown = error;
  }
  assert.equal(injected, 0);
  assert.equal(thrown && thrown.code, 'UNSAFE_SCHEME');
});

test('prototype pollution cannot lower scan limits', () => {
  Object.prototype.maxDepth = 0;
  Object.prototype.maxNodes = 1;
  try {
    const result = scanToolArguments({ a: { b: { c: { url: 'http://127.0.0.1/' } } } }, HTTP);
    assert.equal(result.ok, false);
    assert.equal(result.findings[0].code, 'PRIVATE_IP');
  } finally {
    delete Object.prototype.maxDepth;
    delete Object.prototype.maxNodes;
  }
});

test('isPublicHostname rejects IDNA-foldable and malformed host spellings', () => {
  for (const host of [
    '127。0。0。1', '１２７.０.０.１', '127．0．0．1',
    '.example.com', 'example..com', ':::', '[::1]', '127.0.0.1:443',
  ]) {
    assert.equal(isPublicHostname(host, HTTP), false, host);
  }
  assert.equal(isPublicHostname('example.com', HTTP), true);
  assert.equal(isPublicHostname('[2606:4700:4700::1111]', HTTP), true);
  assert.equal(isPublicHostname('xn--bcher-kva.example', HTTP), true);
});

test('scanner flags scheme-without-slashes URL forms', () => {
  for (const payload of [
    { url: 'https:127.0.0.1' },
    { url: 'http:/169.254.169.254/latest' },
    { target: 'https:169.254.169.254/latest' },
    { url: '//evil.example/x' },
  ]) {
    assert.equal(scanToolArguments(payload, HTTP).ok, false, JSON.stringify(payload));
  }
  assert.equal(scanToolArguments({ url: 'https:127.0.0.1' }, HTTP).findings[0].code, 'PRIVATE_IP');
  assert.equal(scanToolArguments('https:127.0.0.1', HTTP).ok, false);
});

test('scanner checks URL-keyed non-network schemes and ignores relative paths', () => {
  assert.equal(scanToolArguments({ link: 'javascript:alert(1)' }, HTTP).findings[0].code, 'UNSAFE_SCHEME');
  assert.equal(scanToolArguments({ url: 'file:/etc/passwd' }, HTTP).findings[0].code, 'UNSAFE_SCHEME');
  const relative = scanToolArguments({ url: '/relative/path' }, HTTP);
  assert.equal(relative.ok, true);
  assert.equal(relative.findings.length, 0);
});

test('leading dot hostnames are rejected', () => {
  assert.equal(validateUrl('https://.example.com/', HTTP).code, 'INVALID_URL');
  assert.equal(validateUrl('https://.example.com/', {
    ...HTTP, hostPolicy: { allow: ['example.com'] },
  }).ok, false);
});

test('non-iterable allowedSchemes falls back to the default scheme', () => {
  assert.equal(validateUrl('https://example.com/', { allowedSchemes: 42 }).ok, true);
  assert.equal(validateUrl('http://example.com/', { allowedSchemes: 42 }).code, 'UNSAFE_SCHEME');
  assert.equal(validateUrl('https://example.com/', { allowedSchemes: 'https:' }).ok, true);
});

test('new vectors reject cleanly without throwing', () => {
  let result;
  assert.doesNotThrow(() => { result = validateUrl('https://[::ffff:0:a9fe:a9fe]/'); });
  assert.equal(result.ok, false);
  assert.equal(result.code, 'PRIVATE_IP');
  const error = new UrlGuardError('PRIVATE_IP', 'blocked', 'https://[::ffff:0:7f00:1]/');
  assert.equal(error.code, 'PRIVATE_IP');
  assert.equal(error.toJSON().code, 'PRIVATE_IP');
});
