// Strict URL parser, policy engine and synchronous validator.
// The WHATWG parser is used only AFTER hostile-input checks, because it
// normalizes many SSRF payloads (decimal IP, shorthand, backslashes) silently.

import { guardError, fail } from './errors.mjs';
import { classifyIp, normalizeIp, cidrContains } from './ip.mjs';

const CONTROL_RE = /[\u0000-\u001f\u007f-\u009f]/;
const WHITESPACE_RE = /\s/;
const DEFAULT_MAX_INPUT_LENGTH = 8192;
const DEFAULT_SCHEMES = ['https:'];
const DEFAULT_PORTS = { 'http:': 80, 'https:': 443 };

const BLOCKED_HOSTNAMES = new Set([
  'localhost', 'metadata', 'metadata.google.internal', 'metadata.goog',
  'metadata.azure.com', 'instance-data', 'instance-data.ec2.internal',
  'kubernetes.default.svc', 'kubernetes.default', 'api.internal',
]);
const BLOCKED_HOST_SUFFIXES = [
  '.internal', '.localhost', '.local', '.localdomain', '.home.arpa',
  '.in-addr.arpa', '.ip6.arpa', '.onion',
];
const PUBLIC_SUFFIXES = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ai', 'app', 'dev',
  'xyz', 'info', 'biz', 'me', 'tv', 'us', 'uk', 'de', 'fr', 'jp', 'cn', 'in', 'au',
  'ca', 'br', 'nl', 'se', 'no', 'fi', 'es', 'it', 'ru', 'ch', '.at', 'be', 'dk',
  'co.uk', 'org.uk', 'com.au', 'co.jp', 'co.nz', 'com.br', 'co.in',
]);

function normalizeSchemes(schemes) {
  const result = [];
  for (const raw of schemes) {
    if (typeof raw !== 'string') continue;
    let scheme = raw.trim().toLowerCase();
    if (!scheme) continue;
    if (!scheme.endsWith(':')) scheme += ':';
    if (!/^[a-z][a-z\d+.-]*:$/.test(scheme)) continue;
    result.push(scheme);
  }
  return Array.from(new Set(result));
}

function normalizeOptions(options) {
  const opts = options && typeof options === 'object' ? options : {};
  const allowedSchemes = normalizeSchemes(opts.allowedSchemes || DEFAULT_SCHEMES);
  const allowedPorts = opts.allowedPorts === undefined ? 'default-only' : opts.allowedPorts;
  const hostPolicy = opts.hostPolicy && typeof opts.hostPolicy === 'object' ? opts.hostPolicy : {};
  return {
    allowedSchemes,
    allowUserinfo: opts.allowUserinfo === true,
    allowedPorts,
    hostPolicy,
    maxInputLength: Number.isInteger(opts.maxInputLength) && opts.maxInputLength > 0
      ? opts.maxInputLength : DEFAULT_MAX_INPUT_LENGTH,
    idna: opts.idna === 'allow-unicode' ? 'allow-unicode' : 'ascii-only',
    allowCidrs: Array.isArray(opts.allowCidrs) ? opts.allowCidrs : [],
    denyCidrs: Array.isArray(opts.denyCidrs) ? opts.denyCidrs : [],
    dns: opts.dns,
    checkRebinding: opts.checkRebinding === true,
    rebindDelayMs: Number.isFinite(opts.rebindDelayMs) && opts.rebindDelayMs >= 0
      ? opts.rebindDelayMs : 50,
    maxRedirects: Number.isInteger(opts.maxRedirects) && opts.maxRedirects >= 0
      ? opts.maxRedirects : 5,
  };
}

/** Reject hostile literal forms before the WHATWG parser can normalize them away. */
function precheck(input, opts) {
  if (typeof input !== 'string') return fail('INVALID_URL', 'URL must be a string', input);
  if (input.length === 0) return fail('INVALID_URL', 'URL is empty', input);
  if (input.length > opts.maxInputLength) return fail('INPUT_TOO_LARGE', `URL exceeds ${opts.maxInputLength} characters`, input);
  if (CONTROL_RE.test(input)) return fail('INVALID_URL', 'control character in URL', input);
  if (input.includes('\u0000')) return fail('INVALID_URL', 'null byte in URL', input);
  if (input.includes('\\')) return fail('INVALID_URL', 'backslash in URL', input);
  if (WHITESPACE_RE.test(input)) return fail('INVALID_URL', 'whitespace in URL', input);
  if (input.trim() !== input) return fail('INVALID_URL', 'leading or trailing whitespace in URL', input);
  if (input.startsWith('//')) return fail('INVALID_URL', 'scheme-relative URLs are not allowed', input);
  return null;
}

function hostPatternMatches(host, pattern) {
  if (typeof pattern !== 'string' || !pattern) return false;
  let normalized = pattern.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized) return false;
  if (normalized.startsWith('*.')) normalized = normalized.slice(2);
  else if (normalized.startsWith('.')) { /* apex plus subdomains */ }
  const exact = normalized.startsWith('.') ? normalized.slice(1) : normalized;
  if (host === exact) return true;
  if (normalized.startsWith('.')) {
    const base = normalized.slice(1);
    return host === base || host.endsWith(`.${base}`);
  }
  return host.endsWith(`.${exact}`);
}

function isPublicSuffixPattern(pattern) {
  if (typeof pattern !== 'string') return false;
  const normalized = pattern.toLowerCase().replace(/^\*\./, '').replace(/^\./, '').replace(/\.$/, '');
  return PUBLIC_SUFFIXES.has(normalized) || !normalized.includes('.');
}

function checkHostPolicy(hostname, hostPolicy) {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  const deny = Array.isArray(hostPolicy.deny) ? hostPolicy.deny : [];
  const allow = Array.isArray(hostPolicy.allow) ? hostPolicy.allow : [];
  if (BLOCKED_HOSTNAMES.has(host)) return fail('HOST_DENIED', 'hostname is on the built-in deny list', host);
  for (const suffix of BLOCKED_HOST_SUFFIXES) {
    if (host.endsWith(suffix)) return fail('HOST_DENIED', `hostname ends with blocked suffix ${suffix}`, host);
  }
  for (const pattern of deny) {
    if (hostPatternMatches(host, pattern)) return fail('HOST_DENIED', `hostname denied by policy (${pattern})`, host);
  }
  if (allow.length > 0) {
    let allowed = false;
    for (const pattern of allow) {
      if (isPublicSuffixPattern(pattern)) {
        if (hostPolicy.allowPublicSuffix !== true) {
          return fail('HOST_NOT_ALLOWED', `public suffix cannot be allowlisted (${pattern})`, host);
        }
      }
      if (hostPatternMatches(host, pattern)) { allowed = true; break; }
    }
    if (!allowed) return fail('HOST_NOT_ALLOWED', 'hostname is not on the allow list', host);
  }
  return null;
}

/** Validate the string and return a URL object. Synchronous, no network I/O. */
export function validateUrl(input, options) {
  const opts = normalizeOptions(options);
  const pre = precheck(input, opts);
  if (pre) return pre;

  // Check the raw scheme before WHATWG normalization or authority inspection.
  const rawSchemeMatch = /^([a-z][a-z\d+.-]*):/i.exec(input);
  const rawScheme = rawSchemeMatch ? `${rawSchemeMatch[1].toLowerCase()}:` : '';
  if (rawScheme && !opts.allowedSchemes.includes(rawScheme)) {
    return fail('UNSAFE_SCHEME', `scheme ${rawScheme} is not allowed`, input);
  }

  // Examine the raw authority before WHATWG normalization can hide encoded hosts.
  const authorityMatch = /^[a-z][a-z\d+.-]*:\/\/([^/?#]*)/i.exec(input);
  const rawAuthority = authorityMatch ? authorityMatch[1] : '';
  if (authorityMatch && rawAuthority.length === 0) {
    return fail('INVALID_URL', 'empty hostname', input);
  }
  if (/%[0-9a-f]{2}/i.test(rawAuthority)) {
    return fail('INVALID_URL', 'percent-encoded characters in authority are not allowed', input);
  }
  if (opts.idna === 'ascii-only' && /[^\x21-\x7e]/.test(rawAuthority)) {
    return fail('UNSUPPORTED_IDNA', 'unicode hostname requires idna: allow-unicode', input);
  }
  if (opts.idna === 'ascii-only' && /\bxn--/i.test(rawAuthority)) {
    return fail('UNSUPPORTED_IDNA', 'punycode hostname requires idna: allow-unicode', input);
  }

  let url;
  try {
    url = new URL(input);
  } catch {
    return fail('INVALID_URL', 'URL could not be parsed', input);
  }
  if (!opts.allowedSchemes.includes(url.protocol)) {
    return fail('UNSAFE_SCHEME', `scheme ${url.protocol} is not allowed`, input);
  }
  if ((url.username || url.password) && !opts.allowUserinfo) {
    return fail('USERINFO_FORBIDDEN', 'embedded credentials are not allowed', input);
  }

  let hostname = url.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);
  if (hostname.endsWith('.')) hostname = hostname.slice(0, -1);
  if (!hostname) return fail('INVALID_URL', 'empty hostname', input);
  if (hostname.includes('%')) return fail('INVALID_URL', 'percent-encoded hostname is not allowed', input);
  if (opts.idna === 'ascii-only' && /[^\x21-\x7e]/.test(hostname)) {
    return fail('UNSUPPORTED_IDNA', 'unicode hostname requires idna: allow-unicode', input);
  }
  if (hostname.length > 253 || hostname.split('.').some((label) => label.length > 63)) {
    return fail('INVALID_URL', 'hostname or label is too long', input);
  }
  if (hostname.includes('..')) {
    return fail('INVALID_URL', 'hostname contains consecutive dots', input);
  }

  const ipClass = classifyIp(hostname);
  if (ipClass === 'private' || (ipClass !== 'public' && ipClass !== 'invalid')) {
    return fail('PRIVATE_IP', `host resolves to a non-public range (${ipClass})`, input);
  }
  if (ipClass === 'public') {
    for (const cidr of opts.denyCidrs) {
      if (cidrContains(cidr, hostname)) return fail('HOST_DENIED', `host denied by CIDR (${cidr})`, input);
    }
    if (opts.allowCidrs.length > 0 && !opts.allowCidrs.some((cidr) => cidrContains(cidr, hostname))) {
      return fail('HOST_NOT_ALLOWED', 'host is not in an allowed CIDR', input);
    }
  }

  const policyFailure = checkHostPolicy(hostname, hostPolicyOrEmpty(opts));
  if (policyFailure) return { ...policyFailure, input };

  const defaultPort = DEFAULT_PORTS[url.protocol];
  const port = url.port ? Number(url.port) : defaultPort;
  if (!url.port && defaultPort === undefined) {
    // Custom schemes have no well-known port; the absence of an explicit port is safe.
    return {
      ok: true,
      url,
      normalized: url.href,
      hostname,
      port: undefined,
      ipClass,
      normalizedIp: normalizeIp(hostname),
    };
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return fail('PORT_FORBIDDEN', 'port is outside 1-65535', input);
  }
  if (opts.allowedPorts === 'default-only') {
    if (port !== defaultPort) {
      return fail('PORT_FORBIDDEN', `only port ${defaultPort} is allowed for ${url.protocol}`, input);
    }
  } else if (Array.isArray(opts.allowedPorts)) {
    if (!opts.allowedPorts.includes(port)) return fail('PORT_FORBIDDEN', `port ${port} is not allowed`, input);
  } else if (opts.allowedPorts !== 'any') {
    return fail('PORT_FORBIDDEN', 'allowedPorts must be an array, default-only or any', input);
  }

  return {
    ok: true,
    url,
    normalized: url.href,
    hostname,
    port,
    ipClass,
    normalizedIp: normalizeIp(hostname),
  };
}

function hostPolicyOrEmpty(opts) {
  return opts.hostPolicy && typeof opts.hostPolicy === 'object' ? opts.hostPolicy : {};
}

/** Throwing variant. Error codes are stable; stacks contain no internal frames. */
export function assertSafeUrl(input, options) {
  const result = validateUrl(input, options);
  if (!result.ok) throw guardError(result.code, result.detail, input);
  return result;
}

/** Check a hostname against host policy only. Returns true when allowed. */
export function isPublicHostname(hostname, options) {
  if (typeof hostname !== 'string' || !hostname) return false;
  const opts = normalizeOptions(options);
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  const ipClass = classifyIp(host);
  // IP literals must be public; plain DNS names are allowed here and verified at resolution time.
  if (ipClass !== 'public' && ipClass !== 'invalid') return false;
  for (const cidr of opts.denyCidrs) if (cidrContains(cidr, host)) return false;
  if (opts.allowCidrs.length > 0 && !opts.allowCidrs.some((cidr) => cidrContains(cidr, host))) return false;
  return checkHostPolicy(host, hostPolicyOrEmpty(opts)) === null;
}

/** Compile a reusable policy object. */
export function createGuard(options) {
  const opts = normalizeOptions(options);
  Object.freeze(opts);
  return {
    validate: (input) => validateUrl(input, opts),
    assert: (input) => assertSafeUrl(input, opts),
    isPublicHostname: (host) => isPublicHostname(host, opts),
    options: Object.freeze({ ...opts }),
  };
}

export { normalizeOptions };
