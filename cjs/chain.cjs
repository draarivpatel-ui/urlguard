// Redirect-chain validation and rebinding-safe fetch wrapper.

const { guardError, redactInput } = require('./errors.cjs');
const { validateUrl, normalizeOptions, ownOption } = require('./url.cjs');
const { resolveSafe } = require('./dns.cjs');

function originOf(result) {
  const port = result.port === undefined || result.port === null ? '' : String(result.port);
  return `${result.url.protocol}//${result.hostname}:${port}`;
}

function hopKey(result) {
  return `${originOf(result)}${result.url.pathname}${result.url.search}`;
}

// fetch follows exactly these statuses. A 300, 304, 305, 306 or unknown 3xx
// with a Location header is returned to the caller, never followed.
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

function isRedirectStatus(status) {
  return typeof status === 'number' && REDIRECT_STATUSES.has(status);
}

function locationOf(response) {
  const value = response && response.headers && typeof response.headers.get === 'function'
    ? response.headers.get('location')
    : null;
  return typeof value === 'string' && value.length > 0 ? value : null;
}

/**
 * Build the request init for the next hop. Credentials are dropped by the
 * caller before the loop. Bodies follow fetch redirect semantics and are also
 * dropped on any cross-origin hop so a redirect cannot replay a secret body
 * to a different origin.
 */
function redirectInit(status, init, crossOrigin) {
  const next = { ...init };
  const method = typeof next.method === 'string' ? next.method.toUpperCase() : 'GET';
  const switchToGet = status === 303
    ? method !== 'GET' && method !== 'HEAD'
    : (status === 301 || status === 302) && method === 'POST';
  const dropBody = (switchToGet && next.body !== undefined)
    || (crossOrigin && next.body !== undefined);
  if (switchToGet) next.method = 'GET';
  if (dropBody) {
    delete next.body;
    if (method !== 'HEAD') next.method = 'GET';
  }
  if (crossOrigin && next.headers) {
    const headers = new Headers(next.headers);
    headers.delete('host');
    next.headers = headers;
  }
  if (dropBody) {
    const headers = new Headers(next.headers || {});
    headers.delete('content-length');
    headers.delete('content-type');
    headers.delete('content-encoding');
    headers.delete('transfer-encoding');
    next.headers = headers;
  }
  return next;
}

/** Validate every hop of a redirect chain. Each hop is checked from scratch. */
async function validateRedirectChain(urls, options) {
  const opts = normalizeOptions(options);
  const list = typeof urls === 'string' ? [urls] : Array.from(urls || []);
  if (list.length === 0) {
    return { ok: false, code: 'INVALID_URL', detail: 'redirect chain is empty', hops: [] };
  }
  if (list.length - 1 > opts.maxRedirects) {
    return { ok: false, code: 'TOO_MANY_HOPS', detail: `chain exceeds ${opts.maxRedirects} redirects`, hops: [] };
  }
  const hops = [];
  const origins = [];
  const seen = new Set();
  for (let index = 0; index < list.length; index += 1) {
    const raw = list[index];
    const validation = validateUrl(raw, opts);
    if (!validation.ok) {
      return {
        ok: false,
        code: validation.code,
        detail: validation.detail,
        hops,
        hop: index,
        input: redactInput(raw),
      };
    }
    const key = hopKey(validation);
    if (seen.has(key)) {
      return { ok: false, code: 'REDIRECT_LOOP', detail: 'redirect loop detected', hops, hop: index };
    }
    seen.add(key);
    const dns = await resolveSafe(validation.hostname, opts, opts);
    if (!dns.ok) {
      return { ok: false, code: dns.code, detail: dns.detail, hops, hop: index };
    }
    const origin = originOf(validation);
    origins.push(origin);
    hops.push({
      url: validation.normalized,
      hostname: validation.hostname,
      port: validation.port,
      addresses: dns.addresses || [],
      pinnedIp: dns.pinnedIp || null,
      crossOrigin: index > 0 ? origin !== origins[0] : false,
    });
  }
  return { ok: true, hops, finalUrl: hops[hops.length - 1].url };
}

/**
 * Wrap fetch() with URL validation, redirect policy and credential stripping.
 * Every hop is validated and resolved again. The injected fetch still performs
 * its own DNS lookup, so pass an implementation that connects to the validated
 * address when the resolver is untrusted (see the threat model in README.md).
 */
function createSafeFetch(options) {
  const opts = normalizeOptions(options);
  const candidateFetch = ownOption(options, 'fetch');
  const fetchImpl = typeof candidateFetch === 'function' ? candidateFetch : null;
  return async function safeFetch(input, init) {
    if (!fetchImpl && typeof globalThis.fetch !== 'function') {
      throw Object.assign(new Error('fetch is not available'), { code: 'RESOLUTION_FAILED' });
    }
    const target = typeof input === 'string' ? input : input && typeof input.url === 'string' ? input.url : null;
    const validation = validateUrl(target, opts);
    if (!validation.ok) throw guardError(validation.code, validation.detail, target);
    const dns = await resolveSafe(validation.hostname, opts, opts);
    if (!dns.ok) throw guardError(dns.code, dns.detail, target);

    let currentInit = { ...(init || {}) };
    delete currentInit.credentials;
    const headers = new Headers(currentInit.headers || {});
    headers.delete('authorization');
    headers.delete('cookie');
    headers.delete('proxy-authorization');
    headers.delete('referer');
    currentInit.headers = headers;
    currentInit.redirect = 'manual';

    let current = validation.normalized;
    let currentOrigin = originOf(validation);
    const seen = new Set();
    const maxHops = opts.maxRedirects;
    for (let hop = 0; hop <= maxHops; hop += 1) {
      const locationResult = validateUrl(current, opts);
      if (!locationResult.ok) {
        throw guardError(locationResult.code, locationResult.detail, current);
      }
      const dnsResult = await resolveSafe(locationResult.hostname, opts, opts);
      if (!dnsResult.ok) {
        throw guardError(dnsResult.code, dnsResult.detail, current);
      }
      const key = hopKey(locationResult);
      if (seen.has(key)) {
        throw guardError('REDIRECT_LOOP', 'redirect loop detected', current);
      }
      seen.add(key);
      const response = await (fetchImpl || globalThis.fetch)(current, currentInit);
      if (!isRedirectStatus(response.status)) return response;
      const location = locationOf(response);
      if (!location) return response;
      if (hop === maxHops) {
        throw guardError('TOO_MANY_HOPS', `more than ${maxHops} redirects`, current);
      }
      let nextUrl;
      try {
        nextUrl = new URL(location, current).href;
      } catch {
        throw guardError('INVALID_URL', 'redirect Location could not be parsed', location);
      }
      const nextValidation = validateUrl(nextUrl, opts);
      if (!nextValidation.ok) {
        throw guardError(nextValidation.code, nextValidation.detail, nextUrl);
      }
      const nextOrigin = originOf(nextValidation);
      currentInit = redirectInit(response.status, currentInit, currentOrigin !== nextOrigin);
      current = nextValidation.normalized;
      currentOrigin = nextOrigin;
    }
    throw guardError('TOO_MANY_HOPS', 'redirect loop exhausted', current);
  };
}

exports.validateRedirectChain = validateRedirectChain;
exports.createSafeFetch = createSafeFetch;
