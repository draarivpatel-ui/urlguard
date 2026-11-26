// Redirect-chain validation and rebinding-safe fetch wrapper.

import { fail } from './errors.mjs';
import { validateUrl, normalizeOptions } from './url.mjs';
import { resolveSafe } from './dns.mjs';

/** Validate every hop of a redirect chain. Each hop is checked from scratch. */
export async function validateRedirectChain(urls, options) {
  const opts = normalizeOptions(options);
  const list = typeof urls === 'string' ? [urls] : Array.from(urls || []);
  if (list.length === 0) {
    return { ok: false, code: 'INVALID_URL', detail: 'redirect chain is empty', hops: [] };
  }
  if (list.length - 1 > opts.maxRedirects) {
    return { ok: false, code: 'TOO_MANY_HOPS', detail: `chain exceeds ${opts.maxRedirects} redirects`, hops: [] };
  }
  const hops = [];
  const seen = new Set();
  for (let index = 0; index < list.length; index += 1) {
    const raw = list[index];
    const validation = validateUrl(raw, opts);
    if (!validation.ok) {
      return { ok: false, code: validation.code, detail: validation.detail, hops, hop: index, input: raw };
    }
    const key = `${validation.url.protocol}//${validation.hostname.toLowerCase()}:${validation.port}${validation.url.pathname}`;
    if (seen.has(key)) {
      return { ok: false, code: 'REDIRECT_LOOP', detail: 'redirect loop detected', hops, hop: index };
    }
    seen.add(key);
    const dns = await resolveSafe(validation.hostname, opts, opts);
    if (!dns.ok) {
      return { ok: false, code: dns.code, detail: dns.detail, hops, hop: index };
    }
    hops.push({
      url: validation.normalized,
      hostname: validation.hostname,
      port: validation.port,
      addresses: dns.addresses || [],
      pinnedIp: dns.pinnedIp || null,
      crossOrigin: index > 0 ? hops[0].hostname !== validation.hostname : false,
    });
  }
  return { ok: true, hops, finalUrl: hops[hops.length - 1].url };
}

/**
 * Wrap fetch() with URL validation, redirect policy and credential stripping.
 * The injected fetch implementation is called only after every check passes.
 */
export function createSafeFetch(options) {
  const opts = normalizeOptions(options);
  const fetchImpl = typeof options?.fetch === 'function' ? options.fetch : null;
  return async function safeFetch(input, init) {
    if (!fetchImpl && typeof globalThis.fetch !== 'function') {
      throw Object.assign(new Error('fetch is not available'), { code: 'RESOLUTION_FAILED' });
    }
    const target = typeof input === 'string' ? input : input && typeof input.url === 'string' ? input.url : null;
    const validation = validateUrl(target, opts);
    if (!validation.ok) {
      const { guardError } = await import('./errors.mjs');
      throw guardError(validation.code, validation.detail, target);
    }
    const dns = await resolveSafe(validation.hostname, opts, opts);
    if (!dns.ok) {
      const { guardError } = await import('./errors.mjs');
      throw guardError(dns.code, dns.detail, target);
    }
    const nextInit = { ...(init || {}) };
    delete nextInit.credentials;
    const headers = new Headers(nextInit.headers || {});
    headers.delete('authorization');
    headers.delete('cookie');
    headers.delete('proxy-authorization');
    headers.delete('referer');
    nextInit.headers = headers;
    nextInit.redirect = 'manual';

    let current = validation.normalized;
    const seen = new Set();
    const maxHops = opts.maxRedirects;
    for (let hop = 0; hop <= maxHops; hop += 1) {
      const locationResult = await validateUrl(current, opts);
      if (!locationResult.ok) {
        const { guardError } = await import('./errors.mjs');
        throw guardError(locationResult.code, locationResult.detail, current);
      }
      const dnsResult = await resolveSafe(locationResult.hostname, opts, opts);
      if (!dnsResult.ok) {
        const { guardError } = await import('./errors.mjs');
        throw guardError(dnsResult.code, dnsResult.detail, current);
      }
      const key = `${locationResult.url.protocol}//${locationResult.hostname}:${locationResult.port}${locationResult.url.pathname}`;
      if (seen.has(key)) {
        const { guardError } = await import('./errors.mjs');
        throw guardError('REDIRECT_LOOP', 'redirect loop detected', current);
      }
      seen.add(key);
      const response = await (fetchImpl || globalThis.fetch)(current, nextInit);
      if (response.status < 300 || response.status >= 400) return response;
      const location = response.headers?.get?.('location');
      if (!location) return response;
      if (hop === maxHops) {
        const { guardError } = await import('./errors.mjs');
        throw guardError('TOO_MANY_HOPS', `more than ${maxHops} redirects`, current);
      }
      let nextUrl;
      try {
        nextUrl = new URL(location, current).href;
      } catch {
        const { guardError } = await import('./errors.mjs');
        throw guardError('INVALID_URL', 'redirect Location could not be parsed', location);
      }
      current = nextUrl;
    }
    const { guardError } = await import('./errors.mjs');
    throw guardError('TOO_MANY_HOPS', 'redirect loop exhausted', current);
  };
}
