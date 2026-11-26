// DNS resolution, private-range filtering and DNS-rebinding detection.
// All network I/O flows through an injected resolver.

import { fail } from './errors.mjs';
import { classifyIp } from './ip.mjs';

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeDnsOptions(options, base) {
  const opts = base && typeof base === 'object' ? base : {};
  const incoming = options && typeof options === 'object' ? options : {};
  const dns = incoming.dns !== undefined ? incoming.dns : opts.dns;
  return {
    dns,
    checkRebinding: incoming.checkRebinding !== undefined ? incoming.checkRebinding : opts.checkRebinding === true,
    rebindDelayMs: incoming.rebindDelayMs !== undefined ? incoming.rebindDelayMs : (opts.rebindDelayMs ?? 50),
  };
}

function addressList(result) {
  if (!Array.isArray(result)) return [];
  return result
    .map((entry) => {
      if (typeof entry === 'string') return entry;
      if (entry && typeof entry === 'object' && typeof entry.address === 'string') return entry.address;
      return null;
    })
    .filter((address) => address !== null);
}

async function resolveOnce(resolver, hostname) {
  const raw = await resolver(hostname);
  const addresses = addressList(raw);
  if (addresses.length === 0) return { ok: false, code: 'RESOLUTION_FAILED', detail: 'resolver returned no addresses' };
  for (const address of addresses) {
    const ipClass = classifyIp(address);
    if (ipClass !== 'public') {
      return { ok: false, code: 'PRIVATE_IP', detail: `DNS result ${address} is in non-public range ${ipClass}` };
    }
  }
  return { ok: true, addresses: addresses.slice().sort() };
}

/** Resolve a hostname, verify all results are public, optionally detect rebinding. */
export async function resolveSafe(hostname, options, baseOptions) {
  const opts = normalizeDnsOptions(options, baseOptions);
  if (opts.dns === false || opts.dns === undefined || opts.dns === null) {
    return { ok: true, skipped: true, addresses: [] };
  }
  if (typeof opts.dns !== 'function') {
    return fail('RESOLUTION_FAILED', 'dns resolver must be a function or false', hostname);
  }
  let first;
  try {
    first = await resolveOnce(opts.dns, hostname);
  } catch {
    return fail('RESOLUTION_FAILED', 'DNS resolution failed', hostname);
  }
  if (!first.ok) return { ...first, input: hostname };
  if (!opts.checkRebinding) return first;

  const wait = Number.isFinite(opts.rebindDelayMs) && opts.rebindDelayMs >= 0 ? opts.rebindDelayMs : 50;
  if (wait > 0) await delay(wait);
  let second;
  try {
    second = await resolveOnce(opts.dns, hostname);
  } catch {
    return fail('RESOLUTION_FAILED', 'DNS resolution failed on second lookup', hostname);
  }
  if (!second.ok) return { ...second, input: hostname };
  if (first.addresses.join(',') !== second.addresses.join(',')) {
    return fail('DNS_REBIND', 'DNS answer changed between lookups', hostname);
  }
  return { ok: true, addresses: first.addresses, pinnedIp: first.addresses[0] };
}
