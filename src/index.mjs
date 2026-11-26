// urlguard: zero-dependency SSRF and URL-chain safety for Node and edge runtimes.

export { UrlGuardError, guardError } from './errors.mjs';
export {
  parseIpv4, parseIpv6, normalizeIp, classifyIp, mappedIpv4,
  sixToFourIpv4, nat64Ipv4, isTeredo, formatIpv6, ipv4ToUint32,
  parseCidr, cidrContains,
} from './ip.mjs';
export {
  validateUrl, assertSafeUrl, isPublicHostname, createGuard,
} from './url.mjs';
export { resolveSafe } from './dns.mjs';
export { validateRedirectChain, createSafeFetch } from './chain.mjs';
export { scanToolArguments } from './scan.mjs';

/** Default options object, frozen, useful as a documented baseline. */
export const DEFAULT_OPTIONS = Object.freeze({
  allowedSchemes: Object.freeze(['https:']),
  allowUserinfo: false,
  allowedPorts: 'default-only',
  idna: 'ascii-only',
  maxInputLength: 8192,
  checkRebinding: false,
  rebindDelayMs: 50,
  maxRedirects: 5,
});

export const VERSION = '0.1.0';
