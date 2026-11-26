// urlguard: zero-dependency SSRF and URL-chain safety for Node and edge runtimes.

const __reexport___errors_mjs = require('./errors.cjs');
Object.defineProperty(exports, "UrlGuardError", { enumerable: true, get: () => __reexport___errors_mjs.UrlGuardError });
Object.defineProperty(exports, "guardError", { enumerable: true, get: () => __reexport___errors_mjs.guardError });
const __reexport___ip_mjs = require('./ip.cjs');
Object.defineProperty(exports, "parseIpv4", { enumerable: true, get: () => __reexport___ip_mjs.parseIpv4 });
Object.defineProperty(exports, "parseIpv6", { enumerable: true, get: () => __reexport___ip_mjs.parseIpv6 });
Object.defineProperty(exports, "normalizeIp", { enumerable: true, get: () => __reexport___ip_mjs.normalizeIp });
Object.defineProperty(exports, "classifyIp", { enumerable: true, get: () => __reexport___ip_mjs.classifyIp });
Object.defineProperty(exports, "mappedIpv4", { enumerable: true, get: () => __reexport___ip_mjs.mappedIpv4 });
Object.defineProperty(exports, "sixToFourIpv4", { enumerable: true, get: () => __reexport___ip_mjs.sixToFourIpv4 });
Object.defineProperty(exports, "nat64Ipv4", { enumerable: true, get: () => __reexport___ip_mjs.nat64Ipv4 });
Object.defineProperty(exports, "isNat64LocalUse", { enumerable: true, get: () => __reexport___ip_mjs.isNat64LocalUse });
Object.defineProperty(exports, "ipv4CompatibleIpv4", { enumerable: true, get: () => __reexport___ip_mjs.ipv4CompatibleIpv4 });
Object.defineProperty(exports, "siitIpv4", { enumerable: true, get: () => __reexport___ip_mjs.siitIpv4 });
Object.defineProperty(exports, "isTeredo", { enumerable: true, get: () => __reexport___ip_mjs.isTeredo });
Object.defineProperty(exports, "teredoClientIpv4", { enumerable: true, get: () => __reexport___ip_mjs.teredoClientIpv4 });
Object.defineProperty(exports, "formatIpv6", { enumerable: true, get: () => __reexport___ip_mjs.formatIpv6 });
Object.defineProperty(exports, "ipv4ToUint32", { enumerable: true, get: () => __reexport___ip_mjs.ipv4ToUint32 });
Object.defineProperty(exports, "parseCidr", { enumerable: true, get: () => __reexport___ip_mjs.parseCidr });
Object.defineProperty(exports, "cidrContains", { enumerable: true, get: () => __reexport___ip_mjs.cidrContains });
const __reexport___url_mjs = require('./url.cjs');
Object.defineProperty(exports, "validateUrl", { enumerable: true, get: () => __reexport___url_mjs.validateUrl });
Object.defineProperty(exports, "assertSafeUrl", { enumerable: true, get: () => __reexport___url_mjs.assertSafeUrl });
Object.defineProperty(exports, "isPublicHostname", { enumerable: true, get: () => __reexport___url_mjs.isPublicHostname });
Object.defineProperty(exports, "createGuard", { enumerable: true, get: () => __reexport___url_mjs.createGuard });
const __reexport___dns_mjs = require('./dns.cjs');
Object.defineProperty(exports, "resolveSafe", { enumerable: true, get: () => __reexport___dns_mjs.resolveSafe });
const __reexport___chain_mjs = require('./chain.cjs');
Object.defineProperty(exports, "validateRedirectChain", { enumerable: true, get: () => __reexport___chain_mjs.validateRedirectChain });
Object.defineProperty(exports, "createSafeFetch", { enumerable: true, get: () => __reexport___chain_mjs.createSafeFetch });
const __reexport___scan_mjs = require('./scan.cjs');
Object.defineProperty(exports, "scanToolArguments", { enumerable: true, get: () => __reexport___scan_mjs.scanToolArguments });

/** Default options object, frozen, useful as a documented baseline. */
const DEFAULT_OPTIONS = Object.freeze({
  allowedSchemes: Object.freeze(['https:']),
  allowUserinfo: false,
  allowedPorts: 'default-only',
  idna: 'ascii-only',
  maxInputLength: 8192,
  checkRebinding: false,
  rebindDelayMs: 50,
  maxRedirects: 5,
});

const VERSION = '0.1.0';

exports.DEFAULT_OPTIONS = DEFAULT_OPTIONS;
exports.VERSION = VERSION;
