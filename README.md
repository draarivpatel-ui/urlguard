# urlguard

A zero-dependency, RFC-aware URL security guard for Node.js 20+ and edge runtimes. It answers one question correctly: **is this URL, and every hop of its redirect chain, safe for my server or agent to follow?**

Ships pure ESM, generated CommonJS and strict TypeScript definitions. No runtime dependencies, no install step beyond copying the package, no network I/O unless you inject a DNS resolver.

## Install

```sh
npm install urlguard
```

## Quick start

```js
import { validateUrl, assertSafeUrl } from 'urlguard';

const result = validateUrl('https://example.com/api');
if (result.ok) {
  console.log(result.normalized, result.hostname, result.port);
}

try {
  assertSafeUrl('http://169.254.169.254/latest/meta-data/', {
    allowedSchemes: ['http:', 'https:'],
  });
} catch (error) {
  console.error(error.code); // PRIVATE_IP
}
```

CommonJS works identically:

```js
const { validateUrl } = require('urlguard');
```

## API

| Function | Purpose |
| --- | --- |
| `validateUrl(input, opts?)` | Synchronous validation. Returns a discriminated result. |
| `assertSafeUrl(input, opts?)` | Throws `UrlGuardError` with a stable `.code`. |
| `createGuard(opts?)` | Compile a reusable, frozen policy. |
| `validateRedirectChain(urls, opts?)` | Validate every hop, with DNS pinning and loop detection. |
| `createSafeFetch(opts?)` | Wrap `fetch` with validation, hop limits and credential stripping. |
| `scanToolArguments(value, opts?)` | Bounded recursive scan of agent/MCP tool arguments. |
| `isPublicHostname(host, opts?)` | Hostname-only policy check. |
| `classifyIp(host)` | Educational IP classification (private, public, loopback, and so on). |

### DNS resolution and rebinding

DNS is opt-in. Pass a resolver function; the library never imports `node:dns` on its own.

```js
import { nodeResolve } from 'urlguard/runtime/node';

const opts = {
  allowedSchemes: ['https:'],
  dns: nodeResolve,
  checkRebinding: true,
  rebindDelayMs: 50,
};
const result = await validateRedirectChain([
  'https://example.com/',
  'https://api.example.com/',
], opts);
```

When `checkRebinding` is enabled, the resolver is called twice. Both answers must be identical and entirely public. The first public answer is pinned in the result as `pinnedIp`.

### Safe fetch behavior

`createSafeFetch` strips `Authorization`, `Cookie`, `Proxy-Authorization` and `Referer` from every hop, including the first request, and deletes the `credentials` option. Only 301, 302, 303, 307 and 308 are treated as redirects; every other 3xx response is returned unchanged. Redirect bodies follow fetch semantics: 301, 302 and 303 switch a POST to GET without a body, 307 and 308 preserve method and body on the same origin, and no body is ever replayed to a different origin. Redirect loops are matched on origin, path and query.

### Custom policy

```js
const guard = createGuard({
  allowedSchemes: ['https:'],
  allowedPorts: [443, 8443],
  hostPolicy: {
    allow: ['*.example.com'],
    deny: ['admin.example.com'],
  },
  denyCidrs: ['203.0.113.0/24'],
});
```

## Threat model

**In scope**

- Non-HTTP(S) schemes, scheme-relative URLs, embedded credentials, backslashes, control characters and null bytes.
- IPv4 decimal, octal, hex and shorthand forms (`2130706433`, `0177.0.0.1`, `0x7f000001`, `127.1`).
- IPv4-mapped IPv6 (`::ffff:7f00:1`), IPv4-compatible IPv6 (`::7f00:1`), IPv4-translated SIIT (`::ffff:0:7f00:1`), 6to4 (`2002:7f00:1::`), Teredo (decoded with the `0xffffffff` XOR), NAT64 well-known (`64:ff9b::7f00:1`), NAT64 local-use (`64:ff9b:1::/48`), reserved `0000::/8` space and zone IDs.
- Multiple trailing dots (`127.0.0.1..`), leading dots, unicode dot variants (`127。0。0。1`), fullwidth digits, percent-encoded zones and mixed-case hex.
- Cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `168.63.129.16`, `fd00:ec2::254`, `metadata.google.internal`), CGNAT (`100.64.0.0/10`), loopback, link-local, multicast, documentation and benchmark ranges.
- IPv4 CIDR allow and deny lists match the IPv4 address embedded in mapped, compatible, SIIT, 6to4 and NAT64 forms.
- DNS answers in blocked ranges, mixed public/private or dual-stack answers in any order, query failures and rebinding windows.
- Redirect chains: scheme/host/port revalidation on every hop, credential stripping, query-aware loop detection, hop limits, cross-origin tracking and no body replay on any cross-origin hop.
- Agent tool arguments: nested objects and arrays with depth and node caps, hostile getters or proxies never abort a scan, and URL-valued keys are validated even without a scheme separator.

**Out of scope**

- Time-of-check/time-of-use between validation and your socket. `createSafeFetch` re-validates and re-resolves before every hop, but the injected `fetch` still performs its own DNS lookup, so a resolver that changes its answer after the check can still reach a different address. For hard pinning, pass a `fetch` implementation that connects to the validated address, or use the `pinnedIp` returned by `resolveSafe` with `checkRebinding: true`.
- TLS trust, certificate pinning and response-content scanning.
- BGP hijack or malicious DNS returning public addresses that route internally.
- IDNA homoglyph policy beyond the default ASCII-only mode. Enable `idna: 'allow-unicode'` only for trusted inputs.

## Security design notes

- All hostile-input checks run **before** the WHATWG `URL` parser, which silently normalizes many SSRF payloads.
- IPv4 and IPv6 parsing is implemented from scratch. Ambiguous or oversized forms are rejected rather than guessed.
- Error stacks are fixed strings with no internal frames. Inputs are redacted, control characters replaced and credentials masked.
- Options are read only from own properties, so a polluted `Object.prototype`, a hostile prototype or a hostile getter cannot weaken a policy.
- The DNS adapter is a subpath export. Edge bundles never pull in `node:dns`.

## Tests

```sh
npm test
```

The suite runs 206 tests with `node --test` and requires no dependencies. It contains deterministic bypass vectors, seeded fuzz/property cases, adversarial redirect and DNS cases, CJS and ESM parity checks, and package hygiene checks. Both module formats are exercised in Node.

## License

MIT. See [LICENSE](LICENSE).
