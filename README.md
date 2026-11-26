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
  assertSafeUrl('http://169.254.169.254/latest/meta-data/');
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
- IPv4-mapped IPv6 (`::ffff:7f00:1`), 6to4 (`2002:7f00:1::`), Teredo, NAT64 (`64:ff9b::7f00:1`) and zone IDs.
- Cloud metadata endpoints (`169.254.169.254`, `100.100.100.200`, `fd00:ec2::254`, `metadata.google.internal`), CGNAT (`100.64.0.0/10`), loopback, link-local, multicast, documentation and benchmark ranges.
- DNS answers in blocked ranges, mixed public/private answers, query failures and rebinding windows.
- Redirect chains: scheme/host/port revalidation on every hop, loop detection, hop limits and cross-origin tracking.
- Agent tool arguments: nested objects and arrays with depth and node caps.

**Out of scope**

- Time-of-check/time-of-use between validation and your socket. Use `createSafeFetch` with your own resolver, or adopt a client that pins the validated address.
- TLS trust, certificate pinning and response-content scanning.
- BGP hijack or malicious DNS returning public addresses that route internally.
- IDNA homoglyph policy beyond the default ASCII-only mode. Enable `idna: 'allow-unicode'` only for trusted inputs.

## Security design notes

- All hostile-input checks run **before** the WHATWG `URL` parser, which silently normalizes many SSRF payloads.
- IPv4 and IPv6 parsing is implemented from scratch. Ambiguous or oversized forms are rejected rather than guessed.
- Error stacks are fixed strings with no internal frames. Inputs are redacted, control characters replaced and credentials masked.
- The DNS adapter is a subpath export. Edge bundles never pull in `node:dns`.

## Tests

```sh
npm test
```

The suite runs with `node --test` and requires no dependencies. It contains deterministic bypass vectors, seeded fuzz/property cases, CJS and ESM parity checks, and package hygiene checks. Both module formats are exercised in Node.

## License

MIT. See [LICENSE](LICENSE).
