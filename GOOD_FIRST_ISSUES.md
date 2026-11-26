# Good first issues

Ten small, well-scoped tasks for new contributors. Each one names the module to touch and has a deterministic acceptance check. Comment on the issue before starting so work is not duplicated.

## Issue 1: Document the resolver contract

- **Area:** `README.md`, `types/runtime-node.d.ts`
- **Task:** Write a short contract for resolver return values, covering string records, object records, empty answers and mixed families. Show one safe custom resolver example.
- **Acceptance:** The documentation matches the behavior tested in `tests/12-dns-fetch-extra.test.mjs` and adds no new dependency.

## Issue 2: Expand IPv4 mutation fixtures

- **Area:** `tests/02-ipv4.test.mjs`
- **Task:** Add a deterministic table of mutated decimal, octal, hex and shorthand IPv4 forms, including overlong digits and mixed separators. Assert accept or reject behavior explicitly for each row.
- **Acceptance:** Every new case is table-driven, passes on Node 18 through 24 and does not use randomness.

## Issue 3: Add host-pattern case folding tests

- **Area:** `src/url.mjs`, `tests/04-hosts-ports-policy.test.mjs`
- **Task:** Verify wildcard allow and deny patterns behave consistently for uppercase ASCII hostnames and trailing dots. Document any normalization that already occurs before matching.
- **Acceptance:** Focused tests cover allow precedence, deny precedence and wildcard matching without changing unrelated policy behavior.

## Issue 4: Cover non-followed redirect statuses

- **Area:** `tests/06-redirect-chain.test.mjs`, `tests/13-adversarial-hardening.test.mjs`
- **Task:** Add a response-status matrix proving 300, 304, 305 and 399 responses are returned rather than followed, while 301, 302, 303, 307 and 308 remain the only followed statuses.
- **Acceptance:** The matrix uses a fake `fetch` implementation and asserts both call count and returned status.

## Issue 5: Test safe-fetch methods beyond POST

- **Area:** `tests/13-adversarial-hardening.test.mjs`
- **Task:** Extend the redirect body matrix with HEAD, PUT and DELETE. Assert 303 conversion behavior and cross-origin body removal are explicit for each method.
- **Acceptance:** Tests are deterministic and the README redirect semantics are updated if the matrix reveals a mismatch.

## Issue 6: Add scanner key redaction cases

- **Area:** `tests/07-scanner.test.mjs`
- **Task:** Add nested fixtures where URLs appear in keys such as `callback`, `webhook`, `endpoint` and `target`. Assert finding paths stay stable and credential-bearing values are redacted.
- **Acceptance:** No finding includes a password or userinfo component in its serialized output.

## Issue 7: Add CIDR helper parity cases

- **Area:** `tests/08-parity.test.mjs`
- **Task:** Compare ESM and CJS results for `parseCidr`, `cidrContains`, transition-form extraction helpers and formatted IPv6 output across a compact fixture table.
- **Acceptance:** Both module systems return deep-equal results for every fixture.

## Issue 8: Add a TypeScript consumer smoke test

- **Area:** `types/`, `tests/10-hygiene.test.mjs`
- **Task:** Add a small type-only consumer fixture that exercises `ValidateOptions`, `ChainResult`, `ScanResult` and the runtime-node subpath declarations, then document how contributors can check it.
- **Acceptance:** The fixture uses only TypeScript syntax compatible with the published declarations and adds no runtime dependency.

## Issue 9: Make fuzz failures easier to minimize

- **Area:** `tests/09-fuzz-property.test.mjs`
- **Task:** When a seeded mutation fails, print the seed, mutation index and exact input in a single copyable diagnostic line. Do not print anything for passing runs.
- **Acceptance:** A temporary forced failure demonstrates the diagnostic, and the committed suite remains quiet when green.

## Issue 10: Add a threat-model example page

- **Area:** `docs/`, `README.md`
- **Task:** Create a concise example that walks one SSRF attempt through scheme validation, IP classification, DNS resolution and redirect revalidation. Link it from the threat-model section.
- **Acceptance:** The example uses only ASCII punctuation, contains no real internal hostnames and matches current library behavior.
