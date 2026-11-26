# Contributing

Thanks for helping improve urlguard. Security correctness takes priority over feature breadth.

## Development setup

No install step is required. The project has zero runtime and zero development dependencies.

```sh
git clone <repository-url>
cd urlguard
npm test
```

All tests run with the built-in Node test runner. Use Node 18 or newer.

## Test command

```sh
npm test
```

To exercise the CommonJS build after editing `src/*.mjs`, regenerate it first:

```sh
npm run test:all
```

## Guidelines

- Add a regression test for every bypass vector you fix.
- Keep all IP logic dependency-free and deterministic.
- Never expose internal stack frames or raw unsafe input in errors.
- Preserve ESM and CommonJS parity. Add a case to `tests/08-parity.test.mjs` for new public exports.
- Use stable error codes from `UrlGuardErrorCode`. Introducing a new code requires documentation and types updates.
- Avoid em dashes and en dashes in documentation.

## Pull requests

1. Fork and create a focused branch.
2. Add tests, then implementation.
3. Run `npm run test:all`.
4. Describe the threat model impact in the PR body.

## Reporting security issues

Do not open a public PR for a vulnerability. Follow [SECURITY.md](SECURITY.md).
