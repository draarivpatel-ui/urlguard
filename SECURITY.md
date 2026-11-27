# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Privately report a suspected vulnerability through the repository's [Security Advisory reporting form](https://github.com/draarivpatel-ui/urlguard/security/advisories/new). Do not open a public issue for a suspected vulnerability.

Please include:

- A minimal reproduction that uses synthetic input only.
- The affected project version, commit or action ref, and Node.js version.
- The expected security boundary and the observed violation.
- Logs, output, or proof-of-concept code needed to reproduce the finding, with real secrets removed.

Never include a real token, cookie, password, private key, production log line or real personal data in a report.

Vulnerability handling steps:

1. The maintainer acknowledges the private report within 72 hours.
2. The maintainer reproduces the finding against the latest supported version and confirms severity within 14 days when enough information is available.
3. A fix is developed privately, with regression coverage where practical.
4. The maintainer coordinates the advisory, affected versions, reporter credit and disclosure date with the reporter.
5. The target coordinated disclosure window is 90 days or less from acknowledgment. If more time is needed, the maintainer and reporter agree on a new date before disclosure.

## Response SLA

- Acknowledgement: within 48 hours.
- Initial assessment: within 5 business days.
- Fix or mitigation plan: within 10 business days for confirmed issues.

Severity is judged by whether the issue allows a blocked destination to be reached, causes a false negative in redirect chains, or leaks sensitive data through errors.
