# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| < 0.1 | No |

## Reporting a vulnerability

Please **Privately report** security issues using GitHub's **Security Advisory** feature on this repository: open the **Security** tab, choose **Report a vulnerability**, and fill in the private form. Do not open a public issue for an exploitable defect.

Include:

1. The affected version and module format (ESM or CommonJS).
2. A minimal proof of concept URL or payload.
3. The expected versus observed validation result.
4. Any DNS resolver configuration used.

## Response SLA

- Acknowledgement: within 48 hours.
- Initial assessment: within 5 business days.
- Fix or mitigation plan: within 10 business days for confirmed issues.

Severity is judged by whether the issue allows a blocked destination to be reached, causes a false negative in redirect chains, or leaks sensitive data through errors.
