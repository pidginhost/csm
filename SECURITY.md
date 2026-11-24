# Security Policy

CSM is designed to run on production servers. We treat security bugs with high priority and aim to ship fixes quickly.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No - please upgrade |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report a security issue in one of these two ways:

1. By email: send details to `support@pidginhost.com` with the subject line `[CSM SECURITY]`.
2. By GitHub private advisory: use the "Report a vulnerability" button on the Security tab of this repository.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if safe to share)
- Affected version(s)
- Any suggested mitigations you are aware of

## Responsible Disclosure

We follow a coordinated disclosure process:

- We acknowledge receipt within 2 business days.
- We assess and confirm the issue within 5 business days.
- We aim to ship a fix within 14 days for critical issues and 30 days for others.
- We credit reporters in the release notes unless you prefer to remain anonymous.
- Please do not publicly disclose the issue until we have shipped a fix and notified you.

## Scope

In scope: the CSM daemon, Web UI, firewall engine, and installer scripts.

Out of scope:

- Third-party dependencies. Report those upstream.
- Servers running CSM that you do not own or have permission to test.
