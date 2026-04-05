# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Older releases | No - please upgrade |

CSM is designed to run on production servers. We treat security bugs with high priority and aim to ship fixes quickly.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues by one of these methods:

1. **Email:** Send details to the maintainer email listed on the repository. Use the subject line `[CSM SECURITY]`.
2. **GitHub private advisory:** Use the "Report a vulnerability" button on the Security tab of this repository.

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if safe to share)
- Affected version(s)
- Any suggested mitigations you are aware of

## Responsible Disclosure

We follow a coordinated disclosure process:

- We will acknowledge receipt within **2 business days**.
- We will assess and confirm the issue within **5 business days**.
- We aim to ship a fix within **14 days** for critical issues and **30 days** for others.
- We will credit reporters in the release notes unless you prefer to remain anonymous.
- Please do not publicly disclose the issue until we have shipped a fix and notified you.

## Scope

In scope: the CSM daemon, web UI, firewall engine, and installer scripts.

Out of scope: third-party dependencies (report those upstream), servers running CSM that you do not own or have permission to test.
