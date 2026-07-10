# CSM Documentation

CSM is a local security monitoring and response daemon for Linux web servers. cPanel/WHM shared hosting is the primary target; platform detection also selects applicable paths and checks for Plesk, DirectAdmin, and panel-free hosts running Apache, Nginx, LiteSpeed, or no web server.

## Start here

- **New installation:** [Install the signed package](installation.md), review [configuration](configuration.md), start the daemon, then establish the [baseline](installation.md#baseline-scan).
- **Daily operation:** Use the [Web UI](webui.md), [`csm status` and `csm doctor`](cli.md#management), and the [incident response runbook](incident-response-runbook.md).
- **Response policy:** Read [Auto-response](auto-response.md) and [Firewall](firewall.md) before enabling automatic actions.
- **Coverage:** Compare [real-time](detection-realtime.md), [critical](detection-critical.md), and [deep](detection-deep.md) checks with the services installed on the host.
- **Integrations:** Start with the [API](api.md), [metrics](metrics.md), and [audit log](audit-log.md).

## How CSM works

Real-time watchers process filesystem, authentication, access-log, mail, PAM, BPF, and ModSecurity events. Scheduled scans cover host integrity, accounts, CMS files and databases, packages, mail configuration, and performance. Findings are stored locally and can feed alerts, incidents, the Web UI, API clients, Prometheus, syslog, webhooks, and SIEM exports.

Platform-specific checks skip when their required panel or service is absent. The documentation calls out cPanel-only behavior instead of treating a skipped integration as a failure.

## Safety model

Auto-response is off by default. Automatic IP blocking has a dry-run default, while file, process, mail, and BPF actions have their own gates. Infrastructure and operator-allowed addresses are protected from automatic blocks, quarantine records restoration metadata, and firewall configuration supports confirmation-based rollback.

Use [Configuration](configuration.md) as the source for current defaults and [Upgrading](upgrading.md) for state, config, and package migration rules.
