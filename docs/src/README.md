# CSM Documentation

CSM is a local security monitoring and response daemon for Linux web servers, with or without a control panel. It detects the platform and picks the paths and checks for cPanel/WHM, Plesk, DirectAdmin, or no panel, on Apache, Nginx, LiteSpeed, or no web server. cPanel hosts get the deepest account and CMS integration; see [supported platforms](installation.md#supported-platforms).

## Start here

- For a new installation, [install the signed package](installation.md), review [configuration](configuration.md), start the daemon, then establish the [baseline](installation.md#baseline-scan).
- For daily operation, use the [Web UI](webui.md), [`csm status` and `csm doctor`](cli.md#management), and the [incident response runbook](incident-response-runbook.md).
- For response policy, read [Auto-response](auto-response.md) and [Firewall](firewall.md) before you enable automatic actions.
- For coverage, compare the [real-time](detection-realtime.md), [critical](detection-critical.md), and [deep](detection-deep.md) checks with the services installed on the host.
- For integrations, start with the [API](api.md), [metrics](metrics.md), and [audit log](audit-log.md).

## How CSM works

CSM finds problems in two ways:

- Real-time watchers process filesystem, authentication, access-log, mail, PAM, BPF, and ModSecurity events.
- Scheduled scans cover host integrity, accounts, CMS files and databases, packages, mail configuration, and performance.

CSM stores findings locally. They can feed alerts, incidents, the Web UI, API clients, Prometheus, syslog, webhooks, and SIEM exports.

Platform-specific checks skip when their required panel or service is absent. The documentation calls out cPanel-only behavior and does not treat a skipped integration as a failure.

## Safety model

Auto-response is off by default. Automatic IP blocking has a dry-run default. File, process, mail, and BPF actions have their own gates.

Three more safeguards apply:

- Infrastructure and operator-allowed addresses are protected from automatic blocks.
- Quarantine records restoration metadata.
- Firewall configuration supports confirmation-based rollback.

Use [Configuration](configuration.md) as the source for current defaults and [Upgrading](upgrading.md) for state, config, and package migration rules.
