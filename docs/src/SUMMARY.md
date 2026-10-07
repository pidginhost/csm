# Summary

[Introduction](README.md)

# Getting Started

- [Installation](installation.md)
- [Configuration](configuration.md)
- [Credential rotation](credential-rotation.md)
- [Custom account roots](custom-account-roots.md)
- [Service configuration writes](service-confinement.md)
- [Upgrading](upgrading.md)
- [CLI Commands](cli.md)

# Detection and Response

- [Real-Time Detection](detection-realtime.md)
- [Critical Checks](detection-critical.md)
- [Deep Checks](detection-deep.md)
- [Auto-Response](auto-response.md)
- [Observe Mode](observe-mode.md)
- [Capability Matrix](capability-matrix.md)
- [Self-test](self-test.md)
- [Incidents](incidents.md)
- [Incident Response Runbook](incident-response-runbook.md)
- [Direct SMTP Egress](direct-smtp-egress.md)
- [BPF Enforcement](bpf-enforcement.md)

# Hardening

- [CVE Mitigations](cve-mitigations.md)

# Components

- [Firewall (nftables)](firewall.md)
- [ModSecurity](modsecurity.md)
- [Signature Rules](signatures.md)
- [Email AV](email-av.md)
- [Threat Intelligence](threat-intel.md)
- [GeoIP](geoip.md)
- [Challenge Pages](challenge.md)
- [Performance Monitor](performance.md)

# Operations and Integrations

- [Web UI](webui.md)
- [API Reference](api.md)
- [Metrics (Prometheus)](metrics.md)
- [Audit Log (SIEM)](audit-log.md)
- [Action Log](action-log.md)

# Development

- [Building and Testing](development.md)
  - [Clean Application Corpus](clean-corpus.md)
  - [Recorded Finding Streams](finding-streams.md)
  - [Crawl Detector Calibration](crawl-calibration.md)
  - [cPanel Release Tests](cpanel-release-tests.md)
  - [Production Build and Kernel Tests](production-tests.md)
- [Release Signing](release-signing.md)

# Design notes

- [Architecture direction](design/architecture-direction.md)
- [Auto-response safety model](design/auto-response-safety-model.md)
- [Durable action lifecycle](design/durable-action-lifecycle.md)
- [Privilege separation](design/privilege-separation.md)
- [Firewall state migration](design/firewall-state-migration.md)
