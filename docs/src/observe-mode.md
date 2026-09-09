# Observe mode

`mode` declares what CSM is allowed to do to the host it runs on.

| Value | Meaning |
|---|---|
| `enforce` (default) | Every subsystem acts under its own switch. This is how CSM has always behaved. |
| `observe` | Detection, correlation, alerting and the audit sinks run. CSM writes nothing outside its own state, log, cache and quarantine trees. |

```yaml
mode: observe
```

Use observe mode to evaluate detection quality on a real host before granting
CSM the ability to act, or to run CSM permanently as a reporting sensor next to
another response tool.

## What observe mode stops

Two things happen at daemon startup that no other setting controls:

- The auditd rules file is written and `augenrules` is run, so CSM's audit
  layers stay current across package upgrades.
- The host integration files are refreshed: the WHM plugin CGI and its AppConfig
  registration, the CSM section of the ModSecurity user config, and the deploy
  script.

Observe mode skips both and logs that it did. Nothing else in CSM writes to the
host without a switch of its own.

## Contradictory settings are refused, not rewritten

A config that sets `mode: observe` and still enables a subsystem that changes
host state is rejected at load, naming every conflicting key at once:

```
mode: observe forbids changing host state, but these keys still enable it:
auto_response.enabled (set false), firewall.enabled (set false)
```

The keys checked are `auto_response.enabled`, `firewall.enabled`,
`php_shield.enabled`, `bpf_enforcement.enabled`,
`email_protection.forward_guard.enabled`, `email_av.quarantine_infected`,
`auto_response.php_relay.freeze`,
`auto_response.mail_auth_recovery.restart_enabled`, and
`auto_response.virtual_patch_exposed_files` set to `auto`.

CSM refuses rather than silently turning those switches off in memory, because
the config re-signing path marshals the in-memory config back over `csm.yaml`:
an in-memory override would eventually be written into the operator's file.

## What still runs

Detection is unchanged. Real-time watchers, scheduled checks, correlation,
incidents, alerts, webhooks, the SSE stream and the audit-log sinks all behave
exactly as they do under `enforce`.

Manual operator commands still work. `csm firewall deny`, `csm clean`,
`csm virtual-patch --apply`, `csm db-clean` and `csm harden` are explicit
actions an operator takes, not daemon behaviour, so observe mode does not block
them. `auto_response.virtual_patch_exposed_files: manual` is accepted for the
same reason.

Signature and GeoIP updates still run: they write only inside CSM's own
directories.

## Confirming the posture

```bash
csm doctor                 # "operating mode: observe (detection and alerting only, no host changes)"
csm status                 # mode: observe
csm status --json          # .mode
curl .../api/v1/status     # .mode
```

The capability string `mode.observe.v1` reports that a build understands the
setting.

Changing `mode` requires a restart (`systemctl restart csm`), not a reload.
