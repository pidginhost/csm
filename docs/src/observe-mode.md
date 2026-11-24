# Observe mode

`mode` declares what CSM is allowed to do to the host it runs on. The default is `enforce`. In `observe`, CSM detects and alerts as usual, but automatic host remediation and integration updates are disabled.

| Value | Meaning |
|---|---|
| `enforce` (default) | Every subsystem acts under its own switch. |
| `observe` | Detection, correlation, alerting and the audit sinks run. Automatic host remediation and integration updates are disabled. |

```yaml
mode: observe
```

Use observe mode in two situations:

- You want to evaluate detection quality on a real host before granting CSM the ability to act.
- You run CSM permanently as a reporting sensor next to another response tool.

## Switching to observe mode

1. While still in enforce mode, resolve any pending firewall apply/rollback window. Observe startup refuses a pending settings or ruleset rollback.
2. Decide what to do with host protections CSM already installed. Observe mode leaves them in place, so remove or change them explicitly first if that is the intended posture.
3. Turn off every switch that changes host state. See [Contradictory settings are refused, not rewritten](#contradictory-settings-are-refused-not-rewritten).
4. Set `mode: observe`.
5. After a hand edit, run `csm rehash`. Restart the daemon with `systemctl restart csm`. Changing `mode` requires a restart, not a reload.
6. Check the result. See [Confirming the posture](#confirming-the-posture).

Observe startup refuses a pending rollback because restoring it would change the host, while ignoring it would abandon the rollback deadline.

## What observe mode stops

Observe mode disables automatic host remediation. It also skips this host integration work, which otherwise runs automatically:

- Writing the auditd rules file and running `augenrules`. This work keeps CSM's audit layers current across package upgrades.
- Refreshing the host integration files: the WHM plugin CGI and its AppConfig registration, and the CSM section of the ModSecurity user config.
- Refreshing legacy challenge snippets and managed webserver integration snippets, with webserver validation and reloads when needed.
- Refreshing stale vendor rules and deploying custom ModSecurity rules, which the WAF check does during periodic scans.
- Reconciling the Exim forward guard, including removing an installed guard when its switch is disabled.
- Reconciling the antispam integration, including removing it when its switch is disabled. An installed integration is reported as `observe_mode` and left in place.
- Re-applying the AF_ALG kernel mitigation on each run of the critical checks. This applies on hosts hardened with `csm harden --copy-fail`, where `/etc/modprobe.d/csm-copy-fail-mitigation.conf` is present.

Existing host protections are left in place.

## Contradictory settings are refused, not rewritten

A config that sets `mode: observe` and still enables a subsystem that changes host state is rejected at load. The error names every conflicting key at once:

```
mode: observe forbids changing host state, but these keys still enable it:
auto_response.enabled (set false), firewall.enabled (set false)
```

CSM checks these keys:

- `auto_response.enabled`
- `firewall.enabled`
- `php_shield.enabled`
- `bpf_enforcement.enabled`
- `email_protection.forward_guard.enabled`
- `email_protection.antispam.enabled`
- `email_protection.antispam.learning.enabled`
- `auto_response.php_relay.freeze`
- `auto_response.mail_auth_recovery.restart_enabled`
- `auto_response.virtual_patch_exposed_files` set to `auto`

It also refuses three settings that act on a host independently of `auto_response.enabled`:

- `auto_response.copy_fail_kill_process: true`
- `email_av.quarantine_infected: true`, when the antivirus scanner is enabled
- `email_av.fail_mode: tempfail`, when the antivirus scanner is enabled

In observe mode, mail that makes the attachment parse worker fail is allowed with a finding. In `enforce`, CSM requests deferral whatever `fail_mode` says when a permission event still holds delivery.

## What still runs

Detection is unchanged. Real-time watchers, scheduled checks, correlation, incidents, alerts, webhooks, the SSE stream and the audit-log sinks all behave as they do under `enforce`. The one difference is that checks report host drift without fixing it.

| Activity | In observe mode |
|---|---|
| CSM's own files | CSM still writes its own configured state, log, cache and quarantine trees. It creates its runtime sockets under `/run/csm` (`/var/run/csm`). |
| Config integrity hashes | Explicit config edits and reloads can update them. |
| Signature and GeoIP updates | They still run, because they write only inside CSM's own directories. |
| Manual operator commands | They still work. |

### Manual commands

`csm firewall deny`, `csm clean`, `csm virtual-patch --apply`, `csm db-clean` and `csm harden` are explicit actions an operator takes, not daemon behavior. Observe mode does not block them.

`auto_response.virtual_patch_exposed_files: manual` is accepted for the same reason.

## Confirming the posture

```bash
csm doctor                 # "operating mode: observe (no automatic remediation or integration changes)"
csm status                 # mode: observe
csm status --json          # .mode
curl .../api/v1/status     # .mode
```

Doctor compares the running mode with the configured mode and warns if they differ. When the daemon is unreachable, it reports only the configured mode.

The capability string `mode.observe.v1` reports that a build understands the setting.

## Details

The sections below are reference material. You do not need them to run observe mode.

### Host writes that remain

Two host writes remain in observe mode. The [capability matrix](capability-matrix.md) marks both as not configurable.

- On a BPF build, capability discovery loads and briefly attaches probe programs to find out what the kernel supports.
- The Copy Fail check runs `kcarectl --patch-info` to see whether a livepatch covers the host. kcarectl refreshes its own cache under `/var/cache/kcare` on every run, including a read-only query.

Neither changes the host's security configuration, and skipping them would cost the detection they exist for. They are listed here so that "observe" is not read as a promise of zero writes.

### Why CSM refuses instead of rewriting

CSM does not silently turn the conflicting switches off in memory. The config re-hash path writes the in-memory config back over `csm.yaml`, so an in-memory override would eventually be written into your file.
