# Credential rotation

Some CSM integrations take their credential from an environment variable. That environment is the one CSM inherited when it started. To rotate such a credential, change the launch environment and restart CSM.

CSM reads the environment before each request, but that does not import edits to an environment file or exports from another shell. `csm rehash`, SIGHUP, and `systemctl daemon-reload` do not replace a running process's environment.

## Integrations this applies to

| Integration | Environment variable name configured in | Static fallback |
|---|---|---|
| Upstream threat intelligence | `reputation.upstream.token_env` | `reputation.upstream.token` |
| Rspamd | `reputation.rspamd.token_env` | `reputation.rspamd.token` |
| Verdict callback | `auto_response.verdict_callback.hmac_secret_env` | `auto_response.verdict_callback.hmac_secret` |
| Phpanel finding webhook | `alerts.webhook.hmac_secret_env` | `alerts.webhook.hmac_secret` |

A non-empty environment value takes precedence over the static fallback. An unset or empty variable uses that fallback.

Each verdict exchange keeps one secret for both request signing and response verification.

## Configure a systemd environment file

Create `/etc/csm/credentials.env`, owned by root with mode `0600`. Put the actual values in this file through your editor or configuration manager:

```ini
CSM_UPSTREAM_TOKEN=replace-with-upstream-token
CSM_RSPAMD_TOKEN=replace-with-controller-password
CSM_VERDICT_SECRET=replace-with-verdict-secret
CSM_WEBHOOK_SECRET=replace-with-webhook-secret
```

Set the corresponding CSM configuration fields to these variable names. Then create `/etc/systemd/system/csm.service.d/credentials.conf`:

```ini
[Service]
EnvironmentFile=/etc/csm/credentials.env
```

Apply the new unit configuration and start CSM with that environment:

```bash
systemctl daemon-reload
systemctl restart csm.service
systemctl is-active csm.service
```

## Later rotations

Update the existing credentials file and run `systemctl restart csm.service`. `daemon-reload` is needed when the unit or its drop-ins change, not for a value change in an already referenced file.

For a foreground daemon, stop it and launch a new process with the updated environment supplied by its launcher.

Coordinate the change with each receiver:

1. Where the receiver supports overlapping credentials, retain the old credential through restarts and in-flight requests.
2. Verify successful authentication with the new credential at the receiver, without logging its value.
3. Retire the old credential.

## Regression coverage

`TestEnvironmentCredentialRotation` launches a subprocess from an environment file and captures real HTTP requests from all four clients. It checks two things:

- While the process stays running, requests before and after an external file edit use the old credential.
- Restarting the subprocess from the edited file switches all four clients to the new credential.

The test does not change the running process's environment with `os.Setenv`.
