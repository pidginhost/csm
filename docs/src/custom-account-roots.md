# Custom account roots

`account_roots` accepts absolute, normalized directory paths or glob patterns.
The same configured content trees are eligible for manual remediation and
quarantine restore. Detected panel account homes and the existing scratch
quarantine locations keep their normal scope. A configured content directory
itself is not a restore target; restore operates beneath it.

Symlinks in a configured root or its ancestors are rejected. Unsafe trees are
excluded from remediation without disabling other tenants' valid roots.
Destination directories are pinned during restore, including when a tenant
renames a directory while the operation is running.

## Service write access

The packaged service uses `ProtectSystem=strict`. A custom content tree needs a
write grant before the daemon can quarantine, clean, or restore files there.
Keep the account container directory owned by root and not writable by tenants:

```yaml
account_roots:
  - /srv/csm-accounts/*/public
```

For this layout, `/srv/csm-accounts` is root-owned; the account directories below
it can belong to their tenants. Provision the directories before generating the
drop-in:

```sh
set -e
fragment="$(mktemp)"
trap 'rm -f "$fragment"' EXIT
csm systemd-roots > "$fragment"
cat "$fragment"
install -d -m 0755 /etc/systemd/system/csm.service.d
install -m 0644 "$fragment" /etc/systemd/system/csm.service.d/50-account-roots.conf
systemctl daemon-reload
systemctl restart csm.service
csm doctor
```

`csm systemd-roots` only prints the drop-in. It grants existing content
directories or their nearest root-controlled ancestor, and adds mount ordering
for those paths. It refuses symlink roots and broad grants such as `/`, `/srv`,
or `/etc`. It escapes path quoting and systemd specifiers. The generated
fragment appends grants to the packaged service; it does not reset that list.

A tenant-owned directory cannot itself be a grant: its owner could replace it
with a symlink before systemd starts. If the command cannot find a narrow,
root-controlled ancestor, move the accounts beneath a dedicated root-owned
container directory and update `account_roots`.

Regenerate the fragment after changing roots or provisioning a tree outside
existing grants. Changing `account_roots` requires a daemon restart. If integrity
verification is enabled, update its baseline for an intentional configuration
change before restarting, as described in [Configuration](configuration.md).

## Verification

`csm doctor` checks configured custom roots and detected panel roots outside the
packaged home grant. It reports missing roots, unsafe aliases, missing service
grants, and read-only mounts in the running daemon's filesystem view. A stopped
service or an unavailable systemd connection is reported as unverified access.
Reloading unit files alone does not change the running service's mount namespace;
restart the service and run doctor again.

After setup, verify detection, quarantine, listing, and restore on a test account
under the custom root. Confirm that the restored file still belongs to its
tenant. A sibling tree outside the configured roots and existing scratch
locations must remain ineligible for restore.

The repository includes a disposable systemd service test. Build an image from
`build/Dockerfile.systemd-test`, then use the Linux wrapper:

```sh
GO_LINUX_IMAGE=csm-systemd-test scripts/go-linux.sh bash scripts/systemd-account-roots-test.sh
cat .cache/systemd-account-roots/result
```

The test runs production detection, quarantine, listing, restore, and doctor
inside the packaged sandbox, with a generated grant for a separate test volume.
It verifies owner, permissions, timestamps, and rejected sibling and symlink
destinations. This tests service confinement; it does not start the daemon's
watchers or replace panel integration coverage. Logs and generated grants are
saved beside the result file. The harness refuses to run outside its disposable
Linux container.
