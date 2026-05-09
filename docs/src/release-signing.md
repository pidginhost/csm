# Release Signing

CSM has two separate signing paths:

- **Package repository signing** for the normal APT/DNF install path.
- **Detached Ed25519 artifact signatures** for raw binaries, tarballs, and package files downloaded outside the package manager.

Do not reuse keys between these paths. The package repositories use GPG because APT and DNF verify repository metadata that way. Detached release signatures use Ed25519 because the standalone install and deploy scripts verify raw artifact bytes with OpenSSL.

## Status

| Surface | Key type | CI variable | Notes |
|---------|----------|-------------|-------|
| APT repository metadata | GPG | `CSM_GPG_SIGNING_KEY` | Published by `repo:publish`; operators install with `signed-by=/etc/apt/keyrings/csm.gpg`. |
| RPM packages and repository metadata | GPG | `CSM_GPG_SIGNING_KEY` | Published by `repo:publish`; operators use `gpgcheck=1` and `repo_gpgcheck=1`. |
| Raw binaries, tarballs, `.deb`, `.rpm` siblings | Ed25519 | `CSM_SIGNING_KEY` | Optional detached `.sig` files for direct downloads and standalone scripts. |

The preferred operator path is the signed APT/DNF repository documented in [Installation](installation.md). Standalone scripts still support detached signatures, but this source tree does not currently embed an Ed25519 public key in `scripts/install.sh`, `scripts/deploy.sh`, or `scripts/deploy-gitlab.sh`. Without an embedded key or `CSM_SIGNING_KEY_PEM`, those scripts warn and continue unless `CSM_REQUIRE_SIGNATURES=1` is set.

## Package Repository Signing

`repo:publish` runs on version tag pipelines and rebuilds the public package repositories from the current tag plus the retained historical releases.

Required protected CI variables:

| Variable | Type | Purpose |
|----------|------|---------|
| `CSM_GPG_SIGNING_KEY` | File | GPG private key used to sign APT metadata, RPM packages, and RPM repo metadata. |
| `CSM_MIRROR_SSH_KEY` | File | SSH key used to publish the mirror output. |
| `CSM_MIRROR_KNOWN_HOSTS` | Variable | SSH host keys for the mirror host. |

The job exports the public key as `csm-signing.gpg` and publishes it at the mirror root so install docs can reference:

```bash
https://mirrors.pidginhost.com/csm/csm-signing.gpg
```

APT verifies signed repository metadata through the `signed-by=` keyring. DNF verifies both RPM package signatures and repository metadata via `gpgcheck=1` and `repo_gpgcheck=1`.

## Detached Artifact Signatures

`sign:artifacts` signs release files with the Ed25519 private key in `CSM_SIGNING_KEY` when that variable is present. Each signed file gets a `.sig` sibling uploaded with the artifact.

Examples:

```text
csm-linux-amd64
csm-linux-amd64.sig
csm_3.0.0_amd64.deb
csm_3.0.0_amd64.deb.sig
csm-3.0.0-1.x86_64.rpm
csm-3.0.0-1.x86_64.rpm.sig
```

The signature covers the raw artifact bytes with no hashing wrapper. Verification uses:

```bash
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-linux-amd64.sig -in csm-linux-amd64
```

## Detached Signature Setup

On a trusted workstation:

```bash
openssl genpkey -algorithm ed25519 -out csm-signing.key
openssl pkey -in csm-signing.key -pubout -out csm-signing.pub
```

Store the private key in GitLab as a protected `CSM_SIGNING_KEY` variable. Keep the private key in an offline password manager and a second secure backup location. Do not commit it.

For standalone script verification, either:

- Embed the public key PEM in `EMBEDDED_SIGNING_KEY` in `scripts/install.sh`, `scripts/deploy.sh`, and `scripts/deploy-gitlab.sh`.
- Or pass the public key at runtime with `CSM_SIGNING_KEY_PEM`.

To make missing signatures or missing public keys fatal:

```bash
CSM_REQUIRE_SIGNATURES=1 curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
```

If a `.sig` file exists but verification fails, the installer aborts regardless of `CSM_REQUIRE_SIGNATURES`.

## Key Rotation

Package repository GPG key rotation:

1. Generate a new GPG signing key.
2. Replace `CSM_GPG_SIGNING_KEY` in protected CI variables.
3. Publish a tag pipeline so `repo:publish` exports the new public key to the mirror.
4. Update install docs or automation if the key URL changes.

Detached Ed25519 key rotation:

1. Generate a new Ed25519 key pair.
2. Replace `CSM_SIGNING_KEY` in protected CI variables.
3. Update the embedded public key in standalone scripts, or rotate the `CSM_SIGNING_KEY_PEM` value used by automation.
4. Tag a new release.

Old detached signatures remain verifiable only with the old public key. Archive old public keys alongside release metadata so historical releases can still be checked.

## Manual Detached Verification

```bash
curl -LO https://github.com/pidginhost/csm/releases/download/v3.0.0/csm-linux-amd64
curl -LO https://github.com/pidginhost/csm/releases/download/v3.0.0/csm-linux-amd64.sig

openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-linux-amd64.sig -in csm-linux-amd64
```

If verification fails, treat the artifact as untrusted. Do not install it.
