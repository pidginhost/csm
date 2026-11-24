# Release Signing

CSM has two separate signing paths:

- Package repository signing covers the normal APT/DNF install path.
- Detached Ed25519 artifact signatures cover raw binaries, tarballs, and package files downloaded outside the package manager.

Do not reuse keys between these paths. The package repositories use GPG because APT and DNF verify repository metadata that way. Detached release signatures use Ed25519 to authenticate the artifact bytes. The standalone scripts use OpenSSL or a supported fallback verifier.

## Status

| Surface | Key type | CI variable | Notes |
|---------|----------|-------------|-------|
| APT repository metadata | GPG | `CSM_GPG_SIGNING_KEY` | Published by `repo:publish`; operators install with `signed-by=/etc/apt/keyrings/csm.gpg`. |
| RPM packages and repository metadata | GPG | `CSM_GPG_SIGNING_KEY` | Published by `repo:publish`; operators use `gpgcheck=1` and `repo_gpgcheck=1`. |
| Raw binaries, tarballs, `.deb`, `.rpm` siblings | Ed25519 | `CSM_SIGNING_KEY` | Detached `.sig` files for direct downloads and standalone scripts. |
| YARA Forge rule ZIPs | Ed25519 | `CSM_SIGNING_KEY` | Signed by the `yara-forge-mirror` job; clients verify via `signatures.signing_key`. |

The preferred operator path is the signed APT/DNF repository documented in [Installation](installation.md).

Standalone scripts also verify detached signatures. `scripts/install.sh` embeds the Ed25519 public key in `EMBEDDED_SIGNING_KEY`. Override it at runtime with `CSM_SIGNING_KEY_PEM`.

Current releases fail before execution if the key, signature, or compatible verifier is unavailable. Setting `CSM_REQUIRE_SIGNATURES=0` does not bypass verification for current releases.

## Public key

The same Ed25519 key signs release artifacts and YARA Forge rule ZIPs.

Hex form, for `signatures.signing_key` in CSM config:

```text
2d1472b2a1d9728c2717b75111487145a7863f7ce731c1b44181f7a68bb908f7
```

PEM form, for standalone script verification (`EMBEDDED_SIGNING_KEY` / `CSM_SIGNING_KEY_PEM`):

```text
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEALRRysqHZcownF7dREUhxRaeGP3znMcG0QYH3pou5CPc=
-----END PUBLIC KEY-----
```

## Package repository signing

`repo:publish` runs on version tag pipelines. It rebuilds the public package repositories from the current tag plus the retained historical releases.

Required protected CI variables:

| Variable | Type | Purpose |
|----------|------|---------|
| `CSM_GPG_SIGNING_KEY` | File | GPG private key that signs APT metadata, RPM packages, and RPM repo metadata. |
| `CSM_MIRROR_SSH_KEY` | File | SSH key that publishes the mirror output. |
| `CSM_MIRROR_KNOWN_HOSTS` | Variable | SSH host keys for the mirror host. |

The job exports the public key as `csm-signing.gpg` and publishes it at the mirror root, so install docs can reference:

```bash
https://mirrors.pidginhost.com/csm/csm-signing.gpg
```

APT verifies signed repository metadata through the `signed-by=` keyring. DNF verifies both RPM package signatures and repository metadata via `gpgcheck=1` and `repo_gpgcheck=1`.

## Detached artifact signatures

On `main` and version tags, CI signs each architecture's binary and packages with the Ed25519 release key in `CSM_SIGNING_KEY`. A missing key stops signing. The registry and GitHub release jobs sign their assets tarballs after assembly.

The registry also provides detached signatures for its standalone install and deploy scripts. These rules apply to registry publishing:

- The publisher verifies all signatures against the public key embedded in the registry deploy script before it replaces `latest`.
- Each signature must upload successfully before its payload becomes available.
- Main can publish a signed AMD64 build when ARM64 is unavailable.
- Version tags require both architectures.

Examples:

```text
csm-X.Y.Z-linux-amd64
csm-X.Y.Z-linux-amd64.sha256
csm-X.Y.Z-linux-amd64.sig
csm-assets.tar.gz
csm-assets.tar.gz.sha256
csm-assets.tar.gz.sig
csm_X.Y.Z_amd64.deb
csm_X.Y.Z_amd64.deb.sig
csm-X.Y.Z-1.x86_64.rpm
csm-X.Y.Z-1.x86_64.rpm.sig
```

The signature covers the raw artifact bytes with no hashing wrapper. Verification uses:

```bash
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-X.Y.Z-linux-amd64.sig -in csm-X.Y.Z-linux-amd64
```

## Detached signature setup

On a trusted workstation:

```bash
openssl genpkey -algorithm ed25519 -out csm-signing.key
openssl pkey -in csm-signing.key -pubout -out csm-signing.pub
```

Store the private key in GitLab as a protected `CSM_SIGNING_KEY` variable. Keep the private key in an offline password manager and a second secure backup location. Do not commit it.

Embed the matching public key in `scripts/install.sh`, `scripts/deploy.sh`, and `scripts/deploy-gitlab.sh`. CI reads the registry deploy script's embedded key when it verifies builds. Operators can override their local verifier key with `CSM_SIGNING_KEY_PEM`.

## What the standalone scripts enforce

Signature verification is mandatory for current standalone releases. To also reject missing signatures on historical pre-signing releases:

```bash
curl -fsSLo /tmp/csm-install.sh https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh
sudo env CSM_REQUIRE_SIGNATURES=1 bash /tmp/csm-install.sh
```

Standalone installs need OpenSSL 3.0 or newer, an installed CSM binary with `verify-release`, or Python with `cryptography`. The signed APT/DNF repository uses GPG.

### Missing or failed signatures

| Case | What the scripts do |
|------|---------------------|
| A `.sig` file exists but verification fails. | Abort, regardless of `CSM_REQUIRE_SIGNATURES`. |
| The `.sig` is missing (HTTP 404) for release v2.2.0 or later. | Abort, even without `CSM_REQUIRE_SIGNATURES`. |
| The `.sig` is missing for an unknown version or `latest`. | Abort. These cannot qualify for the historical exception. |
| The `.sig` is missing for a release older than v2.2.0. | Continue only under the historical exception below. |

Every release from v2.2.0 on ships a signature. Its absence means the download is incomplete or tampered.

### Historical exception

The scripts tolerate a missing `.sig` only when both of these hold:

- `CSM_REQUIRE_SIGNATURES=0` is in effect.
- You explicitly selected a complete release version older than v2.2.0, with no suffix or leading zeroes.

This exception is checksum-only installation. The scripts report it as unverified, not signature-verified.

### Registry deploy script

`scripts/deploy-gitlab.sh` installs only the registry's current build and has no exception. It refuses a registry build without a valid signature like a release, whatever `CSM_REQUIRE_SIGNATURES` is set to.

`csm doctor` reports older registry deploy scripts that still accept unsigned builds. Replace any reported copy before using it for another upgrade.

### Assets checksum

The same policy applies to the `csm-assets.tar.gz.sha256` checksum:

- Releases published before checksums existed produce a warning and skip the checksum step.
- `CSM_REQUIRE_SIGNATURES=1` makes the missing checksum fatal.
- A checksum that exists but does not match always aborts.

### The `check` action

The `check` action only compares checksums and reports update availability. It does not download or execute a release binary. Installation and upgrade perform the signature checks above.

## Key rotation

### Package repository GPG key

1. Generate a new GPG signing key.
2. Replace `CSM_GPG_SIGNING_KEY` in protected CI variables.
3. Publish a tag pipeline so `repo:publish` exports the new public key to the mirror.
4. Update install docs or automation if the key URL changes.

### Detached Ed25519 key

1. Generate a new Ed25519 key pair.
2. Replace `CSM_SIGNING_KEY` in protected CI variables.
3. Update the embedded public key in all standalone scripts and any `CSM_SIGNING_KEY_PEM` override used by automation.
4. Tag a new release.

Old detached signatures remain verifiable only with the old public key. Archive old public keys alongside release metadata so historical releases can still be checked.

## Manual detached verification

```bash
VERSION=X.Y.Z
curl -LO "https://github.com/pidginhost/csm/releases/download/v${VERSION}/csm-${VERSION}-linux-amd64"
curl -LO "https://github.com/pidginhost/csm/releases/download/v${VERSION}/csm-${VERSION}-linux-amd64.sig"

openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile "csm-${VERSION}-linux-amd64.sig" -in "csm-${VERSION}-linux-amd64"
```

`openssl pkeyutl -rawin` needs OpenSSL 3.0 or newer. EL8 and CloudLinux 8 ship OpenSSL 1.1.1, whose command line cannot verify Ed25519 at all. Use an already installed CSM build there. It verifies with Go's implementation and needs no OpenSSL:

```bash
csm verify-release csm-signing.pub \
  "csm-${VERSION}-linux-amd64.sig" "csm-${VERSION}-linux-amd64"
```

The command exits zero only for an artifact signed by the given key.

If verification fails, treat the artifact as untrusted. Do not install it.

### Verifiers the scripts try

The installer and deploy scripts try these verifiers in order, and refuse the artifact when none is available:

1. OpenSSL 3.0+.
2. An installed `csm verify-release`.
3. `python3-cryptography`.

### Verifier limits

The Go and Python verifiers reject special files and limit input sizes:

| Input | Limit |
|-------|-------|
| Key | 64 KiB |
| Signature | Exactly 64 bytes |
| Artifact | Not empty, at most 512 MiB |

Python verification ignores the working directory, user site packages, and Python environment settings when it imports its dependencies. Install python3-cryptography as a system package.
