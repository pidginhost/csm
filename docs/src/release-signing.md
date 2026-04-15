# Release Signing

CSM signs every release binary, tarball, and package with an ed25519 key. Installers verify signatures before touching disk, which lets operators trust the `curl | bash` install path and catches tampered mirror content.

## Status

| Release | Signed |
|---------|--------|
| v2.1.1 and older | No (pre-signing era) |
| Next release | Yes (once `CSM_SIGNING_KEY` is set in CI) |

Until the key is provisioned, releases ship unsigned and install scripts skip verification with a warning. This is the current state of the pipeline: all signing infrastructure is in place, but no key is configured.

## One-Time Operator Setup

On a trusted workstation (NOT a CI runner):

```bash
# Generate the key pair
openssl genpkey -algorithm ed25519 -out csm-signing.key
openssl pkey -in csm-signing.key -pubout -out csm-signing.pub

# Store the private key
cat csm-signing.key
# Copy the entire output to GitLab > Settings > CI/CD > Variables:
#   Key:   CSM_SIGNING_KEY
#   Type:  Variable
#   Flags: Protected, Masked (if length allows; ed25519 PEMs are long
#          enough to need "masked and hidden")
#          Expose to protected branches/tags only

# Commit the public key into the repo
cat csm-signing.pub
# Paste the "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----"
# block into scripts/install.sh and scripts/deploy.sh at the
# EMBEDDED_SIGNING_KEY variable (currently empty).
```

Store the private key in an offline password manager and a second hardware location. **Do not commit the private key to the repo.** Do not email it to yourself. Do not paste it into Slack.

## What Gets Signed

The `sign:artifacts` CI job runs after `build` and `package`. It signs:

- `csm-linux-amd64`, `csm-linux-arm64` (raw binaries)
- `csm-*-linux-*.rpm` (RPM packages)
- `csm_*_amd64.deb`, `csm_*_arm64.deb` (Debian packages)

The `publish` job signs `csm-assets.tar.gz` (because that tarball is created in the publish job, not the build stage). The `release:github` job re-signs `csm-assets.tar.gz` for the same reason -- it rebuilds the tarball for the GitHub release.

Each signed artifact gets a `.sig` sibling uploaded to the same location. For example:

```
csm-2.2.0-linux-amd64
csm-2.2.0-linux-amd64.sha256
csm-2.2.0-linux-amd64.sig    <-- new
```

## Signature Algorithm

Ed25519 "raw" signatures, meaning the signature covers the raw bytes of the artifact with no prior hashing wrapper. Verification uses:

```bash
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-linux-amd64.sig -in csm-linux-amd64
```

This matches what `scripts/install.sh` and `scripts/deploy.sh` do internally.

## Installer Behavior

Both install scripts read the public key from two sources in priority order:

1. `CSM_SIGNING_KEY_PEM` environment variable (operator override at install time)
2. `EMBEDDED_SIGNING_KEY` variable inside the script (set once when committing the public key)

If neither is set, the installer warns and proceeds -- this lets pre-signing releases install. To enforce strict verification (fail rather than warn), export `CSM_REQUIRE_SIGNATURES=1` before running the installer:

```bash
CSM_REQUIRE_SIGNATURES=1 curl -sSL https://raw.githubusercontent.com/pidginhost/csm/main/scripts/install.sh | bash
```

When a `.sig` file is published but verification fails, the installer always aborts (regardless of `CSM_REQUIRE_SIGNATURES`). A failed signature is always fatal -- the installer never falls back to "trust on install".

## Key Rotation

To rotate the signing key:

1. Generate a new key pair as described above.
2. Update `CSM_SIGNING_KEY` in GitLab CI variables.
3. Update `EMBEDDED_SIGNING_KEY` in `scripts/install.sh` and `scripts/deploy.sh`.
4. Tag a new release. The `sign:artifacts` job will use the new key automatically.
5. Existing deployed instances that use `/opt/csm/deploy.sh upgrade` will continue to work as long as the new release uses the new key (they read the embedded public key fresh each time from the updated deploy.sh).

Old releases remain verifiable with the old public key because the signatures are immutable. Archive the old public key alongside the new one so historical releases can still be validated.

## Verifying a Release Manually

```bash
# Download artifact + sig + public key
curl -LO https://github.com/pidginhost/csm/releases/download/v2.2.0/csm-2.2.0-linux-amd64
curl -LO https://github.com/pidginhost/csm/releases/download/v2.2.0/csm-2.2.0-linux-amd64.sig
curl -LO https://raw.githubusercontent.com/pidginhost/csm/main/scripts/csm-signing.pub

# Verify
openssl pkeyutl -verify -pubin -inkey csm-signing.pub -rawin \
  -sigfile csm-2.2.0-linux-amd64.sig -in csm-2.2.0-linux-amd64
# Signature Verified Successfully
```

If that command fails, treat the binary as untrusted. Do not install it.
