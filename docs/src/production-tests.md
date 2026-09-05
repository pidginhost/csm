# Production build and kernel tests

The default suite tests the portable stubs. `test:production` also runs the full
repository with `yara,journal,bpf`, the tags used by shipped Linux binaries.
It uses the release builder's YARA-X C library and verifies that its version
matches both the Go module and the builder recipe. PHP 8.2 is installed for
runtime tests. The same job runs the pinned linter and security analyzer with
all shipped tags; scanning APIs retain documented exceptions for intentional
reads of caller-selected local files. Rule trust checks cover every accepted
filename extension, regardless of letter case. Run the same gate in a suitable Linux image with:

```bash
scripts/production-tests.sh portable
```

Each gate writes the selected test inventory, Go JSON test events, engine
versions, and commit ID under `production-results/`. The inventory comes from
`go list` and the selected Go test files across all packages. A newly added
package or tagged test is included automatically. Verification rejects missing
tests, package failures, and skipped required regressions. Other environment
skips remain visible in the JSON events. These are not kernel coverage.

## Kernel runner

`test:kernel` is a required job on a dedicated Linux shell runner tagged
`csm-kernel`. Provision an ephemeral VM for each job, locked to this project,
with local Docker, cgroup v2, BTF, BPF LSM enabled in the boot-time LSM list,
BPF ring buffers, fanotify, and nftables. Give it access to pull the pinned
builder image. It must have no unrelated workloads or host credentials.
The ordinary Kubernetes runner does not satisfy this contract automatically.

The job builds `build/Dockerfile.production-test` on the release builder and
uses `scripts/go-linux.sh` to boot systemd inside a disposable container.
`GO_LINUX_PRIVILEGED=1` is an explicit Docker-only test option; the wrapper's
normal capability set remains the default. Use the same setup locally only on
a dedicated Linux test VM:

```bash
docker build --build-arg BUILDER_IMAGE=<release-builder-image> \
  -f build/Dockerfile.production-test -t csm-production-test .
GO_LINUX_RUNTIME=docker GO_LINUX_PRIVILEGED=1 \
  GO_LINUX_IMAGE=csm-production-test scripts/go-linux.sh \
  bash scripts/systemd-account-roots-test.sh production
```

Systemd runs the packaged service sandbox regression and a second test service.
The second service executes the shipped tags plus `nftkernel,kernelintegration`.
Its inventory selects every test added by those tags across all packages, plus
explicitly required attachment tests. New kernel test names need no prefix.
Required checks include real nftables transactions in isolated network
namespaces, kernel-produced BPF ring events, AF_ALG BPF attachment and shutdown,
and journal delivery from two actual services followed by reader cancellation.
The journal test covers both empty and existing history, excludes unrelated
services, and rejects replayed records.
Both the CLI and service test binary use the shipped tags.
The first service verifies remediation and restore under the packaged unit,
custom account-root grants, doctor checks, and process-handle signaling.
It does not exercise the daemon's complete watcher startup; the cPanel package
gate and cloud integration cover that separately.

Missing capabilities fail the kernel gate. A skipped AF_ALG attachment test is
not accepted. Both production and kernel jobs retain artifacts for one year and
are explicit dependencies of publication, including tag-specific dependencies.
A missing kernel runner leaves the job pending and publication blocked.

The separate [clean application gate](clean-corpus.md) provides pinned vendor
corpus measurements. [cPanel release tests](cpanel-release-tests.md) provide
package, upgrade, and primary-platform validation. None substitutes for another.

The journal reader starts after existing matching records and also follows
services with no prior records. Package integrity rechecks preserve a reported
mismatch for the original finding even if that file is now absent or no longer
executable; current file mode is not evidence that the modification was repaired.
