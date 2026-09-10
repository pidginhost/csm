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

Provision it from the cloud catalogue's `alma9` image (AlmaLinux 9, x86_64),
the closest available match to the EL production family; `alma10`, `ubuntu26`
and `debian13` also satisfy the contract. Enable BPF LSM before registering the
runner, since it is not in the default boot-time LSM list:

```bash
grubby --update-kernel=ALL --args="lsm=capability,yama,selinux,bpf"
reboot
cat /sys/kernel/security/lsm      # must list bpf
stat -fc %T /sys/fs/cgroup        # must print cgroup2fs
```

Register with `gitlab-runner register --executor shell --tag-list csm-kernel`,
lock it to this project, and disable it for other projects.

This runner does **not** reproduce the production kernel. Supported hosts run
CloudLinux 8 and EL8 on 4.18; no catalogue image offers that kernel. Treat a
passing `test:kernel` as evidence for a 5.14-or-newer kernel only. Capabilities
that differ across those kernels -- `pidfd_open` is present on the runner and
absent on 4.18 -- are probed at runtime instead and reported by `csm doctor`
and the health status.

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
The kernel test service has an explicit Go workspace and toolchain selection;
EL8 system services may start without a home directory. Once tests stop and
their results and journals are saved, the collector exits the disposable
systemd manager directly with the test result, avoiding EL8 exit-target loops.
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

## Queue inventory tooling

The allocation scanner is available for ownership reviews:

```bash
go run ./scripts/queuegate -scan > queue-allocations.json
```

It scans repository Go source across all build constraints, excluding test files,
`testdata`, hidden directories and vendored dependencies. It records raw channel
allocations and imported `queuehealth.NewChannel` calls, including renamed and
dot imports. Named channel aliases resolve across every package variant in a
repository import directory; an alias that is a channel in only some variants fails
explicitly. Imported named types use the Go toolchain's source importer.
Unresolved types, reflective allocation and indirect references to the accounted constructor fail explicitly.
Supporting a new constructor or generic constraint requires scanner tests and
an ownership review first.

Allocation identities use the file, enclosing function, assignment target,
constructor kind and ordinal. The descriptor includes the allocation expression,
expanded repository constants and assignments or local `var` initializers for
the capacity and its local inputs in the enclosing function. Expression grouping
and build-variant values are retained, including array lengths, literal indices and slice bounds.
Implicit constant declarations, `iota`, closures and named composite literals
in capacity expressions need explicit scanner support and are rejected, including
when nested inside field selections. Import aliases are resolved as package
names, including aliases that match predeclared identifiers. Runtime
collection lengths stay symbolic; only explicit construction and slice bounds
enter the local capacity-input graph. The scanner does not infer arbitrary
function bodies or type layouts and is not whole-program data-flow analysis.

A version 1 manifest contains `allocations` and `owners`. Each allocation copies
its scanner descriptor and adds a reviewed `class`, `rationale`, and `queue`
owner where applicable. Classes are `work`, `lifecycle`, `maintenance`, and
`constructor`. A semaphore or completion signal can order data stored elsewhere;
trace that data before deciding whether it belongs to a work owner. Every work
allocation must reference an owner. Changes, omissions and stale descriptors
fail validation.

Each owner records health `rows`, reviewed `bounds`, and separate `publication`
and `lifecycle` evidence lists. An evidence entry names a package, a top-level
Go test and its required `portable` or `kernel` mode. Owners without a channel
allocation need source `anchors`: a path, symbol and canonical shape. Supported
anchors include struct fields, types, variable or constant declarations, and
function signatures. Missing or changed anchors fail validation.

For a reviewed manifest, generate requirements for the existing test verifier:

```bash
go run ./scripts/queuegate -manifest path/to/reviewed-inventory.json \
  -mode portable -base-required scripts/production-required.json \
  -required-out queue-required.json
```

Use the resulting file as `scripts/testgate -required` with the selected test
inventory and actual Go JSON test events. It combines existing required tests
with the owner's evidence for that mode. A missing, skipped or failed required
test is not accepted. A passing scanner or a test name in JSON alone does not
prove health publication or lifecycle coverage; the named tests need substantive
assertions and execution evidence. The reviewed repository inventory and its
production-runner wiring are still pending.

The scanner cannot discover arbitrary queues held in maps, heaps, durable
storage, kernel buffers or dependencies. Those need explicit owner entries and
source anchors, plus tests that drive real admission, progress, loss and cleanup.
Adding a new non-channel owner remains a code-review responsibility. No syntax
inventory substitutes for reviewing the behavior of its required tests.
