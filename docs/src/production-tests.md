# Production build and kernel tests

The default test suite builds without the `yara`, `journal` and `bpf` build tags, so it tests portable stand-ins (stubs) for that code, not the code that ships. Two required CI jobs test what ships. `test:production` runs the full repository with the build tags of shipped Linux binaries. `test:kernel` runs the tests that need a real kernel, on a dedicated runner.

Both jobs retain artifacts for one year and are explicit dependencies of publication, including tag-specific dependencies.

## The production gate

`test:production` runs the full repository with `yara,journal,bpf`, the tags used by shipped Linux binaries. The job also does the following:

- It uses the release builder's YARA-X C library and verifies that its version matches both the Go module and the builder recipe.
- It installs PHP 8.2 for runtime tests.
- It runs the pinned linter and security analyzer with all shipped tags. The analyzer flags file reads where the caller chooses the path. The scanning APIs do that on purpose, so they keep documented exceptions.
- Its rule trust checks cover every accepted filename extension, regardless of letter case.

Run the same gate in a suitable Linux image with:

```bash
scripts/production-tests.sh portable
```

### What each gate records

Each gate writes four things under `production-results/`: the selected test inventory, Go JSON test events, engine versions, and the commit ID.

The inventory comes from `go list` and the selected Go test files across all packages. A newly added package or tagged test is included automatically.

Verification rejects missing tests, package failures, and skipped required regressions. Other environment skips remain visible in the JSON events. These are not kernel coverage.

## Kernel runner

`test:kernel` is a required job on a dedicated Linux shell runner tagged `csm-kernel`. The ordinary Kubernetes runner does not satisfy this contract automatically.

### What the runner needs

Provision an ephemeral VM for each job, locked to this project. The VM needs:

- local Docker,
- cgroup v2,
- BTF,
- BPF LSM enabled in the boot-time LSM list,
- BPF ring buffers,
- fanotify,
- nftables,
- access to pull the pinned builder image.

It must have no unrelated workloads or host credentials.

### Provisioning the runner

Provision it from the cloud catalog's `alma9` image (AlmaLinux 9, x86_64), the closest available match to the EL production family. `alma10`, `ubuntu26` and `debian13` also satisfy the contract.

BPF LSM is not in the default boot-time LSM list, so enable it before registering the runner:

```bash
grubby --update-kernel=ALL --args="lsm=capability,yama,selinux,bpf"
reboot
cat /sys/kernel/security/lsm      # must list bpf
stat -fc %T /sys/fs/cgroup        # must print cgroup2fs
```

Register with `gitlab-runner register --executor shell --tag-list csm-kernel`, lock it to this project, and disable it for other projects.

### What a pass does not prove

This runner does **not** reproduce the production kernel. Supported hosts run CloudLinux 8 and EL8 on 4.18, and no catalog image offers that kernel. Treat a passing `test:kernel` as evidence for a 5.14-or-newer kernel only.

Some capabilities differ across those kernels. For example, `pidfd_open` is present on the runner and absent on 4.18. The kernel job cannot cover those differences. CSM probes these capabilities at runtime, and `csm doctor` and the health status report the result.

### What the job runs

The job builds `build/Dockerfile.production-test` on the release builder. It uses `scripts/go-linux.sh` to boot systemd inside a disposable container. Systemd then runs two test services. Both the CLI and the service test binary use the shipped tags.

The first service is the packaged service sandbox regression. It verifies remediation and restore under the packaged unit, custom account-root grants, doctor checks, and process-handle signaling. It does not exercise the daemon's complete watcher startup. The cPanel package gate and cloud integration cover that separately.

The second service executes the shipped tags plus `nftkernel,kernelintegration`. Its inventory selects every test added by those tags across all packages, plus explicitly required attachment tests. New kernel test names need no prefix.

Required checks in the second service include:

- real nftables transactions in isolated network namespaces,
- kernel-produced BPF ring events,
- AF_ALG BPF attachment and shutdown,
- journal delivery from two actual services, followed by reader cancellation.

The journal test covers both empty and existing history, excludes unrelated services, and rejects replayed records.

### Running the kernel job locally

`GO_LINUX_PRIVILEGED=1` is an explicit Docker-only test option. The wrapper's normal capability set remains the default. Use the same setup locally only on a dedicated Linux test VM:

```bash
docker build --build-arg BUILDER_IMAGE=<release-builder-image> \
  -f build/Dockerfile.production-test -t csm-production-test .
GO_LINUX_RUNTIME=docker GO_LINUX_PRIVILEGED=1 \
  GO_LINUX_IMAGE=csm-production-test scripts/go-linux.sh \
  bash scripts/systemd-account-roots-test.sh production
```

### When the kernel gate fails or waits

| Case | Result |
|------|--------|
| The runner lacks a required capability | The kernel gate fails. |
| The AF_ALG attachment test is skipped | Not accepted. |
| No kernel runner is available | The job stays pending and publication stays blocked. |

## Other gates

The separate [clean application gate](clean-corpus.md) provides pinned vendor corpus measurements. [cPanel release tests](cpanel-release-tests.md) provide package, upgrade, and primary-platform validation. None substitutes for another.

## Required Queue inventory

`scripts/queue-inventory.json` is the reviewed inventory of queues. Its `owners` entries cover channel handoffs, durable work, coalesced pending work and kernel buffers. Each owner records its health rows, its bounds, and the publication and lifecycle regressions it requires.

Both runner modes validate the inventory before test selection and execution. The runner then:

1. Takes the union of the owners' regressions and its existing requirements.
2. Writes that union to `production-results/<mode>/queue-required.json`.
3. Requires actual passing events for every selected requirement.

A full suite that passes today is not enough. If a test is not listed as required, nothing fails when that test is skipped later.

### Where a regression belongs

The portable baseline in `scripts/production-required.json` also requires the shared accounting, health reporting, doctor and gate regressions.

Keep recovery and concurrency regressions with their owner when they test an owner-specific boundary. Keep shared contracts in the baseline.

### The manifest

The inventory file is a version 1 manifest. It contains `allocations` and `owners`.

Each allocation copies its scanner descriptor and adds a reviewed `class`, a `rationale`, and a `queue` owner where applicable. Classes are `work`, `lifecycle`, `maintenance`, and `constructor`. Every work allocation must reference an owner.

A semaphore or completion signal can order data stored elsewhere. Trace that data before deciding whether it belongs to a work owner.

Changes, omissions and stale descriptors fail validation.

### Owners

Each owner records health `rows`, reviewed `bounds`, and separate `publication` and `lifecycle` evidence lists. An evidence entry names a package, a top-level Go test and its required `portable` or `kernel` mode.

Owners without a channel allocation need source `anchors`: a path, symbol and canonical shape. Supported anchors include struct fields, types, variable or constant declarations, and function signatures. Missing or changed anchors fail validation.

### Scanning allocations

The allocation scanner is available for ownership reviews:

```bash
go run ./scripts/queuegate -scan > queue-allocations.json
```

It records raw channel allocations and imported `queuehealth.NewChannel` calls, including renamed and dot imports. [Scanner rules](#scanner-rules) lists what it reads and what it rejects.

Supporting a new constructor or generic constraint requires scanner tests and an ownership review first.

### Generating requirements

For a reviewed manifest, generate requirements for the existing test verifier:

```bash
go run ./scripts/queuegate -manifest scripts/queue-inventory.json \
  -mode portable -base-required scripts/production-required.json \
  -required-out queue-required.json
```

Use the resulting file as `scripts/testgate -required` with the selected test inventory and actual Go JSON test events. It combines existing required tests with the owner's evidence for that mode. A missing, skipped or failed required test is not accepted.

A passing scanner or a test name in JSON alone does not prove health publication or lifecycle coverage. The named tests need substantive assertions and execution evidence.

Runner regression tests exercise both modes with real test events, including changed capacities, unclassified allocations, missing tests and skipped required evidence.

### What the scanner cannot find

The scanner cannot discover arbitrary queues held in maps, heaps, durable storage, kernel buffers or dependencies. Those need explicit owner entries and source anchors, plus tests that drive real admission, progress, loss and cleanup.

Adding a new non-channel owner remains a code-review responsibility. No syntax inventory substitutes for reviewing the behavior of its required tests.

### Requirements for specific owners

PHP relay publication requirements start the Linux wiring with temporary filesystem paths and a real state store. They check live registration, persistence, shutdown evidence and failed watcher attachment. They must also reject removal of either production registration. Manually registering a provider in a test only proves that provider's behavior.

PHP Shield eval-site admission and result channels belong to the `php_shield.eval_sites` work owner, because the ownership proof determines the grade of a finding held by the event reader. Both modes require publication, timeout, result retention, recovery and fail-closed grading regressions.

The advisory health row for that owner retains a timed-out filesystem walk and a completed result until the caller and walk both settle. A timeout or refused proof counts as lost grading work while the finding stays High.

## Details

This section is reference material: exact scanner rules and a few behaviors the tests pin.

### Scanner rules

The scanner reads repository Go source across all build constraints. It excludes test files, `testdata`, hidden directories and vendored dependencies.

| Case | What the scanner does |
|------|-----------------------|
| A directory is removed during the scan, such as a test's scratch folder | Skips it. |
| The scan root is missing, a directory is unreadable, or a source read fails | Fails the gate. |
| A named channel alias | Resolves it across every package variant in a repository import directory. |
| An alias that is a channel in only some variants | Fails explicitly. |
| An imported named type | Resolves it with the Go toolchain's source importer. |
| Unresolved types, reflective allocation, or indirect references to the accounted constructor | Fails explicitly. |

### Allocation identities and descriptors

Allocation identities use the file, enclosing function, assignment target, constructor kind and ordinal.

The descriptor includes the allocation expression and expanded repository constants. It also includes the assignments or local `var` initializers for the capacity and its local inputs in the enclosing function. Expression grouping and build-variant values are retained, including array lengths, literal indices and slice bounds.

The scanner has no support for the following in a capacity expression and rejects them, including when they are nested inside field selections:

- implicit constant declarations,
- `iota`,
- closures,
- named composite literals.

Import aliases are resolved as package names, including aliases that match predeclared identifiers.

Runtime collection lengths stay symbolic. Only explicit construction and slice bounds enter the local capacity-input graph. The scanner does not infer arbitrary function bodies or type layouts and is not whole-program data-flow analysis.

### The kernel test service on EL8

The kernel test service has an explicit Go workspace and toolchain selection, because EL8 system services may start without a home directory.

Once tests stop and their results and journals are saved, the collector exits the disposable systemd manager directly with the test result. This avoids EL8 exit-target loops.

### Journal reader and package integrity behavior

The journal reader starts after existing matching records. It also follows services with no prior records.

Package integrity rechecks preserve a reported mismatch for the original finding even if that file is absent or not executable any more. Current file mode is not evidence that the modification was repaired.
