# CSM Engineering Roadmap

Forward-looking engineering decisions that are committed to but not yet
implemented. Items move from here into commits + `CHANGELOG.md` entries
as they land.

This file is for contributors. End-user documentation lives in
`docs/`.

---

## 1. Move build from musl-static to glibc-dynamic

**Status:** committed, not started
**Drives / unblocks:** safe future YARA-X upgrades; any other cgo
dependency upgrade

### Why

The YARA-X 1.15.0 upgrade attempt on 2026-04-16 put cluster6 into a
deterministic SIGSEGV restart loop inside `yrx_compiler_build`. The
crash was never root-caused in the production-pressure window; the
only reliable fix was to revert to v1.14.0 (commit `a98e257`). The
failure mode — SEGV_ACCERR in Rust-compiled-to-C-ABI code called via
cgo, inside a binary linked statically against musl with a
source-built libunwind and stub libgcc_s.a — strongly suggests a
Rust/musl/unwinder ABI interaction that upstream YARA-X does not
test.

Corroborating evidence: the 2.4.3 release required **8 consecutive
builder-image iterations** just to get YARA-X 1.15.0 to link at all,
including a source-built libunwind with `--disable-minidebuginfo` to
dodge undefined `lzma_*` symbols from Alpine's packaged libunwind.
Each round shipped through CI without reproducing the runtime
crash, because we had no local 1.15.0 reproduction harness. Upstream
YARA-X's CI matrix targets glibc. We are fighting a
combination they do not exercise.

### Decision

Switch the builder base from `alpine` + musl-static to
`debian:bookworm-slim` + glibc-dynamic. Build `csm` as a
glibc-dynamic binary whose glibc floor matches the oldest supported
cPanel host (CloudLinux / Alma / RHEL 8, glibc 2.28). Accept the
trade-off that the binary becomes distro-floor-specific instead of
"runs anywhere with a Linux kernel".

### Expected outcome

- Future YARA-X (and other cgo) upgrades stop fighting the
  toolchain. Upstream test config = our runtime config.
- Debug tooling (gdb, perf, lldb, proper stack unwinding, symbolic
  traces) works as documented instead of silently producing garbage
  on musl-static.
- The `Dockerfile.builder` work that landed with the 2.4.3 attempt
  (source libunwind, `--disable-minidebuginfo`, libgcc_s stub,
  musl-gcc shim, linker override via `CARGO_TARGET_*_LINKER`) all
  disappears — none of it is needed on glibc.

### Work items

1. Fork `build/Dockerfile.builder` to target `debian:bookworm-slim`
   on a glibc-2.28 or glibc-2.31 floor (build on a CloudLinux 8 or
   Debian 11 image that has glibc 2.28/2.31). Keep only: Go
   toolchain, Rust toolchain, `cargo-c` for YARA-X build.
2. Cross-compile for aarch64 against a matched glibc-floor arm64
   base (e.g. `debian:bookworm-slim/arm64`). Drop the
   `musl.cc` cross-toolchain.
3. Bump `.gitlab-ci.yml` `CSM_BUILDER_TAG` to something like
   `glibc-2.28-r1`. The CI job that rebuilds the builder image runs
   automatically on tag change.
4. Verify on every target distro we deploy to: CloudLinux 8,
   AlmaLinux 8, AlmaLinux 9, Ubuntu 22.04, Ubuntu 24.04. Use the
   existing `integration` stage, extended.
5. Review `scripts/deploy.sh`, `scripts/install.sh`, and
   `/root/deploy-csm.sh` for any binary-naming or SHA-pinning
   assumptions; update if needed.
6. Once green on all targets, re-attempt the YARA-X upgrade (to the
   latest stable at the time, which may be 1.15.x patch, 1.16, or
   later) **with local reproduction coverage** before it ships to
   main. The re-attempt is a separate commit; this roadmap item
   is complete when the glibc build is shipping and stable.

### Out of scope

- Running CSM on Alpine, BusyBox, or other musl-libc distros. Not
  a real deployment target.
- Statically linking all dependencies into the glibc binary. Dynamic
  glibc with a pinned floor is sufficient.
- Re-attempting the YARA-X upgrade in this work item. That happens
  after the build change has been stable for a release cycle.

### Rollback plan

The current 2.4.2 musl-static build is proven stable. If the glibc
switch causes regressions, revert the Dockerfile + CSM_BUILDER_TAG
commits and the next CI run produces the old binary.

---

## 2. Process-isolate YARA-X (and other cgo dependencies)

**Status:** planned, after item 1
**Drives / unblocks:** resilience against any future cgo
dependency bug

### Why

A bug in any cgo dependency currently takes the entire `csm` daemon
down. The 2026-04-16 incident demonstrated the cost: 17 systemd
restart attempts over 4 minutes, real-time monitoring offline for
the whole window, manual rollback required. Glibc (item 1 above)
reduces the probability of such a bug; it does not eliminate it. The
next cgo dependency crash — in YARA-X, in a future
`github.com/google/nftables` bug, in a libc symbol that drifts
between distros — will have the same blast radius unless we
architect around it.

### Decision

Run the YARA rule compiler + scan loop in a supervised child
process (`csm yara-worker`). The daemon supervises the worker over a
Unix-domain socket. If the worker crashes the daemon restarts it
with exponential backoff and emits a clear finding
(`yara_worker_crashed` or similar); real-time monitoring stays up
throughout.

The pattern generalises: any future cgo-heavy component can be
moved behind the same supervisor wrapper.

### Scope sketch

- New subcommand: `csm yara-worker` (runs the YARA-X compile + scan
  loop; reads requests and writes responses on a Unix socket).
- IPC: length-prefixed frames on a Unix-domain socket. Socket path
  `/run/csm/yara-worker.sock` (mode `0600`, owned by root).
  Configurable.
- Daemon side: supervisor goroutine that forks the worker, monitors
  it, restarts on exit with exponential backoff up to a ceiling,
  and surfaces an alert after N consecutive restarts.
- Rule-reload: worker re-execs on `SIGHUP` to pick up new rules
  without a daemon restart.
- Graceful degradation: if the worker has been unavailable for
  longer than a threshold, YARA-backed checks return "no result"
  rather than blocking or escalating.

### Acceptance criteria

- An induced `SIGSEGV` in the worker leaves the daemon running and
  the real-time file monitor uninterrupted. A finding is emitted
  identifying the worker crash.
- Scan latency adds no more than ~5 ms over the in-process baseline
  (budget: one socket round-trip + serialisation).
- The integration stage covers: normal scan, worker crash during a
  scan, worker crash during rule rebuild, worker unreachable
  (socket gone), and worker restart-loop ceiling.

### Out of scope

- Process-isolating anything other than YARA-X in the first pass.
  Other cgo dependencies can adopt the same pattern in follow-up
  work.
- Multi-worker / worker-pool scaling. One worker per daemon is
  sufficient for current load.

### Estimated size

3–5 engineering days including integration tests.

---
