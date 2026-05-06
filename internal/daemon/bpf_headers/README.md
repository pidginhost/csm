# BPF Headers

Shared C headers used by every CSM BPF program that reads kernel struct
fields. Today this is just `vmlinux.h` -- the BTF-derived header containing
every kernel struct definition the program may reference. CO-RE relocations
emitted by clang at compile time make programs portable across kernel
versions: the verifier rewrites field offsets at load time using the running
kernel's BTF, regardless of the offsets baked in by the source kernel.

## Why this is checked in

`vmlinux.h` is generated from a representative kernel via `bpftool`. We bake
it once and ship it so contributors do not need a privileged Linux host or a
kernel with `CONFIG_DEBUG_INFO_BTF=y` available to compile BPF programs.

The current copy was generated from AlmaLinux 9, kernel
`5.14.0-570.12.1.el9_6.x86_64`. CO-RE makes the resulting programs work on
every supported target kernel (Alma 9 / RHEL 9 / Ubuntu 22.04+ / Ubuntu
24.04) regardless of which kernel the header came from.

## Regenerating

When a new kernel adds fields a program needs to read, refresh via:

```sh
# On a privileged Alma 9 host with bpftool installed:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

Commit the new file with a note in CHANGELOG only if the regeneration
adds visible coverage; routine refreshes do not need a changelog entry.

## How phases include it

Each `internal/daemon/<feature>_bpfprog/` package's `gen.go` adds
`-cflags "-I../bpf_headers"` to the bpf2go invocation so the C source can
`#include <vmlinux.h>`. Phase 1 (`connection_bpfprog`) does NOT include
this header because it only reads stable UAPI struct `bpf_sock_addr`;
Phases 2-4 will reach into `task_struct`, `file`, and `inode` and need
CO-RE-aware compilation.
