// Package af_alg_bpfprog hosts the BPF C source for the AF_ALG (CVE-2026-31431
// "Copy Fail") kernel-side deny program and the generated Go
// bindings produced by bpf2go.
//
// To regenerate (needs clang + libbpf-devel; the CI builder image carries
// both):
//
//	make bpf-gen
package af_alg_bpfprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type af_alg_event -cflags "-I../bpf_headers" AFAlg _af_alg.bpf.c -- -I/usr/include
