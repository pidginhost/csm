// Package exec_bpfprog hosts the BPF C source for the sched/sched_process_exec
// tracepoint live monitor and the generated Go bindings produced by bpf2go.
//
// To regenerate (needs clang + libbpf-devel; the CI builder image carries
// both):
//
//	make bpf-gen
package exec_bpfprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type exec_event -cflags "-I../bpf_headers" Exec _exec.bpf.c -- -I/usr/include
