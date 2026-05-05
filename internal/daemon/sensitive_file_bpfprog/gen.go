// Package sensitive_file_bpfprog hosts the BPF C source for the
// lsm/file_permission live monitor and the generated Go bindings produced
// by bpf2go.
//
// To regenerate (needs clang + libbpf-devel; the CI builder image carries
// both):
//
//	make bpf-gen
package sensitive_file_bpfprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type sensitive_event -type fileid -cflags "-I../bpf_headers" SensitiveFile _sensitive_file.bpf.c -- -I/usr/include
