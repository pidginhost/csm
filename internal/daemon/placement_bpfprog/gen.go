// Package placement_bpfprog hosts the BPF C source for the lsm/inode_rename
// and lsm/inode_link placement monitor and the generated Go bindings produced
// by bpf2go.
//
// To regenerate (needs clang + libbpf-devel; the CI builder image carries
// both):
//
//	make bpf-gen
package placement_bpfprog

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type placement_event -cflags "-I../bpf_headers" Placement _placement.bpf.c -- -I/usr/include
